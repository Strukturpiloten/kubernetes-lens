//! One owning thread witnesses the gate exec stop before release and native completion.
//! Runtime acceptance remains independent of source and pure-test evidence.
#![forbid(unsafe_code)]
use nix::sys::ptrace::{self, Event, Options};
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    Idle,
    Exec,
    Terminal,
    Unexpected,
}

pub trait Observer {
    // Must check held pidfd/start identity and one gate thread immediately before seize.
    fn bound_identity(&mut self) -> Result<(), &'static str>;
    // Root-only half send; original deadline and watchdog armed before invocation.
    fn permit(&mut self) -> Result<(), &'static str>;
    // Independently inspect all FD 0/1/2/object/runtime/isolation controls while held stop.
    fn final_stop(&mut self) -> Result<(), &'static str>;
    fn cancelled(&mut self) -> bool;
    // Kill only journal-bound group/PID, never an unheld numeric PID.
    fn terminate_owned(&mut self) -> Result<(), &'static str>;
    // Bubblewrap is sole real-parent reaper. Terminal trace notice never proves native success.
    fn real_parent_reaped(&mut self) -> Result<bool, &'static str>;
    // The controller may select a shorter cleanup end once; never extend the supplied ceiling.
    fn cleanup_ceiling(&self) -> Option<Instant> {
        None
    }
}

pub trait Kernel {
    fn seize(&mut self) -> Result<(), &'static str>;
    fn notice(&mut self) -> Result<Notice, &'static str>;
    fn detach(&mut self) -> Result<(), &'static str>;
    fn pause(&mut self);
}

pub struct LinuxKernel {
    pid: Pid,
    owner: ThreadId,
}
impl LinuxKernel {
    pub fn new_on_owning_thread(host_pid: i32) -> Result<Self, &'static str> {
        if host_pid <= 1 {
            return Err("invalid-host-pid");
        }
        Ok(Self {
            pid: Pid::from_raw(host_pid),
            owner: thread::current().id(),
        })
    }
    fn same_thread(&self) -> Result<(), &'static str> {
        if thread::current().id() == self.owner {
            Ok(())
        } else {
            Err("tracer-thread-changed")
        }
    }
}
impl Kernel for LinuxKernel {
    fn seize(&mut self) -> Result<(), &'static str> {
        self.same_thread()?;
        ptrace::seize(self.pid, Options::PTRACE_O_TRACEEXEC | Options::PTRACE_O_EXITKILL).map_err(|_| "seize-failed")
    }
    fn notice(&mut self) -> Result<Notice, &'static str> {
        self.same_thread()?;
        let flags = WaitPidFlag::__WALL | WaitPidFlag::__WNOTHREAD | WaitPidFlag::WNOHANG;
        match waitpid(self.pid, Some(flags)).map_err(|_| "exact-pid-wait-failed")? {
            WaitStatus::StillAlive => Ok(Notice::Idle),
            WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, event)
                if pid == self.pid && event == Event::PTRACE_EVENT_EXEC as i32 =>
            {
                Ok(Notice::Exec)
            }
            WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _) if pid == self.pid => Ok(Notice::Terminal),
            _ => Ok(Notice::Unexpected),
        }
    }
    fn detach(&mut self) -> Result<(), &'static str> {
        self.same_thread()?;
        ptrace::detach(self.pid, None::<Signal>).map_err(|_| "detach-failed")
    }
    fn pause(&mut self) {
        thread::sleep(Duration::from_millis(2));
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TraceResult {
    pub witnessed_and_detached: bool,
    pub original_cause: &'static str,
    pub cleanup_confirmed: bool,
}

fn fail<K: Kernel, O: Observer>(
    kernel: &mut K,
    observer: &mut O,
    cause: &'static str,
    attached: bool,
    terminal_consumed: bool,
    cleanup_end: Instant,
) -> TraceResult {
    let mut terminal = terminal_consumed || !attached;
    if observer.terminate_owned().is_err() {
        return TraceResult {
            witnessed_and_detached: false,
            original_cause: cause,
            cleanup_confirmed: false,
        };
    }
    let cleanup_end = observer
        .cleanup_ceiling()
        .map_or(cleanup_end, |end| end.min(cleanup_end));
    while Instant::now() < cleanup_end {
        if !terminal {
            match kernel.notice() {
                Ok(Notice::Terminal) => terminal = true, // allows real parent's wait
                Ok(_) => (),
                Err(_) => {
                    // ESRCH/ECHILD is not invented termination evidence.
                    return TraceResult {
                        witnessed_and_detached: false,
                        original_cause: cause,
                        cleanup_confirmed: false,
                    };
                }
            }
        }
        if terminal && matches!(observer.real_parent_reaped(), Ok(true)) {
            return TraceResult {
                witnessed_and_detached: false,
                original_cause: cause,
                cleanup_confirmed: true,
            };
        }
        kernel.pause();
    }
    TraceResult {
        witnessed_and_detached: false,
        original_cause: cause,
        cleanup_confirmed: false,
    }
}

/// Must run on the same dedicated OS thread that constructs `LinuxKernel`.
/// `D_exec` is supplied from before snapshot, never started here.
/// Returns after detach; outside owned watchdog remains mandatory for runtime/cleanup.
/// Absolute ceiling selected before setup; failure never starts a new cleanup budget.
pub fn trace_gate_until<K: Kernel, O: Observer>(
    kernel: &mut K,
    observer: &mut O,
    execution_deadline: Instant,
    cleanup_end: Instant,
) -> TraceResult {
    if Instant::now() >= execution_deadline || observer.cancelled() {
        return fail(
            kernel,
            observer,
            "cancelled-or-execution-timeout",
            false,
            false,
            cleanup_end,
        );
    }
    if let Err(cause) = observer.bound_identity() {
        return fail(kernel, observer, cause, false, false, cleanup_end);
    }
    if let Err(cause) = kernel.seize() {
        return fail(kernel, observer, cause, false, false, cleanup_end);
    }
    if Instant::now() >= execution_deadline || observer.cancelled() {
        return fail(
            kernel,
            observer,
            "cancelled-or-execution-timeout",
            true,
            false,
            cleanup_end,
        );
    }
    if let Err(cause) = observer.permit() {
        return fail(kernel, observer, cause, true, false, cleanup_end);
    }
    loop {
        if Instant::now() >= execution_deadline || observer.cancelled() {
            return fail(
                kernel,
                observer,
                "cancelled-or-execution-timeout",
                true,
                false,
                cleanup_end,
            );
        }
        match kernel.notice() {
            Ok(Notice::Idle) => kernel.pause(),
            Ok(Notice::Exec) => {
                if let Err(cause) = observer.final_stop() {
                    return fail(kernel, observer, cause, true, false, cleanup_end);
                }
                // Deadline/cancellation rechecked after potentially expensive final readback.
                if Instant::now() >= execution_deadline || observer.cancelled() {
                    return fail(
                        kernel,
                        observer,
                        "cancelled-or-execution-timeout",
                        true,
                        false,
                        cleanup_end,
                    );
                }
                match kernel.detach() {
                    Ok(()) => {
                        return TraceResult {
                            witnessed_and_detached: true,
                            original_cause: "exec-witnessed-only",
                            cleanup_confirmed: false,
                        };
                    }
                    Err(cause) => {
                        return fail(kernel, observer, cause, true, false, cleanup_end);
                    }
                }
            }
            Ok(Notice::Terminal) => {
                return fail(kernel, observer, "pre-detach-death", true, true, cleanup_end);
            }
            Ok(Notice::Unexpected) => {
                return fail(kernel, observer, "unexpected-trace-stop", true, false, cleanup_end);
            }
            Err(cause) => return fail(kernel, observer, cause, true, false, cleanup_end),
        }
    }
}

#[cfg(test)]
mod absolute_cleanup_tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    struct State {
        terminal: bool,
        events: Vec<&'static str>,
    }
    struct MockKernel(Rc<RefCell<State>>);
    struct MockObserver {
        state: Rc<RefCell<State>>,
        end: Instant,
        acknowledge: bool,
    }
    impl Kernel for MockKernel {
        fn seize(&mut self) -> Result<(), &'static str> {
            Ok(())
        }
        fn notice(&mut self) -> Result<Notice, &'static str> {
            let mut state = self.0.borrow_mut();
            state.terminal = true;
            state.events.push("terminal-consumed");
            Ok(Notice::Terminal)
        }
        fn detach(&mut self) -> Result<(), &'static str> {
            Ok(())
        }
        fn pause(&mut self) {}
    }
    impl Observer for MockObserver {
        fn bound_identity(&mut self) -> Result<(), &'static str> {
            Ok(())
        }
        fn permit(&mut self) -> Result<(), &'static str> {
            Ok(())
        }
        fn final_stop(&mut self) -> Result<(), &'static str> {
            Ok(())
        }
        fn cancelled(&mut self) -> bool {
            false
        }
        fn terminate_owned(&mut self) -> Result<(), &'static str> {
            self.state.borrow_mut().events.push("private-owned-cancel");
            Ok(())
        }
        fn real_parent_reaped(&mut self) -> Result<bool, &'static str> {
            let mut state = self.state.borrow_mut();
            if !state.terminal {
                return Err("tracer-still-owns-terminal");
            }
            state.events.push("actual-parent-ack");
            Ok(self.acknowledge)
        }
        fn cleanup_ceiling(&self) -> Option<Instant> {
            Some(self.end)
        }
    }
    #[test]
    fn failure_consumes_terminal_before_parent_ack_and_does_not_invent_missing_ack() {
        let state = Rc::new(RefCell::new(State {
            terminal: false,
            events: Vec::new(),
        }));
        let mut kernel = MockKernel(state.clone());
        let end = Instant::now() + Duration::from_secs(1);
        let mut observer = MockObserver {
            state: state.clone(),
            end,
            acknowledge: true,
        };
        let result = fail(&mut kernel, &mut observer, "cancelled", true, false, end);
        assert!(result.cleanup_confirmed);
        assert_eq!(
            state.borrow().events,
            ["private-owned-cancel", "terminal-consumed", "actual-parent-ack"]
        );
        observer.end = Instant::now();
        observer.acknowledge = false;
        let result = fail(&mut kernel, &mut observer, "cancelled", true, false, end);
        assert!(!result.cleanup_confirmed);
    }
    #[test]
    fn already_expired_absolute_cleanup_never_starts_a_fresh_failure_window() {
        let state = Rc::new(RefCell::new(State {
            terminal: false,
            events: Vec::new(),
        }));
        let mut kernel = MockKernel(state.clone());
        let end = Instant::now();
        let mut observer = MockObserver {
            state: state.clone(),
            end: end + Duration::from_secs(10),
            acknowledge: true,
        };
        let result = fail(&mut kernel, &mut observer, "original-expiry", true, false, end);
        assert!(!result.cleanup_confirmed);
        assert_eq!(state.borrow().events, ["private-owned-cancel"]);
    }
}
