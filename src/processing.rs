//! Shared native-processing ceilings; independent of parser shape and allocator memory.
use crate::diagnostic::{Finding, FindingCode, Phase};
use std::{cell::Cell, rc::Rc};

/// Lower-configurable cumulative ceilings for one native processing operation.
/// These count charged payloads and conservative work, not every allocation or RSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeProcessingLimits {
    /// Maximum charged payload buffer/copy bytes.
    pub max_payload_bytes: usize,
    /// Maximum charged byte visits, digit comparisons and traversal units.
    pub max_processing_units: usize,
    /// Maximum ordinary report entries; a terminal limit finding is separate.
    pub max_report_entries: usize,
    /// Maximum retained ordinary report payload bytes.
    pub max_report_bytes: usize,
}
impl Default for NativeProcessingLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: 64 * 1024 * 1024,
            max_processing_units: 64 * 1024 * 1024,
            max_report_entries: 10_000,
            max_report_bytes: 1024 * 1024,
        }
    }
}
impl NativeProcessingLimits {
    /// Apply the componentwise smaller ceiling; zero allowances remain valid.
    #[must_use]
    pub fn lowered_by(self, other: Self) -> Self {
        Self {
            max_payload_bytes: self.max_payload_bytes.min(other.max_payload_bytes),
            max_processing_units: self.max_processing_units.min(other.max_processing_units),
            max_report_entries: self.max_report_entries.min(other.max_report_entries),
            max_report_bytes: self.max_report_bytes.min(other.max_report_bytes),
        }
    }
    pub(crate) fn bounded(self) -> Self {
        Self::default().lowered_by(self)
    }
}

#[derive(Clone)]
pub(crate) struct NativeOperationBudget(Rc<Counters>);
struct Counters {
    limits: NativeProcessingLimits,
    payload: Cell<usize>,
    work: Cell<usize>,
    reports: Cell<usize>,
    report_bytes: Cell<usize>,
    reports_exhausted: Cell<bool>,
    exhausted: Cell<bool>,
}
impl NativeOperationBudget {
    pub(crate) fn new(limits: NativeProcessingLimits) -> Self {
        Self(Rc::new(Counters {
            limits: limits.bounded(),
            payload: Cell::new(0),
            work: Cell::new(0),
            reports: Cell::new(0),
            report_bytes: Cell::new(0),
            reports_exhausted: Cell::new(false),
            exhausted: Cell::new(false),
        }))
    }
    pub(crate) fn limits(&self) -> NativeProcessingLimits {
        self.0.limits
    }
    pub(crate) fn exhausted(&self) -> bool {
        self.0.exhausted.get()
    }
    pub(crate) fn fail(&self, phase: Phase) -> Finding {
        self.0.exhausted.set(true);
        limit(phase)
    }
    fn reserve(&self, counter: &Cell<usize>, amount: usize, ceiling: usize, phase: Phase) -> Result<(), Finding> {
        if self.exhausted() {
            return Err(limit(phase));
        }
        let Some(total) = counter.get().checked_add(amount) else {
            return Err(self.fail(phase));
        };
        counter.set(total);
        if total > ceiling {
            return Err(self.fail(phase));
        }
        Ok(())
    }
    pub(crate) fn payload(&self, bytes: usize, phase: Phase) -> Result<(), Finding> {
        self.reserve(&self.0.payload, bytes, self.0.limits.max_payload_bytes, phase)
    }
    pub(crate) fn work(&self, units: usize, phase: Phase) -> Result<(), Finding> {
        self.reserve(&self.0.work, units, self.0.limits.max_processing_units, phase)
    }
    pub(crate) fn payload_array<T>(&self, count: usize, phase: Phase) -> Result<(), Finding> {
        self.payload(
            count.checked_mul(size_of::<T>()).ok_or_else(|| self.fail(phase))?,
            phase,
        )
    }
    pub(crate) fn payload_sizes(&self, sizes: impl IntoIterator<Item = usize>, phase: Phase) -> Result<(), Finding> {
        let bytes = sizes
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .ok_or_else(|| self.fail(phase))?;
        self.payload(bytes, phase)
    }
    /// Conservative structural/payload preflight for one retained deep tree copy.
    pub(crate) fn tree_copy(&self, tree: &crate::syntax::TreeNode, phase: Phase) -> Result<(), Finding> {
        fn cost(
            budget: &NativeOperationBudget,
            node: &crate::syntax::TreeNode,
            phase: Phase,
        ) -> Result<usize, Finding> {
            use crate::syntax::{TreeNode, TreeValue};
            budget.work(1, phase)?;
            let fail = || budget.fail(phase);
            let mut total = size_of::<TreeNode>();
            match &node.value {
                TreeValue::String(value) | TreeValue::Number(value) => {
                    budget.work(value.len(), phase)?;
                    total = total.checked_add(value.len()).ok_or_else(fail)?;
                }
                TreeValue::Mapping(entries) => {
                    for (key, value) in entries {
                        budget.work(key.len(), phase)?;
                        total = total
                            .checked_add(size_of::<String>())
                            .and_then(|n| n.checked_add(key.len()))
                            .ok_or_else(fail)?;
                        total = total.checked_add(cost(budget, value, phase)?).ok_or_else(fail)?;
                    }
                }
                TreeValue::Sequence(items) => {
                    for item in items {
                        total = total.checked_add(cost(budget, item, phase)?).ok_or_else(fail)?;
                    }
                }
                TreeValue::Tagged(tag, value) => {
                    budget.work(tag.len(), phase)?;
                    total = total
                        .checked_add(tag.len())
                        .and_then(|n| n.checked_add(cost(budget, value, phase).ok()?))
                        .ok_or_else(fail)?;
                }
                TreeValue::Null | TreeValue::Bool(_) => {}
            }
            Ok(total)
        }
        self.payload(cost(self, tree, phase)?, phase)
    }
    pub(crate) fn report(&self, finding: &Finding, phase: Phase) -> Result<(), Finding> {
        let bytes = finding.path.as_ref().map_or(Some(0), |path| {
            path.0
                .iter()
                .try_fold(0usize, |total, part| total.checked_add(part.len()))
        });
        let bytes = bytes
            .and_then(|bytes| bytes.checked_add(size_of::<Finding>()))
            .ok_or_else(|| self.fail(phase))?;
        let entries = self.0.reports.get().checked_add(1);
        let payload = self.0.report_bytes.get().checked_add(bytes);
        if self.0.reports_exhausted.get()
            || entries.is_none_or(|entries| entries > self.0.limits.max_report_entries)
            || payload.is_none_or(|payload| payload > self.0.limits.max_report_bytes)
        {
            self.0.reports_exhausted.set(true);
            return Err(self.fail(phase));
        }
        self.payload(bytes, phase)?;
        if let (Some(entries), Some(payload)) = (entries, payload) {
            self.0.reports.set(entries);
            self.0.report_bytes.set(payload);
        }
        Ok(())
    }
    /// Retain earlier ordinary reports and at most one fixed pathless compatibility terminal.
    pub(crate) fn finish_report(&self, findings: &mut Vec<Finding>, phase: Phase) {
        let mut terminal = self.exhausted();
        findings.retain(|finding| {
            if finding.code == FindingCode::LimitExceeded {
                terminal = true;
                return false;
            }
            if self.report(finding, phase).is_ok() {
                true
            } else {
                terminal = true;
                false
            }
        });
        if terminal {
            findings.push(limit(phase));
        }
    }
}
pub(crate) fn limit(phase: Phase) -> Finding {
    Finding::error(FindingCode::LimitExceeded, phase)
}

/// Preflight each retained finding before growing the ordinary report.
pub(crate) struct ProcessingReport {
    findings: Vec<Finding>,
    processing: NativeOperationBudget,
    phase: Phase,
}
impl ProcessingReport {
    pub(crate) fn new(processing: NativeOperationBudget, phase: Phase) -> Self {
        Self {
            findings: Vec::new(),
            processing,
            phase,
        }
    }
    pub(crate) fn from_report(findings: Vec<Finding>, processing: NativeOperationBudget, phase: Phase) -> Self {
        // The already charged report belongs to this same operation, not a new allowance.
        Self {
            findings,
            processing,
            phase,
        }
    }
    pub(crate) fn processing(&self) -> &NativeOperationBudget {
        &self.processing
    }
    pub(crate) fn entries_mut(&mut self) -> &mut [Finding] {
        &mut self.findings
    }
    pub(crate) fn failed(&self) -> bool {
        self.processing.exhausted()
    }
    pub(crate) fn push(&mut self, finding: Finding) {
        if finding.code == FindingCode::LimitExceeded {
            self.processing.fail(self.phase);
            return;
        }
        if self.failed() {
            return;
        }
        if self.processing.report(&finding, self.phase).is_ok() {
            self.findings.push(finding);
        }
    }
    pub(crate) fn extend(&mut self, findings: impl IntoIterator<Item = Finding>) {
        for finding in findings {
            self.push(finding);
            if self.failed() {
                break;
            }
        }
    }
    /// Transfer already charged findings inside this same operation without resetting allowance.
    pub(crate) fn append_charged(&mut self, findings: impl IntoIterator<Item = Finding>) {
        for finding in findings {
            if finding.code == FindingCode::LimitExceeded {
                self.processing.fail(self.phase);
            } else {
                self.findings.push(finding);
            }
        }
    }
    pub(crate) fn into_vec(mut self) -> Vec<Finding> {
        if self.failed() {
            self.findings
                .retain(|finding| finding.code != FindingCode::LimitExceeded);
            self.findings.push(limit(self.phase));
        }
        self.findings
    }
}
impl std::ops::Deref for ProcessingReport {
    type Target = [Finding];
    fn deref(&self) -> &Self::Target {
        &self.findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clones_are_sticky_checked_and_cannot_refund() {
        let budget = NativeOperationBudget::new(NativeProcessingLimits {
            max_processing_units: 2,
            ..NativeProcessingLimits::default()
        });
        assert!(budget.work(1, Phase::Decoding).is_ok());
        let cloned = budget.clone();
        assert!(cloned.work(1, Phase::Generation).is_ok());
        assert!(cloned.work(1, Phase::Analysis).is_err());
        assert!(budget.work(0, Phase::Validation).is_err());
        let overflow = NativeOperationBudget::new(NativeProcessingLimits::default());
        assert!(overflow.work(1, Phase::Parsing).is_ok());
        assert!(overflow.work(usize::MAX, Phase::Parsing).is_err());
        assert!(overflow.exhausted());
    }
    #[test]
    fn report_exhaustion_keeps_prior_violation_and_one_safe_terminal() {
        let budget = NativeOperationBudget::new(NativeProcessingLimits {
            max_report_entries: 1,
            ..NativeProcessingLimits::default()
        });
        let mut report = ProcessingReport::new(budget, Phase::Validation);
        report.push(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation));
        report.push(Finding::warning(FindingCode::UnknownKind, Phase::Validation));
        report.push(Finding::error(FindingCode::LimitExceeded, Phase::Validation));
        let findings = report.into_vec();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].code, FindingCode::NativeFieldInvalid);
        assert_eq!(findings[1].code, FindingCode::LimitExceeded);
        assert!(findings[1].path.is_none());
        assert!(findings[1].resource.is_none());
    }
    #[test]
    fn report_payloads_are_preflighted_against_both_payload_limits() {
        for limits in [
            NativeProcessingLimits {
                max_report_bytes: 0,
                ..NativeProcessingLimits::default()
            },
            NativeProcessingLimits {
                max_payload_bytes: 0,
                ..NativeProcessingLimits::default()
            },
        ] {
            let mut report = ProcessingReport::new(NativeOperationBudget::new(limits), Phase::Validation);
            report.push(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation));
            assert!(report.failed());
            let findings = report.into_vec();
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].code, FindingCode::LimitExceeded);
            assert!(findings[0].path.is_none());
        }
    }
}
