//! Fallible test expectations keep extension regressions compatible with the strict lint gate.
pub(super) type TestResult<T = ()> = Result<T, String>;
pub(super) trait TestRequired<T> {
    fn required(self, message: &str) -> TestResult<T>;
}
impl<T> TestRequired<T> for Option<T> {
    fn required(self, message: &str) -> TestResult<T> {
        self.ok_or_else(|| message.to_owned())
    }
}
impl<T, E> TestRequired<T> for Result<T, E> {
    fn required(self, message: &str) -> TestResult<T> {
        self.map_err(|_| message.to_owned())
    }
}
