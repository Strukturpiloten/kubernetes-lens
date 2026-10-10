//! Independent exact JSON grammar, mathematical comparison and finite-limit checks.
use kubernetes_lens::{
    FindingCode,
    processing::NativeProcessingLimits,
    source::{ExplicitSourceAccess, ParseLimits},
    value::ExactJsonNumber,
};
use std::cmp::Ordering;

fn number(value: &str) -> Result<ExactJsonNumber, String> {
    ExactJsonNumber::parse(value, &ParseLimits::default()).map_err(|_| "valid JSON number was rejected".into())
}
fn require<T>(result: Result<T, kubernetes_lens::Finding>) -> Result<T, String> {
    result.map_err(|_| "unexpected bounded operation failure".into())
}
fn failure<T>(result: Result<T, kubernetes_lens::Finding>) -> Result<kubernetes_lens::Finding, String> {
    result.err().ok_or_else(|| "operation should have failed".into())
}
#[test]
fn comparison_is_mathematical_without_float_rounding_or_exponent_expansion() -> Result<(), String> {
    let limits = ParseLimits::default();
    for (left, right, expected) in [
        ("9007199254740992", "9007199254740993", Ordering::Less),
        ("-9007199254740992", "-9007199254740993", Ordering::Greater),
        ("0.000000000000000000001", "0.000000000000000000002", Ordering::Less),
        ("-0.0e2147483647", "0e-2147483648", Ordering::Equal),
        ("1e2147483647", "9e2147483646", Ordering::Greater),
        ("1e-2147483648", "2e-2147483648", Ordering::Less),
        ("10.00e-1", "1", Ordering::Equal),
        ("1.201", "1.21", Ordering::Less),
        ("-1.201", "-1.21", Ordering::Greater),
    ] {
        let left = number(left)?;
        let right = number(right)?;
        assert_eq!(require(left.compare(&right, &limits))?, expected);
        assert_eq!(left == right, expected == Ordering::Equal);
    }
    Ok(())
}
#[test]
fn grammar_is_strict_json_and_errors_do_not_reveal_spelling() -> Result<(), String> {
    for value in [
        "",
        "+1",
        "01",
        "-01",
        ".5",
        "1.",
        "1e",
        "1e+",
        "0x12",
        "NaN",
        "1Gi",
        " 1",
        "1\n",
        "1e000000000000x",
    ] {
        let finding = failure(ExactJsonNumber::parse(value, &ParseLimits::default()))?;
        assert_eq!(finding.code, FindingCode::NativeFieldInvalid);
        assert!(finding.path.is_none());
    }
    let value = number("123456789.0123456789")?;
    assert!(!format!("{value:?}").contains("123456789"));
    assert_eq!(
        value.lexeme(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        "123456789.0123456789"
    );
    Ok(())
}
#[test]
fn comparison_has_a_precise_lowered_ceiling_even_for_signed_zero() -> Result<(), String> {
    let left = number("-0")?;
    let right = number("0")?;
    for allowance in [0, 512] {
        let limits = ParseLimits {
            processing: NativeProcessingLimits {
                max_processing_units: allowance,
                ..NativeProcessingLimits::default()
            },
            ..ParseLimits::default()
        };
        assert_eq!(failure(left.compare(&right, &limits))?.code, FindingCode::LimitExceeded);
    }
    let limits = ParseLimits {
        processing: NativeProcessingLimits {
            max_processing_units: 513,
            ..NativeProcessingLimits::default()
        },
        ..ParseLimits::default()
    };
    assert_eq!(require(left.compare(&right, &limits))?, Ordering::Equal);
    Ok(())
}
#[test]
fn number_shape_boundaries_are_finite() -> Result<(), String> {
    let maximum = "9".repeat(512);
    assert!(ExactJsonNumber::parse(&maximum, &ParseLimits::default()).is_ok());
    let one_over = "9".repeat(513);
    assert_eq!(
        failure(ExactJsonNumber::parse(&one_over, &ParseLimits::default()))?.code,
        FindingCode::LimitExceeded
    );
    let limits = ParseLimits {
        max_scalar_bytes: 2,
        ..ParseLimits::default()
    };
    assert!(ExactJsonNumber::parse("12", &limits).is_ok());
    assert_eq!(
        failure(ExactJsonNumber::parse("123", &limits))?.code,
        FindingCode::LimitExceeded
    );
    let limits = ParseLimits {
        max_input_bytes: 2,
        ..ParseLimits::default()
    };
    assert_eq!(
        failure(ExactJsonNumber::parse("123", &limits))?.code,
        FindingCode::LimitExceeded
    );
    for value in ["1e2147483648", "1e-2147483649", "1e000000000000"] {
        assert_eq!(
            failure(ExactJsonNumber::parse(value, &ParseLimits::default()))?.code,
            FindingCode::LimitExceeded
        );
    }
    Ok(())
}
