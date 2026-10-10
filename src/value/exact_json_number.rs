//! Exact finite JSON numbers; this is not Kubernetes' floating-point schema oracle.
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    processing::NativeOperationBudget,
    registry::{EncodeContext, FieldDecodeContext, codec::FieldCodec},
    source::{ExplicitSourceAccess, ParseLimits},
    syntax::{TreeNode, TreeValue},
};
use std::{cmp::Ordering, fmt, sync::Arc};

const MAX_LEXEME: usize = 512;
const MAX_EXPONENT_TOKEN: usize = 11;
struct Number {
    lexeme: String,
    coefficient: String,
    sign: i8,
    scale: i64,
}
/// A strictly parsed JSON number with exact decimal mathematical comparison.
/// Original spelling is private; clones share immutable backing.
#[derive(Clone)]
pub struct ExactJsonNumber(Arc<Number>);
impl fmt::Debug for ExactJsonNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExactJsonNumber(<private>)")
    }
}
impl PartialEq for ExactJsonNumber {
    fn eq(&self, other: &Self) -> bool {
        self.0.sign == other.0.sign && self.0.scale == other.0.scale && self.0.coefficient == other.0.coefficient
    }
}
impl Eq for ExactJsonNumber {}
impl ExactJsonNumber {
    pub(crate) fn native_lexeme(&self) -> &str {
        &self.0.lexeme
    }
    /// Parse the JSON number grammar without accepting quantity suffixes or floats.
    /// # Errors
    /// Rejects malformed numbers, excessive lexemes/exponents and finite budgets.
    pub fn parse(value: &str, limits: &ParseLimits) -> Result<Self, Finding> {
        let context = FieldDecodeContext::new(*limits, NativeOperationBudget::new(limits.processing), Phase::Decoding);
        if value.len() > limits.max_input_bytes {
            return Err(context.processing.fail(context.phase));
        }
        Self::parse_in(value, &context).map_err(|finding| {
            if finding.code == FindingCode::LimitExceeded {
                finding
            } else {
                context
                    .processing
                    .report(&finding, context.phase)
                    .err()
                    .unwrap_or(finding)
            }
        })
    }
    /// Inspect retained spelling only with explicit private-value authorization.
    #[must_use]
    pub fn lexeme(&self, _access: &ExplicitSourceAccess) -> &str {
        &self.0.lexeme
    }
    /// Compare exact supplied values; no native-double parity is implied.
    /// # Errors
    /// Refuses a lowered processing allowance without expanding exponents.
    pub fn compare(&self, other: &Self, limits: &ParseLimits) -> Result<Ordering, Finding> {
        let processing = NativeOperationBudget::new(limits.processing);
        if !limits.valid()
            || [self, other].iter().any(|number| {
                number.0.lexeme.len() > limits.max_input_bytes || number.0.lexeme.len() > limits.max_scalar_bytes
            })
        {
            return Err(processing.fail(Phase::Analysis));
        }
        self.compare_in(other, &processing, Phase::Analysis)
    }
    pub(crate) fn compare_in(
        &self,
        other: &Self,
        processing: &NativeOperationBudget,
        phase: Phase,
    ) -> Result<Ordering, Finding> {
        processing.work(MAX_LEXEME.checked_add(1).ok_or_else(|| processing.fail(phase))?, phase)?;
        if self.0.sign != other.0.sign {
            return Ok(self.0.sign.cmp(&other.0.sign));
        }
        if self.0.sign == 0 {
            return Ok(Ordering::Equal);
        }
        let rank = |number: &Number| {
            i64::try_from(number.coefficient.len())
                .ok()
                .and_then(|length| length.checked_sub(number.scale))
                .ok_or_else(|| processing.fail(phase))
        };
        let mut order = rank(&self.0)?.cmp(&rank(&other.0)?);
        if order == Ordering::Equal {
            let left = self.0.coefficient.as_bytes();
            let right = other.0.coefficient.as_bytes();
            for index in 0..left.len().max(right.len()) {
                order = left
                    .get(index)
                    .copied()
                    .unwrap_or(b'0')
                    .cmp(&right.get(index).copied().unwrap_or(b'0'));
                if order != Ordering::Equal {
                    break;
                }
            }
        }
        Ok(if self.0.sign < 0 { order.reverse() } else { order })
    }
    pub(crate) fn parse_in(value: &str, ctx: &FieldDecodeContext) -> Result<Self, Finding> {
        let phase = ctx.phase;
        let processing = &ctx.processing;
        processing.work(1, phase)?;
        if !ctx.limits.valid() || value.len() > MAX_LEXEME || value.len() > ctx.limits.max_scalar_bytes {
            return Err(processing.fail(phase));
        }
        processing.work(value.len().checked_mul(6).ok_or_else(|| processing.fail(phase))?, phase)?;
        let bytes = value.as_bytes();
        let mut cursor = usize::from(bytes.first() == Some(&b'-'));
        let negative = cursor == 1;
        let integer_start = cursor;
        match bytes.get(cursor) {
            Some(b'0') => cursor += 1,
            Some(b'1'..=b'9') => {
                cursor += 1;
                while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                    cursor += 1;
                }
            }
            _ => return Err(invalid(phase)),
        }
        let integer_end = cursor;
        let mut fraction_start = cursor;
        let mut fraction_end = cursor;
        if bytes.get(cursor) == Some(&b'.') {
            cursor += 1;
            fraction_start = cursor;
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                cursor += 1;
            }
            fraction_end = cursor;
            if fraction_start == fraction_end {
                return Err(invalid(phase));
            }
        }
        let exponent_text = if bytes.get(cursor).is_some_and(|byte| matches!(byte, b'e' | b'E')) {
            cursor += 1;
            let start = cursor;
            if bytes.get(cursor).is_some_and(|byte| matches!(byte, b'+' | b'-')) {
                cursor += 1;
            }
            let digits = cursor;
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                cursor += 1;
            }
            if cursor == digits {
                return Err(invalid(phase));
            }
            Some(&value[start..cursor])
        } else {
            None
        };
        if cursor != bytes.len() {
            return Err(invalid(phase));
        }
        let exponent = if let Some(token) = exponent_text {
            if token.len() > MAX_EXPONENT_TOKEN {
                return Err(processing.fail(phase));
            }
            token.parse::<i32>().map_err(|_| processing.fail(phase))?
        } else {
            0
        };
        let digit_length = (integer_end - integer_start)
            .checked_add(fraction_end - fraction_start)
            .ok_or_else(|| processing.fail(phase))?;
        processing.payload_sizes([value.len(), digit_length, size_of::<Number>()], phase)?;
        processing.work(digit_length, phase)?;
        let mut coefficient = String::with_capacity(digit_length);
        coefficient.push_str(&value[integer_start..integer_end]);
        coefficient.push_str(&value[fraction_start..fraction_end]);
        let leading = coefficient.bytes().take_while(|byte| *byte == b'0').count();
        let mut scale = i64::try_from(fraction_end - fraction_start)
            .ok()
            .and_then(|fraction| fraction.checked_sub(i64::from(exponent)))
            .ok_or_else(|| processing.fail(phase))?;
        let sign = if leading == coefficient.len() {
            coefficient.clear();
            scale = 0;
            0
        } else {
            drop(coefficient.drain(..leading));
            let trailing = coefficient.bytes().rev().take_while(|byte| *byte == b'0').count();
            coefficient.truncate(coefficient.len() - trailing);
            scale = scale
                .checked_sub(i64::try_from(trailing).map_err(|_| processing.fail(phase))?)
                .ok_or_else(|| processing.fail(phase))?;
            if negative { -1 } else { 1 }
        };
        Ok(Self(Arc::new(Number {
            lexeme: value.to_owned(),
            coefficient,
            sign,
            scale,
        })))
    }
}
fn invalid(phase: Phase) -> Finding {
    Finding::error(FindingCode::NativeFieldInvalid, phase)
}
impl FieldCodec for ExactJsonNumber {
    fn decode(node: &TreeNode, ctx: &FieldDecodeContext, path: &FieldPath) -> Result<Self, Finding> {
        let TreeValue::Number(value) = &node.value else {
            return Err(invalid(ctx.phase).at_path(path.clone()));
        };
        Self::parse_in(value, ctx).map_err(|finding| {
            if finding.code == FindingCode::LimitExceeded {
                finding
            } else {
                finding.at_path(path.clone())
            }
        })
    }
    fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
        let phase = ctx.budget.phase();
        if self.0.lexeme.len() > ctx.limits.max_scalar_bytes {
            return Err(ctx.budget.processing().fail(phase));
        }
        ctx.budget.processing().work(self.0.lexeme.len(), phase)?;
        ctx.budget.processing().payload(self.0.lexeme.len(), phase)?;
        ctx.budget.scalar(self.0.lexeme.len(), path)?;
        Ok(TreeNode::new(TreeValue::Number(self.0.lexeme.clone())))
    }
}
