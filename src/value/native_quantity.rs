//! Exact supplied order without native rounding, capping or exponent expansion.
use super::Quantity;
use crate::{
    diagnostic::{Finding, Phase},
    processing::{NativeOperationBudget, NativeProcessingLimits},
    registry::FieldDecodeContext,
};
use std::cmp::Ordering;

/// Conservative classification, independent of exact supplied ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeQuantityDomain {
    /// Both supplied values are nonnegative integral bytes no larger than `i64::MAX`.
    /// This is an arithmetic domain, not API acceptance, field positivity or provisioning proof.
    ConservativeIntegralBytes,
    /// Exact Lens order is known, but native rounding/capping semantics are unverified.
    NativeSemanticsUnverified,
}
/// An exact supplied comparison plus its separately stated native arithmetic domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuppliedQuantityOrder {
    /// Mathematical order of exactly supplied values, without rounding/capping.
    pub ordering: Ordering,
    /// Conservative domain classification; field-specific validation remains separate.
    pub native_domain: NativeQuantityDomain,
}
impl Quantity {
    pub(crate) fn parse_in(lexeme: &str, ctx: &FieldDecodeContext) -> Result<Self, Finding> {
        if !ctx.limits.valid() || lexeme.len() > ctx.limits.max_scalar_bytes {
            return Err(ctx.processing.fail(ctx.phase));
        }
        // Keep the established grammar bound and invalid-grammar outcome unchanged.
        if lexeme.is_empty() || lexeme.len() > 512 || !lexeme.is_ascii() {
            return Err(super::invalid_value());
        }
        let rounds = ["Ki", "Mi", "Gi", "Ti", "Pi", "Ei"]
            .iter()
            .position(|suffix| lexeme.ends_with(suffix))
            .map_or(0, |index| (index + 1) * 10);
        let coefficient = lexeme
            .len()
            .checked_add(20)
            .ok_or_else(|| ctx.processing.fail(ctx.phase))?;
        // Conservative bound includes digit strings and the existing char scratch in binary parsing.
        let payload = coefficient
            .checked_mul(8)
            .and_then(|bytes| bytes.checked_mul(rounds + 1))
            .and_then(|bytes| bytes.checked_add(lexeme.len()))
            .ok_or_else(|| ctx.processing.fail(ctx.phase))?;
        let work = coefficient
            .checked_mul(2)
            .and_then(|units| units.checked_mul(rounds + 1))
            .ok_or_else(|| ctx.processing.fail(ctx.phase))?;
        ctx.processing.payload(payload, ctx.phase)?;
        ctx.processing.work(work, ctx.phase)?;
        Self::parse_unbudgeted(lexeme)
    }
    /// Compare exactly supplied mathematical values under one bounded operation.
    /// Native Kubernetes rounding/capping and storage/controller behavior are not inferred.
    /// # Errors
    /// Returns a fixed pathless `LimitExceeded` when the conservative comparison allowance is exhausted.
    pub fn compare_supplied(
        &self,
        other: &Self,
        limits: &NativeProcessingLimits,
    ) -> Result<SuppliedQuantityOrder, Finding> {
        let processing = NativeOperationBudget::new(*limits);
        let ordering = self.compare_exact(other, &processing, Phase::Validation)?;
        Ok(SuppliedQuantityOrder {
            ordering,
            native_domain: if self.conservative_bytes() && other.conservative_bytes() {
                NativeQuantityDomain::ConservativeIntegralBytes
            } else {
                NativeQuantityDomain::NativeSemanticsUnverified
            },
        })
    }
    pub(crate) fn compare_exact(
        &self,
        other: &Self,
        processing: &NativeOperationBudget,
        phase: Phase,
    ) -> Result<Ordering, Finding> {
        // Fixed before all zero/sign shortcuts: <=531 coefficient digits plus two rank/sign units.
        processing.work(533, phase)?;
        let left = &self.value;
        let right = &other.value;
        if left.sign != right.sign {
            return Ok(left.sign.cmp(&right.sign));
        }
        if left.sign == 0 {
            return Ok(Ordering::Equal);
        }
        let rank = |quantity: &super::ExactQuantity| {
            i64::try_from(quantity.digits.len())
                .ok()
                .and_then(|length| length.checked_sub(i64::from(quantity.scale)))
                .ok_or_else(|| processing.fail(phase))
        };
        let mut order = rank(left)?.cmp(&rank(right)?);
        if order == Ordering::Equal {
            for index in 0..left.digits.len().max(right.digits.len()) {
                order = left
                    .digits
                    .as_bytes()
                    .get(index)
                    .copied()
                    .unwrap_or(b'0')
                    .cmp(&right.digits.as_bytes().get(index).copied().unwrap_or(b'0'));
                if order != Ordering::Equal {
                    break;
                }
            }
        }
        Ok(if left.sign < 0 { order.reverse() } else { order })
    }
    fn conservative_bytes(&self) -> bool {
        let value = &self.value;
        if value.sign < 0 || value.scale > 0 {
            return false;
        }
        if value.sign == 0 {
            return true;
        }
        let Some(rank) = i64::try_from(value.digits.len())
            .ok()
            .and_then(|length| length.checked_sub(i64::from(value.scale)))
        else {
            return false;
        };
        if rank != 19 {
            return rank < 19;
        }
        value
            .digits
            .bytes()
            .chain(std::iter::repeat(b'0'))
            .take(19)
            .cmp(b"9223372036854775807".iter().copied())
            != Ordering::Greater
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_comparisons_share_exact_fixed_allowance() -> Result<(), String> {
        let quantity = Quantity::parse("1Gi").map_err(|_| "quantity parse failed")?;
        for (units, second_succeeds) in [(1065, false), (1066, true)] {
            let budget = NativeOperationBudget::new(NativeProcessingLimits {
                max_processing_units: units,
                ..NativeProcessingLimits::default()
            });
            assert!(quantity.compare_exact(&quantity, &budget, Phase::Validation).is_ok());
            assert_eq!(
                quantity.compare_exact(&quantity, &budget, Phase::Validation).is_ok(),
                second_succeeds
            );
        }
        Ok(())
    }
    #[test]
    fn field_limit_error_stays_pathless() -> Result<(), String> {
        use crate::{
            diagnostic::{FieldPath, FindingCode},
            registry::codec::FieldCodec,
            source::ParseLimits,
            syntax::TreeNode,
        };
        let limits = ParseLimits {
            processing: NativeProcessingLimits {
                max_payload_bytes: 0,
                ..NativeProcessingLimits::default()
            },
            ..ParseLimits::default()
        };
        let context = FieldDecodeContext::new(limits, NativeOperationBudget::new(limits.processing), Phase::Decoding);
        let finding = Quantity::decode(
            &TreeNode::string("1Gi"),
            &context,
            &FieldPath(vec!["private-key".into()]),
        )
        .err()
        .ok_or("missing quantity limit")?;
        assert_eq!(finding.code, FindingCode::LimitExceeded);
        assert!(finding.path.is_none());
        Ok(())
    }
}
