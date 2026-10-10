//! One protected decoded byte authority; base64 spelling remains source evidence.
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    processing::NativeOperationBudget,
    registry::{EncodeContext, FieldDecodeContext, codec::FieldCodec},
    source::{ExplicitSourceAccess, ParseLimits},
    syntax::TreeNode,
};
use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use std::{fmt, sync::Arc};

fn engine() -> GeneralPurpose {
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
            .with_decode_allow_trailing_bits(true),
    )
}
/// Protected native bytes, with no second editable encoded-string authority.
/// Cloning shares the immutable payload rather than allocating another byte copy.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeBytes(Arc<Vec<u8>>);
impl fmt::Debug for NativeBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeBytes(<private>)")
    }
}
impl NativeBytes {
    /// Consume caller-owned bytes after bounded fresh base64-output preflight.
    /// The existing caller buffer is not counted as a library payload allocation.
    /// # Errors
    /// Refuses scalar/output-size or processing limits without exposing bytes.
    pub fn try_from_bytes(bytes: Vec<u8>, limits: &ParseLimits) -> Result<Self, Finding> {
        let processing = NativeOperationBudget::new(limits.processing);
        processing.work(1, Phase::Decoding)?;
        fresh_len(bytes.len(), limits, &processing, Phase::Decoding)?;
        Ok(Self(Arc::new(bytes)))
    }
    /// Decode standard padded base64, allowing only CR/LF whitespace and native unused tail bits.
    /// Original spelling is not retained in this editable native value.
    /// # Errors
    /// Refuses invalid alphabet/padding, other whitespace, or cumulative finite limits.
    pub fn parse_base64(value: &str, limits: &ParseLimits) -> Result<Self, Finding> {
        let processing = NativeOperationBudget::new(limits.processing);
        let ctx = FieldDecodeContext::new(*limits, processing.clone(), Phase::Decoding);
        Self::decode_text(value, &ctx, &FieldPath::default()).map_err(|finding| {
            if finding.code == FindingCode::LimitExceeded {
                finding
            } else {
                processing.report(&finding, ctx.phase).err().unwrap_or(finding)
            }
        })
    }
    /// Reveal actual native bytes only after separate explicit source authorization.
    #[must_use]
    pub fn bytes(&self, _access: &ExplicitSourceAccess) -> &[u8] {
        &self.0
    }
    pub(crate) fn native_bytes(&self) -> &[u8] {
        &self.0
    }
    fn decode_text(value: &str, ctx: &FieldDecodeContext, path: &FieldPath) -> Result<Self, Finding> {
        let budget = &ctx.processing;
        budget.work(1, ctx.phase)?;
        if !ctx.limits.valid() || value.len() > ctx.limits.max_scalar_bytes {
            return Err(budget.fail(ctx.phase));
        }
        budget.work(value.len(), ctx.phase)?;
        let mut count = 0usize;
        let mut whitespace = false;
        let mut padding = 0usize;
        for byte in value.bytes() {
            if matches!(byte, b'\r' | b'\n') {
                whitespace = true;
                continue;
            }
            count = count.checked_add(1).ok_or_else(|| budget.fail(ctx.phase))?;
            padding = if byte == b'=' { padding + 1 } else { 0 };
        }
        if count % 4 != 0 || padding > 2 {
            return Err(invalid(ctx.phase, path));
        }
        let capacity = (count / 4).checked_mul(3).ok_or_else(|| budget.fail(ctx.phase))?;
        let decoded = capacity.checked_sub(padding).ok_or_else(|| invalid(ctx.phase, path))?;
        if decoded > ctx.limits.max_input_bytes {
            return Err(budget.fail(ctx.phase));
        }
        // Reserve every new payload before allocation; rejected attempts never refund.
        if whitespace {
            budget.payload(count, ctx.phase)?;
        }
        budget.payload(capacity, ctx.phase)?;
        budget.work(value.len(), ctx.phase)?;
        budget.work(count, ctx.phase)?;
        let filtered;
        let input = if whitespace {
            let mut buffer = Vec::with_capacity(count);
            buffer.extend(value.bytes().filter(|byte| !matches!(byte, b'\r' | b'\n')));
            filtered = buffer;
            filtered.as_slice()
        } else {
            value.as_bytes()
        };
        let mut bytes = vec![0; capacity];
        let length = engine()
            .decode_slice(input, &mut bytes)
            .map_err(|_| invalid(ctx.phase, path))?;
        if length != decoded {
            return Err(invalid(ctx.phase, path));
        }
        bytes.truncate(length);
        Ok(Self(Arc::new(bytes)))
    }
}
fn fresh_len(
    length: usize,
    limits: &ParseLimits,
    budget: &NativeOperationBudget,
    phase: Phase,
) -> Result<usize, Finding> {
    let encoded = base64::encoded_len(length, true).ok_or_else(|| budget.fail(phase))?;
    if !limits.valid() || encoded > limits.max_scalar_bytes || encoded > limits.max_input_bytes {
        return Err(budget.fail(phase));
    }
    Ok(encoded)
}
fn invalid(phase: Phase, path: &FieldPath) -> Finding {
    Finding::error(FindingCode::NativeFieldInvalid, phase).at_path(path.clone())
}
impl FieldCodec for NativeBytes {
    fn decode(node: &TreeNode, ctx: &FieldDecodeContext, path: &FieldPath) -> Result<Self, Finding> {
        Self::decode_text(node.as_str().ok_or_else(|| invalid(ctx.phase, path))?, ctx, path)
    }
    fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
        let fields = ctx.fields(ctx.budget.phase());
        let length = fresh_len(self.0.len(), &fields.limits, &fields.processing, fields.phase)?;
        fields.processing.payload(length, fields.phase)?;
        fields.processing.work(self.0.len(), fields.phase)?;
        fields.processing.work(length, fields.phase)?;
        let mut encoded = vec![0; length];
        let written = engine()
            .encode_slice(self.native_bytes(), &mut encoded)
            .map_err(|_| fields.processing.fail(fields.phase))?;
        if written != length {
            return Err(fields.processing.fail(fields.phase));
        }
        fields.processing.work(length, fields.phase)?;
        let encoded = String::from_utf8(encoded).map_err(|_| fields.processing.fail(fields.phase))?;
        ctx.owned_string(encoded, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::processing::NativeProcessingLimits;
    #[test]
    fn fresh_encoding_is_canonical_and_copy_charges_share_the_operation() -> Result<(), String> {
        let bytes =
            NativeBytes::parse_base64("Z\r\nh==", &ParseLimits::default()).map_err(|_| "base64 parse failed")?;
        let limits = ParseLimits {
            processing: NativeProcessingLimits {
                max_payload_bytes: 7,
                ..NativeProcessingLimits::default()
            },
            ..ParseLimits::default()
        };
        let operation = NativeOperationBudget::new(limits.processing);
        let context = EncodeContext::in_operation(None, limits, operation.clone());
        let path = FieldPath::default();
        let node = bytes.encode(&context, &path).map_err(|_| "fresh encoding failed")?;
        assert_eq!(node.as_str(), Some("Zg=="));
        assert!(context.clone_node(&node, &path).is_err());
        assert!(operation.exhausted());
        assert!(bytes.encode(&context, &path).is_err());
        Ok(())
    }
    #[test]
    fn decode_context_clones_do_not_reset_binary_payload_allowance() -> Result<(), String> {
        let limits = ParseLimits {
            processing: NativeProcessingLimits {
                max_payload_bytes: 5,
                ..NativeProcessingLimits::default()
            },
            ..ParseLimits::default()
        };
        let context = FieldDecodeContext::new(limits, NativeOperationBudget::new(limits.processing), Phase::Decoding);
        let node = TreeNode::string("AAEC");
        NativeBytes::decode(&node, &context, &FieldPath::default()).map_err(|_| "first decode failed")?;
        assert!(NativeBytes::decode(&node, &context.clone(), &FieldPath::default()).is_err());
        assert!(context.processing.exhausted());
        Ok(())
    }
    struct SyntheticBinary(NativeBytes);
    impl FieldCodec for SyntheticBinary {
        fn decode(node: &TreeNode, ctx: &FieldDecodeContext, path: &FieldPath) -> Result<Self, Finding> {
            NativeBytes::decode(
                node.get("data").ok_or_else(|| invalid(ctx.phase, path))?,
                ctx,
                &path.child("data"),
            )
            .map(Self)
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            let child = path.child("data");
            ctx.object(vec![(ctx.key("data", &child)?, self.0.encode(ctx, &child)?)], path)
        }
    }
    #[test]
    fn typed_binary_delta_preserves_unchanged_spelling_and_canonicalizes_changes() -> Result<(), String> {
        use crate::{
            generation::{MergeContext, merge_native_delta},
            source::{DocumentFormat, InputOrigin, SourceId, SourceInput},
        };
        let text = b"data: 'Zh=='\nopaque: private-neighbor\n";
        let input = crate::parse_source(
            SourceInput {
                id: SourceId(19),
                format: DocumentFormat::YamlStream,
                origin: InputOrigin::Authored,
                source_version: None,
                bytes: text,
            },
            &ParseLimits::default(),
        )
        .map_err(|_| "source parse failed")?;
        let original = input.trees.first().ok_or("missing syntax tree")?;
        let fields = FieldDecodeContext::new(ParseLimits::default(), input.processing.clone(), Phase::Decoding);
        let native = SyntheticBinary::decode(original, &fields, &FieldPath::default())
            .map_err(|_| "typed binary decode failed")?;
        let context = EncodeContext::in_operation(None, ParseLimits::default(), input.processing.clone());
        let known = native
            .encode(&context, &FieldPath::default())
            .map_err(|_| "known encode failed")?;
        assert_eq!(known.get("data").and_then(TreeNode::as_str), Some("Zg=="));
        let unchanged = native
            .encode(&context, &FieldPath::default())
            .map_err(|_| "unchanged encode failed")?;
        let merge = |after: &TreeNode| {
            merge_native_delta(
                original,
                &known,
                after,
                &FieldPath::default(),
                &[],
                &[],
                MergeContext {
                    gvk: None,
                    target: None,
                },
            )
            .map_err(|_| "binary delta failed")
        };
        let retained = merge(&unchanged)?;
        assert_eq!(retained.get("data").and_then(TreeNode::as_str), Some("Zh=="));
        let changed = SyntheticBinary(
            NativeBytes::try_from_bytes(b"foo".to_vec(), &ParseLimits::default()).map_err(|_| "fresh bytes failed")?,
        );
        let changed = changed
            .encode(&context, &FieldPath::default())
            .map_err(|_| "changed encode failed")?;
        let emitted = merge(&changed)?;
        assert_eq!(emitted.get("data").and_then(TreeNode::as_str), Some("Zm9v"));
        assert_eq!(
            emitted.get("opaque").and_then(TreeNode::as_str),
            Some("private-neighbor")
        );
        assert_eq!(original.get("data").and_then(TreeNode::as_str), Some("Zh=="));
        assert_eq!(
            input
                .evidence
                .reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
            text
        );
        Ok(())
    }
}
