# Foundation fixtures

Foundation inputs are independently authored, minimal inline YAML/JSON cases in
`tests/foundation.rs` and `tests/foundation/codec.rs`. They contain deliberate invalid syntax,
Unicode, duplicate keys, alias cycles, unsupported merge/scalar semantics, private test markers,
source wrappers, version/gate boundaries and unknown descendants. No oracle fixture/source was
copied. Test-only codecs are not shipped production support.

These cases do not discharge the frozen native compatibility/runtime evidence cells.
