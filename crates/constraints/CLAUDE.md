# `crates/constraints`

## What this crate owns
Circuit families as data: `PolyAddress`, the closed `GateDef` enum and its `Coeff`,
`LayerSpec`, and the `CircuitArtifact` that holds a circuit twice — as a flat constraint
list and as layered gates — with the laws tying the two together, the cache-free
compilation, the gate catalogue and the `postcard` wire form.

Nothing here evaluates a gate. The kernel is `gkr_verify::eval_gate`, and it is the
semantic authority; this crate owns the formula *representation* and the checks made
when a circuit is built. **`docs/spec/gkr.md` §1–§4 is normative.**

```rust
pub enum VirtualKind { RowIndex }
pub enum PolyAddress { Memory(u32), Witness(u32), Setup(u32), Virtual(VirtualKind),
                       Inner { layer, offset }, Scratch(u32), Cached { layer, offset } }  // + Display
pub enum Coeff { Literal(Fr), Challenge(u32) }
pub enum GateDef { Linear, Product, MaskIntoIdentity, AffineProduct, TreeProduct }
impl GateDef { pub fn operands(&self) -> Vec<PolyAddress>; pub fn coefficients(&self) -> Vec<Coeff>; }
pub struct CatalogueEntry { variant, defined_in, evaluated_in, inputs, output, template, purpose }
pub const CATALOGUE: [CatalogueEntry; 5];
pub struct CachedEntry { name, address, gate }
pub struct ProducingEntry { relation, output, gate }
pub struct EnforcingEntry { relation, gate }
pub struct LayerSpec { halving, num_vars, width, cached, producing, enforcing }
pub struct Relation { name, output: Option<u32>, gate }
pub struct LookupExpr { name, channel, tuple }
pub struct ScratchSlot { name, address }
pub struct Padding { row: Vec<Fr>, zero_row_valid: bool }
pub struct CircuitArtifact { format_version, coefficient_encoding, trace_vars, memory, witness, setup,
                             virtuals, layers, relations, lookups, scratch, outputs, padding }
impl CircuitArtifact {
    pub fn depth(&self) -> usize;  pub fn layer_vars(&self, k) -> u32;  pub fn layer_width(&self, k) -> u32;
    pub fn committed(&self) -> Vec<PolyAddress>;
    pub fn validate(&self) -> Result<(), ConstraintError>;
    pub fn inline_cached(&self) -> Result<CircuitArtifact, ConstraintError>;
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(bytes: &[u8]) -> Result<CircuitArtifact, String>;
}
pub enum ConstraintError { Locality, DerivedWidth, TopLayer, SingleSource, Degree, NotInlinable, Malformed }
pub const FORMAT_VERSION: u32 = 0;
pub const COEFFICIENT_ENCODING_CANONICAL_LE: u32 = 0;
pub const MAX_TRACE_VARS: u32 = 30;
```

## Frozen invariants
- **`PolyAddress` is the only way a polynomial is named**, and where each variant may
  appear is fixed: `M W S V` in gate list 0, `L{k}` in list `k`, `C{k}` in list `k`, never
  `scratch` in a gate; `M W S V scratch` in a relation, never `L` or `C`. The committed
  subtrees are split by role in the type: `M` memory-argument-tied, `W` not, `S` setup.
- **`GateDef` is closed.** Five shapes, wire tags 0–4, append-only. A later stage adds a
  variant with a tag of its own; nothing interprets a coefficient table generically.
- **Cached entries are substituted, never columns.** No table, no claim, no width, no gate
  total. Degree is counted after substitution, which is the one way a degree-3 gate can
  be written — and `validate` refuses it.
- **Laws 1–4 and every other rule of `docs/spec/gkr.md` §4.2 live in `validate`.** It is
  the construction-time check: whatever builds an artifact calls it, every engine entry
  point asserts it. `crates/checker` enforces the laws a second time with code that shares
  nothing with `src/laws.rs`.
- **A relation constructed and then dropped is refused**: an inner column below the top
  that no gate reads, or a cached entry no gate names, constrains nothing.
- **A halving list halves every column of its layer, in order.**
- **The wire form is `postcard` over a tuple per type**, hand-written serde with exactly
  two visitors, no header beyond `format_version` and `coefficient_encoding`. `from_bytes`
  is total, reserves nothing an untrusted length asks for, and takes only the bytes
  `to_bytes` writes. It checks no law, so a checker can be handed a broken artifact.
- **Names are documentation, never semantics**: `[a-z0-9_]`, unique across the whole
  artifact, stored beside what they name.
- **`#![no_std]` + `alloc`, forever.** `gkr-verify` reads artifacts and the recursion
  guest links `gkr-verify`. CI builds it for `riscv32imac-unknown-none-elf`.

## Fixtures
`tests/vectors/toy_cached.bin` and `tests/vectors/toy_cache_free.bin`: S13's toy
circuit and its cache-free compilation. The toy is defined in `tools/kat-gen/src/gkr.rs`
and nowhere else; `cargo run -p kat-gen -- gkr` rewrites both, CI regenerates and diffs
them, and every suite that reads them pins their SHA-256 first. They are this crate's
output, not an oracle: the independent description of the toy is
`crates/checker/tests/cross_check.rs`.

## Tests
| File | Covers |
| --- | --- |
| `tests/wire.rs` | both fixtures round-trip byte for byte; every refusal of the reader; every single-bit flip of a fixture decodes or errors, never panics |
| `tests/laws.rs` | one mutation of the toy per rule, each refused with its error — structured variants matched whole, prose details by the rule and the address or name they carry — beside the toy validating; the degree-3 gate; cache-free inlining and its refusals |
| `tests/audit.rs` | every `GateDef` variant emitted across both compilations; the catalogue; the two compilations' identical shape |
