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
pub enum VirtualKind { RowIndex, RamLive }
pub enum PolyAddress { Memory(u32), Witness(u32), Setup(u32), Virtual(VirtualKind),
                       Inner { layer, offset }, Scratch(u32), Cached { layer, offset } }  // + Display
pub enum Coeff { Literal(Fr), Challenge(u32) }
pub enum GateDef { Linear, Product, MaskIntoIdentity, AffineProduct, TreeProduct, Quadratic }
impl GateDef { pub fn operands(&self) -> Vec<PolyAddress>; pub fn coefficients(&self) -> Vec<Coeff>; }
pub struct CatalogueEntry { variant, defined_in, evaluated_in, inputs, output, template, purpose }
pub const CATALOGUE: [CatalogueEntry; 6];
pub struct CachedEntry { name, address, gate }
pub struct ProducingEntry { relation, output, gate }
pub struct EnforcingEntry { relation, gate }
pub struct LayerSpec { halving, num_vars, width, cached, producing, enforcing }
pub struct Relation { name, output: Option<u32>, gate }
pub struct LookupExpr { name, channel, selector: PolyAddress, tuple }
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
pub const FORMAT_VERSION: u32 = 1;
pub const COEFFICIENT_ENCODING_CANONICAL_LE: u32 = 0;
pub const MAX_TRACE_VARS: u32 = 30;

pub mod memory {                                   // docs/spec/memory.md §2, §3.3, §7, §8
    pub const CYCLE: PolyAddress;                  // M[0]
    pub const FIELD_MASK: u32 = 0;  FIELD_ADDR = 1;  FIELD_READ_TS = 2;  FIELD_READ_VALUE = 3;  FIELD_WRITE_VALUE = 4;
    pub const FRAME_QUERIES: usize = 8;
    pub const FRAME_NAMES: [&str; 8];              // pc rs1 rs2 arg1 arg2 load ram rd
    pub const FRAME_SPACE: [u8; 8];                // PC REG REG REG REG RAM RAM REG
    pub const FRAME_DELTA: [u64; 8];               // 0 1 2 2 2 2 3 3
    pub fn frame(query: usize, field: u32) -> PolyAddress;           // M[1 + 5·query + field]
    pub fn gap_hi(query: usize) -> PolyAddress;                      // W[query]
    pub const RD_INV: PolyAddress;  RD_IS_ZERO;  RD_SELECTED;        // W[8], W[9], W[10]
    pub const RD: usize = 7;
    pub fn read_tuple(query: usize) -> GateDef;    // unmasked, Linear, constant γ_M
    pub fn write_tuple(query: usize) -> GateDef;
    pub fn leaf(tuple: &GateDef, mask: PolyAddress) -> GateDef;      // flat Quadratic
    pub fn booleanity(mask: PolyAddress) -> GateDef;
    pub fn gap_lookups(query: usize, hi: PolyAddress) -> [LookupExpr; 2];
    pub fn frame_artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn image_window_artifact(trace_vars: u32) -> CircuitArtifact;  // INIT_TEARDOWN
    pub fn zero_window_artifact(trace_vars: u32) -> CircuitArtifact;   // ZERO_WINDOWS
    pub fn check_memory(a: &CircuitArtifact) -> Result<(), String>;
}
```

## Frozen invariants
- **`PolyAddress` is the only way a polynomial is named**, and where each variant may
  appear is fixed: `M W S V` in gate list 0, `L{k}` in list `k`, `C{k}` in list `k`, never
  `scratch` in a gate; `M W S V scratch` in a relation, never `L` or `C`. The committed
  subtrees are split by role in the type: `M` memory-argument-tied, `W` not, `S` setup.
- **`GateDef` is closed.** Six shapes, wire tags 0–5, append-only. A later stage adds a
  variant with a tag of its own; nothing interprets a coefficient table generically.
- **Cached entries are substituted, never columns.** No table, no claim, no width, no gate
  total. Degree is counted after substitution, which is the one way a degree-3 gate can
  be written — and `validate` refuses it.
- **Laws 1–4 and every other rule of `docs/spec/gkr.md` §4.2 live in `validate`.** It is
  the construction-time check: whatever builds or loads an artifact calls it, once. No
  engine entry point calls it — `gkr_verify::verify` and `gkr`'s passes assume an artifact
  that passed — so the verifying-key and proving-key loading routines of later stages
  must. `crates/checker` enforces the laws a second time with code that shares nothing
  with `src/laws.rs`.
- **A relation constructed and then dropped is refused**: an inner column below the top
  that no gate reads, or a cached entry no gate names, constrains nothing.
- **A halving list halves every column of its layer, in order.**
- **Two virtual kinds, append-only**: `RowIndex` (`V[row]`, tag 0) and `RamLive`
  (`V[ram_live]`, tag 1, `docs/spec/gkr.md` §2.1). Their closed forms are
  `gkr-verify`'s.
- **A lookup is a range obligation** (`docs/spec/memory.md` §7): a channel of
  `constants::lookup_channel`, one `Linear` expression with literal coefficients over
  `M W S V`, and an `M`, `W` or `S` selector. `validate` refuses anything else, naming
  the lookup.
- **The wire form is `postcard` over a tuple per type**, hand-written serde with exactly
  two visitors, no header beyond `format_version` and `coefficient_encoding`. `from_bytes`
  is total, reserves nothing an untrusted length asks for, refuses every format version
  but `FORMAT_VERSION` before decoding anything after it, and takes only the bytes
  `to_bytes` writes. It checks no law, so a checker can be handed a broken artifact.
- **Names are documentation, never semantics**: `[a-z0-9_]`, unique across the whole
  artifact, stored beside what they name.
- **`#![no_std]` + `alloc`, forever.** `gkr-verify` reads artifacts and the recursion
  guest links `gkr-verify`. CI builds it for `riscv32imac-unknown-none-elf`.
- **`memory` holds the memory argument's circuits as data, and `docs/spec/memory.md` is
  normative for it.** The frame layout, the AS and Δ tables, the tuple, leaf and gadget
  gates, the names and the three artifact constructors are there and nowhere else: `trace`
  fills the columns, `gkr-verify`'s boundary evaluates `read_tuple` through the kernel, and
  `kat-gen` writes the constructors' bytes.
- **One tuple gate for circuits and boundary.** `read_tuple(q)` and `write_tuple(q)` are the
  *unmasked* tuple, a `Linear` whose `AS` and `Δ` terms sit on the mask column; with mask 1
  each is exactly `T`. `leaf` turns one into the flat `Quadratic` of §2.2 and §3.3 by rule,
  so the window leaves and the frame leaves are one construction.
- **A memory artifact is built by one private assembly** from complete vectors: leaves, row-wise
  `Product` lists to `[read, write]`, `trace_vars` halving lists, outputs at `READ_ROOT` and
  `WRITE_ROOT` named `read_root` and `write_root`, relations and scratch mirroring every gate,
  an all-zero padding row with `zero_row_valid` decided from the enforcing gates. It asserts
  two gap obligations per read before anything else (S14 must-be-exact 5), then runs
  `validate` and `check_memory`, and panics on any refusal: a memory artifact that exists
  has passed both.
- **`check_memory` is §8, beside `validate`, sharing no code with it**: forward provenance
  (a global slot and a `W` column in one cone), a global slot over anything but `M`, `S`,
  `V`, and a leaf mask that is committed without its booleanity gate in list 0 or virtual
  but not `V[ram_live]`. It assumes an artifact that passed `validate`.
- **The window address step is `WORD_BYTES`, not `TS_STEP`.** Both are 4; one is bytes per
  RAM word, the other timestamps per cycle.

## Fixtures
`tests/vectors/toy_cached.bin` and `tests/vectors/toy_cache_free.bin`: S13's toy
circuit, written at format 1 since S14 with an empty lookup list, and its cache-free
compilation. The toy is defined in `tools/kat-gen/src/gkr.rs`
and nowhere else; `cargo run -p kat-gen -- gkr` rewrites both, CI regenerates and diffs
them, and every suite that reads them pins their SHA-256 first. They are this crate's
output, not an oracle: the independent description of the toy is
`crates/checker/tests/cross_check.rs`.

`tests/vectors/memory_frame.bin`, `image_window.bin` and `zero_window.bin`: the three
`memory` constructors at `trace_vars` 22. `cargo run -p kat-gen -- memory` rewrites them, CI
regenerates and diffs them, and `tests/memory.rs` pins their SHA-256 and holds each to its
constructor's bytes. The leaves' independent description is the plain arithmetic of
`crates/gkr/tests/memory.rs`.

## Tests
| File | Covers |
| --- | --- |
| `tests/wire.rs` | both fixtures round-trip byte for byte; a format version other than 1 refused before decoding; `VirtualKind`'s tags and `V[ram_live]`'s address and name; a lookup against its hand-written bytes; `Quadratic` against its hand-written bytes for no terms, linear only, products only and both, and each malformed `Quadratic` refused; every refusal of the reader; every single-bit flip of a fixture decodes or errors, never panics |
| `tests/laws.rs` | one mutation of the toy per rule, each refused with its error — structured variants matched whole, prose details by the rule and the address or name they carry — beside the toy validating; each lookup rule broken alone, refused naming the lookup, beside one and two lawful lookups and an `M` selector; the degree-3 gate; `Quadratic`'s degree, its identically zero and unread-column cases, Law 4 against an `AffineProduct` relation, and its refusal to inline; cache-free inlining and its refusals |
| `tests/memory.rs` | the three fixtures pinned and equal to their constructors; every constructor validating and passing `check_memory` at 12 and 22; two roots named `read_root`, `write_root`, an all-zero padding row, `trace_vars` halving lists; the frame's layout, leaf order, widths and enforcing gates by name; its 16 obligations whole, `gap_lo_pc`'s constant `−1`; acceptance 11 exhaustively at reduced width, 5-bit chunks over a 10-bit clock, every `(ts, read_ts)` pair admitted exactly when `read_ts < ts`; §8's pinned read sets; `check_memory` refusing a leaf fed from `W` (acceptance 9); the forward-provenance counterexample as a producing and as an enforcing gate of list 1, each beside its lawful control; a slot and a `W` column meeting through two cached entries, a cached entry itself carrying both, and a slot over a cached entry; a frame without `pc_mask_boolean` and one without `rd_mask_boolean`, whose mask another gate still reads; a window leaf masked by `S[0]` and by `V[row]`; and a global slot over an inner column — each mutant still passing `validate`, each test run against the mutant it names |
| `src/memory.rs` (unit) | acceptance 12: the frame with one obligation dropped before the artifact is written panics at the count assertion |
| `tests/audit.rs` | every `GateDef` variant, all six, emitted across both compilations, counts written by hand; the catalogue; the two compilations' identical shape |
