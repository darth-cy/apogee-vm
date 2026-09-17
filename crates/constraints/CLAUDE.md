# `crates/constraints`

## What this crate owns
Circuit families as data: `PolyAddress`, the closed `GateDef` enum and its `Coeff`,
`LayerSpec`, and the `CircuitArtifact` that holds a circuit twice — as a flat constraint
list and as layered gates — with the laws tying the two together, the cache-free
compilation, the gate catalogue and the `postcard` wire form.

Nothing here evaluates a gate. The kernel is `gkr_verify::eval_gate`, and it is the
semantic authority; this crate owns the formula *representation* and the checks made
when a circuit is built. **`docs/spec/gkr.md` §1–§4 is normative.**
`docs/spec/constraint-manifest.md` is the readable account of every circuit
`family_circuit` returns — each column, inner layer, gate and lookup by position, name and
formula — and a change to a family's circuit updates its entry there.

```rust
pub enum VirtualKind { RowIndex, RamLive, Range19, Range16 }
pub enum PolyAddress { Memory(u32), Witness(u32), Setup(u32), Virtual(VirtualKind),
                       Inner { layer, offset }, Scratch(u32), Cached { layer, offset } }  // + Display
pub enum Coeff { Literal(Fr), Challenge(u32) }
pub enum GateDef { Linear, Product, MaskIntoIdentity, AffineProduct, TreeProduct, Quadratic, TreeCross }
impl GateDef { pub fn operands(&self) -> Vec<PolyAddress>; pub fn coefficients(&self) -> Vec<Coeff>; }
pub struct CatalogueEntry { variant, defined_in, evaluated_in, inputs, output, template, purpose }
pub const CATALOGUE: [CatalogueEntry; 7];
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

pub mod lookup {                                   // docs/spec/lookup.md
    pub struct ChannelSpec { pub channel: u32, pub table: Vec<PolyAddress>, pub multiplicity: PolyAddress }
    pub fn beta_power(j: usize) -> Coeff;           // the literal 1 at j = 0, a derived slot above
    pub fn range_table(channel: u32) -> Option<VirtualKind>;
    pub fn row_denominator(l: &LookupExpr) -> GateDef;      // E_l + g, one Quadratic
    pub fn table_denominator(spec: &ChannelSpec) -> GateDef; // T + g, one Linear
    pub fn check_discharge(a: &CircuitArtifact, specs: &[ChannelSpec]) -> Result<(), String>;
    pub fn check_copowers(a: &CircuitArtifact, scaled: &[PolyAddress]) -> Result<(), String>;
}

pub mod memory {                                   // docs/spec/memory.md §2, §3.3, §7, §8
    pub const CYCLE: PolyAddress;                  // M[0]
    pub const FIELD_MASK: u32 = 0;  FIELD_ADDR = 1;  FIELD_READ_TS = 2;  FIELD_READ_VALUE = 3;  FIELD_WRITE_VALUE = 4;
    pub const FRAME_QUERIES: usize = 8;            // the QUERY TABLE's size, never a frame's width
    pub const FRAME_NAMES: [&str; 8];              // pc rs1 rs2 arg1 arg2 load ram rd
    pub const FRAME_SPACE: [u8; 8];                // PC REG REG REG REG RAM RAM REG
    pub const FRAME_DELTA: [u64; 8];               // 0 1 2 2 2 2 3 3
    pub const PC: usize = 0;  RS1 = 1;  RS2 = 2;  ARG1 = 3;  ARG2 = 4;  LOAD = 5;  RAM = 6;  RD = 7;
    pub const FRAME_READ_ONLY: [usize; 5];         // RS1 RS2 ARG1 ARG2 LOAD, the write-back queries
    pub fn frame_queries(family: u32) -> &'static [usize];   // the frozen per-family subset
    pub fn frame(slot: usize, field: u32) -> PolyAddress;            // M[1 + 5·slot + field]
    pub fn gap_hi(slot: usize) -> PolyAddress;                       // W[slot]
    pub fn rd_inv(width: usize) -> PolyAddress;    // W[width]; rd_is_zero W[width+1], rd_selected W[width+2]
    pub fn read_tuple(query: usize) -> GateDef;    // unmasked, Linear, constant γ_M; term PART_* is that part
    pub fn frame_artifact(queries: &[usize], trace_vars: u32) -> CircuitArtifact;
    pub fn family_frame_artifact(family: u32, trace_vars: u32) -> CircuitArtifact;
    pub struct Extras { pub witness: Vec<String>, pub setup: Vec<String>,
                        pub virtuals: Vec<(VirtualKind, String)>,
                        pub enforcing: Vec<(String, GateDef)>, pub lookups: Vec<LookupExpr>,
                        pub channels: Vec<lookup::ChannelSpec> }                  // + Default
    pub fn frame_with_channels_artifact(queries: &[usize], trace_vars: u32, extras: Extras)
        -> CircuitArtifact;      // S16's shape; panics on an empty extras.channels
    pub fn image_window_artifact(trace_vars: u32) -> CircuitArtifact;  // INIT_TEARDOWN
    pub fn zero_window_artifact(trace_vars: u32) -> CircuitArtifact;   // ZERO_WINDOWS
    pub fn check_memory(a: &CircuitArtifact) -> Result<(), String>;
}

pub struct FamilyCircuit { pub family: u32, pub artifact: CircuitArtifact,
                           pub channels: Vec<lookup::ChannelSpec> }
impl FamilyCircuit { pub fn reads_generic_table(&self) -> bool; }   // S17: a GENERIC channel spec
pub fn family_circuit(family: u32, trace_vars: u32) -> Option<FamilyCircuit>;   // the registry

pub mod gadgets {                                  // docs/spec/jump-branch-slt.md §3; S17
    pub fn is_zero(x: &[(Coeff, PolyAddress)], inv: PolyAddress, z: PolyAddress,
                   enable: PolyAddress) -> [GateDef; 2];   // x·inv + z − enable, z·x
    pub struct Comparison { pub prefix: String, pub selector: PolyAddress, pub signed: Vec<PolyAddress>,
                            pub lhs, pub lhs_hi, pub lhs_sign, pub rhs, pub rhs_hi, pub rhs_sign,
                            pub lt, pub gap, pub gap_hi: PolyAddress }
    pub fn comparison_equation(c: &Comparison, word_bits: u32) -> GateDef;
    pub fn comparison(c: &Comparison) -> (Vec<(String, GateDef)>, Vec<LookupExpr>);
}

pub mod jump_branch_slt {                          // docs/spec/jump-branch-slt.md; S17
    pub const DECODED: [PolyAddress; 6];           // W[7..13]: next_pc rs1 rs2 rd imm mask
    pub const KINDS: [PolyAddress; 12];            // W[13..25]: extra_mask::jump_branch_slt order
    pub const CMP_RHS: PolyAddress;  RS1_HI;  RS1_SIGN;  CMP_RHS_HI;  CMP_RHS_SIGN;  LT;
    pub const CMP_GAP: PolyAddress;  CMP_GAP_HI;  EQ;  EQ_INV;  TAKEN;  JALR_DROP;  PC_WRAP;
    pub const NEXT_PC_HI: PolyAddress;  RD_HI;     // W[25..40]
    pub const MULTIPLICITIES: [PolyAddress; 4];    // W[40..44]: timestamp, range16, generic, decoder
    pub const TABLE_WIDTH: usize = 7;              // S[0..7]
    pub const GENERIC_TABLE: [PolyAddress; 3];     // S[7..10]
    pub const LEGAL_MASKS: [u32; 12];              // the twelve one-bit masks
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}

pub mod add_sub {                                  // docs/spec/shard-proof.md §8
    pub const DECODED: [PolyAddress; 6];           // W[10..16]: next_pc rs1 rs2 rd imm mask
    pub const KINDS: [PolyAddress; 6];             // W[16..22]: system addi auipc add sub lui
    pub const IS_ECALL: PolyAddress;  IS_FENCE;  WRAP;  RD_HI;  PC_WRAP;  NEXT_PC_HI;   // W[22..28]
    pub const MULTIPLICITIES: [PolyAddress; 3];    // W[28..31]: timestamp, range16, decoder
    pub const TABLE_WIDTH: usize = 7;              // S[0..7], program::lookup_tuple order
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}
```

## Frozen invariants
- **`PolyAddress` is the only way a polynomial is named**, and where each variant may
  appear is fixed: `M W S V` in gate list 0, `L{k}` in list `k`, `C{k}` in list `k`, never
  `scratch` in a gate; `M W S V scratch` in a relation, never `L` or `C`. The committed
  subtrees are split by role in the type: `M` memory-argument-tied, `W` not, `S` setup.
- **`GateDef` is closed.** Seven shapes, wire tags 0–6, append-only. A later stage adds a
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
- **A halving list halves every column of its layer**: it writes as many columns as it
  reads, and every entry is a halving shape — `TreeProduct`, one level of a product tree,
  or `TreeCross`, the numerator of one level of a fraction tree. Since S15 an entry may
  read a column other than its own, which is what lets a numerator read its denominator.
- **Four virtual kinds, append-only**: `RowIndex` (`V[row]`, tag 0), `RamLive`
  (`V[ram_live]`, tag 1, `docs/spec/gkr.md` §2.1) and S15's range tables `Range19` (tag 2)
  and `Range16` (tag 3), each the low `BITS` bits of the row index
  (`docs/spec/lookup.md` §3). Their closed forms are `gkr-verify`'s.
- **A lookup is a channel, a selector and a tuple** (`docs/spec/memory.md` §7,
  `docs/spec/lookup.md`): a channel of `constants::lookup_channel`; one `Linear`
  expression on a range channel and 1 to `MAX_TUPLE` on a table one, every lookup of a
  channel the same width since one channel has one table; literal coefficients over
  `M W S V`; an `M`, `W` or `S` selector **that gate list 0 holds to booleanity**, without
  which LogUp and the native reading of an obligation are different statements.
  `validate` refuses anything else, naming the lookup.
- **`lookup` is the LogUp channels as data, and `docs/spec/lookup.md` is normative for
  it**: the three gating conventions, the denominator gates, the fraction tree's leaves,
  the construction rules and the copower assertion. `check_discharge` holds every lookup
  to exactly one gate-list-0 denominator, and every channel to exactly one
  `(−mult, T + g)` table fraction, by normalized expansion, and counts both **per
  channel** — inside the cone below that channel's own root pair. The two range channels
  gate identically, so one lookup's denominator gate can be another channel's leaf byte
  for byte; and a table fraction matched over the whole gate list would let two channels
  hold each other's. `checker` enforces the lookup half by evaluation at pseudo-random
  points, and the table half through `check_channel_roots` once the columns exist. A frame with no channel is S14's `frame_artifact` alone —
  `frame_with_channels_artifact` refuses an empty channel list, so the shape with every
  obligation undischarged is not one the rule can be skipped for.
- **One assembly for every circuit**, `build`: a set of product and fraction trees whose
  leaves gate list 0 writes, reduced row-wise until each is one node — a tree that
  finishes early copies itself up — then `trace_vars` halving lists to a zero-variable
  top. The output map is the memory roots, then each channel's `(num, den)` pair in
  channel order.
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
  `kat-gen` writes the constructors' bytes. One exception since S17: the x0 rule's first
  two gates come from `gadgets::is_zero`, with their bytes unchanged.
- **One tuple gate for circuits and boundary.** `read_tuple(q)` and the private write tuple
  are the *unmasked* tuple, a `Linear` whose `AS` and `Δ` terms sit on the mask column; with
  mask 1 each is exactly `T`. One private constructor writes both, each part's terms in slot
  `constants::memory::PART_*`, so the read tuple's term `PART_*` is that part and
  `gkr_verify::boundary_factors` places its operand values by the same constants. The
  private `leaf` turns a tuple into the flat `Quadratic` of §2.2 and §3.3 by rule, so the
  window leaves and the frame leaves are one construction. The gadgets' constructors are
  private too: nothing outside this file builds a gate from them.
- **A memory artifact is built by one private assembly** from complete vectors: leaves, row-wise
  `Product` lists to `[read, write]`, `trace_vars` halving lists, outputs at `READ_ROOT` and
  `WRITE_ROOT` named `read_root` and `write_root`, relations and scratch mirroring every gate,
  an all-zero padding row with `zero_row_valid` decided from the enforcing gates. It asserts
  two gap obligations per read before anything else (S14 must-be-exact 5), then runs
  `validate` and `check_memory`, and panics on any refusal: a memory artifact that exists
  has passed both.
- **`check_memory` is §8, beside `validate`, sharing no code with it**: forward provenance
  (a global slot and a `W` column in one cone), a root whose cone reads a `W` column at all,
  a global slot over anything but `M`, `S`, `V`, and a leaf mask that is committed without
  its booleanity gate in list 0 or virtual but not `V[ram_live]`. It assumes an artifact that
  passed `validate`.
- **`family_circuit` is the one registry of circuits** (`docs/spec/shard-proof.md` §11).
  A verifying key's circuits are byte for byte what it returns for the key's families and
  heights, so a circuit is a protocol constant given a family and a height; a later family
  is one arm here and one fill in `crates/prover`. It returns `None` for a family no stage
  has built, above `MAX_TRACE_VARS`, and for `ADD_SUB_LUI_AUIPC` and `JUMP_BRANCH_SLT`
  below 19 variables, the timestamp channel's bound. The two window families have no
  channels.
- **A circuit that reads the `GENERIC` channel names the packed table as its last three
  setup columns** (S17). `FamilyCircuit::reads_generic_table` is whether any channel spec
  is `GENERIC`. At S17 only `JUMP_BRANCH_SLT` reads it: its `S[0..7]` are identity's
  decoded table, and its `S[7..10]` (`jump_branch_slt::GENERIC_TABLE`) are the packed
  table. A shard of such a family opens those three columns against the verifying key's
  one `generic_table`, which the key's SRS digest covers and identity does not;
  `VerifyingKey::check` holds a registered circuit to this order
  (`docs/spec/shard-proof.md` §7.2).
- **`add_sub` is §8 as data**, S15's `frame_with_channels_artifact` over the family's seven
  frame queries plus 21 witness columns, the 7-column decoded table as `S`, 31 enforcing
  gates, five lookups and three channels. Its gates are the family's whole semantics:
  one-hot kinds and the packed mask the table's domain; each query's mask the row kind's
  use of it times `m_pc`; each written value the kind's arithmetic with a boolean carry
  and a 16+16-bit range split; `ecall` only as `exit` (`a7 = 93`), its status `a0`, its
  `next_pc` `HALT_PC`; every other row's `next_pc` the decoded fall-through, with a
  boolean `pc_wrap`. A `const` assertion pins `system_code::ECALL == 0`, so a renumbering
  fails the build, and `artifact` asserts each channel's obligation count — 14, 4, 1 —
  when it builds the circuit, so a dropped obligation panics at construction.
- **`jump_branch_slt` is `docs/spec/jump-branch-slt.md` as data** (S17): the four-query
  frame plus 37 witness columns, S11's seven-column decoded table and the packed generic
  table as `S`, 42 enforcing gates, 22 lookups and four channels. Its semantics are linear
  forms over twelve one-hot kind bits read from S11's unchanged table; one comparison
  (`gadgets::comparison`) feeds both the branches and the `slt` kinds; `eq` is
  `gadgets::is_zero` enabled by `m_pc`; `taken` is a committed bit; `next_pc` carries one
  ungated wrap and a `jalr` dropped bit, and every `next_pc` is range-checked **even**, so no
  row of the family writes `HALT_PC`. `artifact` asserts each channel's obligation count —
  8, 11, 2, 1 — and runs `lookup::check_copowers` over `next_pc`, whose evenness obligation
  halves it.
- **`gadgets` is S17's pair of reusable constructors, frozen for S18 and S19.** `is_zero`
  is `x·inv + z − enable = 0, z·x = 0`, and S14's x0 rule is built on it with its bytes
  unchanged (the frame fixtures hold that); `comparison` is the ungated degree-2 ordering
  equation, `lt`'s booleanity, three 16+16 range pairs and two `U16GetSign` lookups, and
  `comparison_equation` exposes the equation at any width so the exhaustive reduced-width
  check evaluates the gate itself.
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

`tests/vectors/memory_frame_{alu,reg,mem,atomics}.bin`, `image_window.bin` and
`zero_window.bin`: the `memory` constructors at `trace_vars` 22. One frame fixture per
*distinct* frame — families sharing a query list share their artifact byte for byte, so
`reg` is `JUMP_BRANCH_SLT`, `SHIFT_BITWISE` and `MUL_DIV`, and `mem` is `MEM_WORD` and
`MEM_SUBWORD` — with a test holding each of the seven execution families to one of the
four files, so four fixtures pin all seven. `cargo run -p kat-gen -- memory` rewrites
them, CI regenerates and diffs them, and `tests/memory.rs` pins their SHA-256 and holds
each to its constructor's bytes. The leaves' independent description is the plain
arithmetic of `crates/gkr/tests/memory.rs`.

`tests/vectors/add_sub.bin` and `tests/vectors/jump_branch_slt.bin`: S16's
`add_sub::artifact` and S17's `jump_branch_slt::artifact`, each at `trace_vars` 22, the
family's default height. `cargo run -p kat-gen -- family` rewrites both, kat-gen's own unit
test holds each to its constructor, CI regenerates and diffs them, and
`crates/checker/tests/add_sub.rs` and `jump_branch_slt.rs` pin their SHA-256 and hold their
gates to `docs/spec/shard-proof.md` §8 and `docs/spec/jump-branch-slt.md`.

## Tests
| File | Covers |
| --- | --- |
| `tests/wire.rs` | both fixtures round-trip byte for byte; a format version other than 1 refused before decoding; `VirtualKind`'s tags and `V[ram_live]`'s address and name; a lookup against its hand-written bytes; `Quadratic` against its hand-written bytes for no terms, linear only, products only and both, and each malformed `Quadratic` refused; every refusal of the reader; every single-bit flip of a fixture decodes or errors, never panics |
| `tests/laws.rs` | one mutation of the toy per rule, each refused with its error — structured variants matched whole, prose details by the rule and the address or name they carry — beside the toy validating; each lookup rule broken alone, refused naming the lookup, beside one and two lawful lookups and an `M` selector; the degree-3 gate; `Quadratic`'s degree, its identically zero and unread-column cases, Law 4 against an `AffineProduct` relation, and its refusal to inline; cache-free inlining and its refusals |
| `tests/memory.rs` | the three fixtures pinned and equal to their constructors; every constructor validating and passing `check_memory` at 12 and 22; two roots named `read_root`, `write_root`, an all-zero padding row, `trace_vars` halving lists; every read tuple's parts at their `PART_*` positions; the frame's layout, leaf order, widths and enforcing gates by name; its 16 obligations whole, `gap_lo_pc`'s constant `−1`; acceptance 11 exhaustively at reduced width, 5-bit chunks over a 10-bit clock, each query's own `gap_lo` expression read from the frame with its high chunk at 0, every `(cycle, read_ts)` pair admitted exactly when `read_ts < 4·cycle + Δ`; §8's pinned read sets; `check_memory` refusing a leaf fed from `W` (acceptance 9); the forward-provenance counterexample as a producing and as an enforcing gate of list 1, each beside its lawful control; a slot and a `W` column meeting through two cached entries, a cached entry itself carrying both, and a slot over a cached entry; a frame without `pc_mask_boolean` and one without `rd_mask_boolean`, whose mask another gate still reads; a window leaf masked by `S[0]` and by `V[row]`; a global slot over an inner column; and a write root read from a `W` column alone, which provenance does not see — each mutant still passing `validate`, each test run against the mutant it names |
| `src/gadgets.rs` (unit) | two range halfwords are the comparison's 32-bit word; the comparison returns two gates and eight lookups, each sign lookup the generic table's width; the equation built at 1 and 32 bits and refused at 0 and 33; a `const` assertion holds `U16GetSign`'s keys above AND's |
| `src/jump_branch_slt.rs` (unit) | the legal masks are twelve distinct single bits; through the private `assemble` seam, the honest extras give `artifact`, and the build is refused for an obligation dropped (the channel count), for `next_pc`'s direct bound replaced (the copower check) and for a gate nonzero on the all-zero row |
| `src/add_sub.rs` (unit) | the three system codes pairwise distinct, which is what lets `system_split`, `ecall_code` and `fence_code` refuse every `ebreak` row; the gates themselves are `crates/checker/tests/add_sub.rs`' |
| `src/memory.rs` (unit) | acceptance 12: the frame with one obligation dropped before the artifact is written panics at the count assertion |
| `tests/audit.rs` | every `GateDef` variant, all six, emitted across both compilations, counts written by hand; the catalogue; the two compilations' identical shape |
