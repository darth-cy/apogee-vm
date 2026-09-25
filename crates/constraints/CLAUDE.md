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
    pub fn check_copowers(a: &CircuitArtifact, scaled: &[(PolyAddress, PolyAddress)])
        -> Result<(), String>;   // (column, the selector its scaled obligation carries); S18
}

pub mod memory {                                   // docs/spec/memory.md §2, §3.3, §7, §8
    pub const CYCLE: PolyAddress;                  // M[0]
    pub const FIELD_MASK: u32 = 0;  FIELD_ADDR = 1;  FIELD_READ_TS = 2;  FIELD_READ_VALUE = 3;  FIELD_WRITE_VALUE = 4;
    pub const FRAME_QUERIES: usize = 9;            // the QUERY TABLE's size, never a frame's width
    pub const FRAME_NAMES: [&str; 9];              // pc rs1 rs2 arg1 arg2 load ram rd deleg
    pub const FRAME_SPACE: [u8; 9];                // PC REG REG REG REG RAM RAM REG DELEGATION_KECCAK_F
                                                   // LOAD's and DELEG's entries are defaults: both
                                                   // name their space per row, below
    pub const FRAME_DELTA: [u64; 9];               // 0 1 2 2 2 2 3 3 3
    pub const PC: usize = 0;  RS1 = 1;  RS2 = 2;  ARG1 = 3;  ARG2 = 4;  LOAD = 5;  RAM = 6;  RD = 7;  DELEG = 8;
    pub const FRAME_READ_ONLY: [usize; 5];         // RS1 RS2 ARG1 ARG2 LOAD, the write-back queries
    pub fn frame_queries(family: u32) -> &'static [usize];   // the frozen per-family subset
    pub fn frame_query_takes(q: usize, space: u8, delta: u64) -> bool;   // THE routing rule
    pub fn frame(slot: usize, field: u32) -> PolyAddress;            // M[1 + 5·slot + field]
    pub fn deleg_space(width: usize) -> PolyAddress;                 // M[1 + 5w]: the requested type
    pub fn load_space(width: usize) -> PolyAddress;                  // M[1 + 5w]: RAM or ADVICE; S25b
    pub fn gap_hi(slot: usize) -> PolyAddress;                       // W[slot]
    pub fn rd_inv(width: usize) -> PolyAddress;    // W[width]; rd_is_zero W[width+1], rd_selected W[width+2]
    pub fn read_tuple(query: usize) -> GateDef;    // unmasked, Linear, constant γ_M; term PART_* is that part
    pub fn frame_artifact(queries: &[usize], trace_vars: u32) -> CircuitArtifact;
    pub fn family_frame_artifact(family: u32, trace_vars: u32) -> CircuitArtifact;
    pub struct FamilySpec { pub witness: Vec<String>, pub setup: Vec<String>,
                            pub virtuals: Vec<(VirtualKind, String)>,
                            pub enforcing: Vec<(String, GateDef)>, pub lookups: Vec<LookupExpr>,
                            pub channels: Vec<lookup::ChannelSpec> }              // + Default
    pub fn frame_with_channels_artifact(queries: &[usize], trace_vars: u32, family_spec: FamilySpec)
        -> CircuitArtifact;      // S16's shape; panics on an empty family_spec.channels
    pub fn image_window_artifact(trace_vars: u32) -> CircuitArtifact;  // INIT_TEARDOWN
    pub fn zero_window_artifact(trace_vars: u32) -> CircuitArtifact;   // ZERO_WINDOWS
    pub fn advice_window_artifact(trace_vars: u32) -> CircuitArtifact; // ADVICE_WINDOWS; S25b
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

pub mod shift_bitwise {                            // docs/spec/shift-bitwise.md; S18
    pub const DECODED: [PolyAddress; 6];           // W[7..13]: next_pc rs1 rs2 rd imm mask
    pub const KINDS: [PolyAddress; 12];            // W[13..25]: extra_mask::shift_bitwise order
    pub const F_SHIFT: PolyAddress;  F_BITWISE;    // W[25..27]: the two halves, each a lookup selector
    pub const RS1_HI: PolyAddress;  RS1_SIGN;  SRC2_HI;  AMOUNT;  POW;  COPOW;  HIGH;  HIGH_HI;
    pub const SE: PolyAddress;  SHIFT_IN;  SHIFT_PROD;  OVF;  OVF_HI;  RESIDUE;  RESIDUE_HI;
    pub const SCALED: PolyAddress;  SCALED_HI;     // W[27..44]
    pub const BYTES_A: [PolyAddress; 4];  BYTES_B;  BYTES_AND;   // W[44..56]
    pub const RD_HI: PolyAddress;                  // W[56]
    pub const MULTIPLICITIES: [PolyAddress; 4];    // W[57..61]: timestamp, range16, generic, decoder
    pub const TABLE_WIDTH: usize = 7;              // S[0..7]
    pub const GENERIC_TABLE: [PolyAddress; 3];     // S[7..10]
    pub const LEGAL_MASKS: [u32; 12];              // the twelve one-bit masks
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}

pub mod mul_div {                                  // docs/spec/mul-div.md; S18
    pub const WORD_BITS: u32 = 32;
    pub const DECODED: [PolyAddress; 5];           // W[7..12]: next_pc rs1 rs2 rd mask -- NO imm
    pub const KINDS: [PolyAddress; 8];             // W[12..20]: extra_mask::mul_div order
    pub const F_DIV: PolyAddress;                  // W[20]: the is-zero gadgets' enable
    pub const RS1_HI: PolyAddress;  RS1_TOP;  RS2_HI;  RS2_TOP;  S1;  S2;   // W[21..27]
    pub const MX: PolyAddress;  MY;  P_LOW;  P_LOW_HI;  P_HIGH;  P_HIGH_HI;  P_SIGN;  // W[27..34]
    pub const Q: PolyAddress;  Q_HI;  Q_SIGN;  R;  R_HI;  R_SIGN;           // W[34..40]
    pub const R_INV: PolyAddress;  RZ;  D1;  D_INV;  DZ;                    // W[40..45]
    pub const ABS_R: PolyAddress;  ABS_D;  GAP;  GAP_HI;  RD_HI;            // W[45..50]
    pub const MULTIPLICITIES: [PolyAddress; 4];    // W[50..54]
    pub const TABLE_WIDTH: usize = 6;              // S[0..6] -- six, the tuple having no imm
    pub const GENERIC_TABLE: [PolyAddress; 3];     // S[6..9]
    pub const LEGAL_MASKS: [u32; 8];
    pub fn arithmetic_gates(word_bits: u32) -> Vec<(String, GateDef)>;   // the width seam
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}

pub mod mem_word {                                 // docs/spec/memory-ops.md §3; S19
    pub const DECODED: [PolyAddress; 6];           // W[9..15]: next_pc rs1 rs2 rd imm mask
    pub const KINDS: [PolyAddress; 2];             // W[15..17]: extra_mask::mem_word order
    pub const WRAP: PolyAddress;  WORD_INDEX;  WORD_INDEX_HI;  RD_HI;      // W[17..21]
    pub const IS_ADVICE: PolyAddress;  WORD_INDEX_HI_REST;                 // W[21..23]; S25b
    pub const MULTIPLICITIES: [PolyAddress; 3];    // W[23..26]: timestamp, range16, decoder
    pub const TABLE_WIDTH: usize = 7;              // S[0..7]; NO generic table
    pub const LEGAL_MASKS: [u32; 2];
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}

pub mod mem_subword {                              // docs/spec/memory-ops.md §4; S19
    pub const BYTE_BITS: u32 = 8;                  // the one place a byte's width is written
    pub const DECODED: [PolyAddress; 6];           // W[9..15]
    pub const KINDS: [PolyAddress; 6];             // W[15..21]: extra_mask::mem_subword order
    pub const WRAP: PolyAddress;  WORD_INDEX;  WORD_INDEX_HI;  BIT0;  BIT1;    // W[21..26]
    pub const P: PolyAddress;  PCOPOW;  WPH;  P_RAM;  WORD;                    // W[26..31]
    pub const HIGH: PolyAddress;  HIGH_HI;  HIGH_SCALED;  HIGH_SCALED_HI;      // W[31..35]
    pub const SUB: PolyAddress;  SUB_SCALED;  SUB_SCALED_HI;                   // W[35..38]
    pub const LOW: PolyAddress;  LOW_HI;  LOW_SCALED;  LOW_SCALED_HI;          // W[38..42]
    pub const SRC_SUB: PolyAddress;  SRC_SUB_SCALED;  SRC_SUB_SCALED_HI;
    pub const SRC_HIGH: PolyAddress;  SRC_HIGH_HI;                             // W[42..47]
    pub const SIGN_IN: PolyAddress;  SIGN;  SE;  RD_HI;                        // W[47..51]
    pub const IS_ADVICE: PolyAddress;  WORD_INDEX_HI_REST;                     // W[51..53]; S25b
    pub const MULTIPLICITIES: [PolyAddress; 4];    // W[53..57]
    pub const TABLE_WIDTH: usize = 7;              // S[0..7]
    pub const GENERIC_TABLE: [PolyAddress; 3];     // S[7..10]
    pub const LEGAL_MASKS: [u32; 6];
    pub fn splice_gates(byte_bits: u32) -> Vec<(String, GateDef)>;   // the width seam
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}

pub mod atomics {                                  // docs/spec/memory-ops.md §6; S19
    pub const DECODED: [PolyAddress; 5];           // W[8..13]: next_pc rs1 rs2 rd mask -- NO imm
    pub const KINDS: [PolyAddress; 11];            // W[13..24]: extra_mask::atomics order
    pub const WORD_INDEX: PolyAddress;  WORD_INDEX_HI;                         // W[24..26]
    pub const SUM: PolyAddress;  SUM_HI;  ADD_WRAP;  F_BITWISE;                // W[26..30]
    pub const BYTES_A: [PolyAddress; 4];  BYTES_B;  BYTES_AND;                 // W[30..42]
    pub const OLD_HI: PolyAddress;  OLD_SIGN;  SRC_HI;  SRC_SIGN;  LT;
    pub const CMP_GAP: PolyAddress;  CMP_GAP_HI;  LO;                          // W[42..50]
    pub const MULTIPLICITIES: [PolyAddress; 4];    // W[50..54]
    pub const TABLE_WIDTH: usize = 6;              // S[0..6] -- six, the tuple having no imm
    pub const GENERIC_TABLE: [PolyAddress; 3];     // S[6..9]
    pub const LEGAL_MASKS: [u32; 11];
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}

pub mod add_sub {                                  // docs/spec/shard-proof.md §8
    pub const DECODED: [PolyAddress; 6];           // W[11..17]: next_pc rs1 rs2 rd imm mask
    pub const KINDS: [PolyAddress; 6];             // W[17..23]: system addi auipc add sub lui
    pub const IS_ECALL: PolyAddress;  IS_FENCE;                                // W[23..25]
    pub const IS_DELEGATION: [PolyAddress; 3];     // W[25..28]; IS_KECCAK is IS_DELEGATION[0]
    pub const IS_READ: PolyAddress;  IS_WRITE;                                 // W[28..30]; S25
    pub const FD_UNCOMMITTED: PolyAddress;  RAM_VALUE_HI;                      // W[30..32]; S25a
    pub const WRAP: PolyAddress;  RD_HI;  PC_WRAP;  NEXT_PC_HI;                // W[32..36]
    pub const MULTIPLICITIES: [PolyAddress; 3];    // W[36..39]: timestamp, range16, decoder
    pub const TABLE_WIDTH: usize = 7;              // S[0..7], program::lookup_tuple order
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}

pub mod keccak {                                   // docs/spec/delegation.md §6; S21
    pub const CYCLE: PolyAddress;  LIVE;  BASE;  ANCHOR_VALUE;                 // M[0..4]
    pub fn word(j: usize, field: u32) -> PolyAddress;        // M[4 + 4j + f], j < 50
    pub const WORD_ADDR: u32 = 0;  WORD_READ_TS;  WORD_READ_VALUE;  WORD_WRITE_VALUE;
    pub fn in_bit(b: usize) -> PolyAddress;                  // W[0..1600]
    pub fn gap_bit(j: usize, bit: usize) -> PolyAddress;     // W[1600..3500], 38 a word
    pub fn base_low_bit(bit: usize) -> PolyAddress;          // W[3500..3529]
    pub fn base_room_bit(bit: usize) -> PolyAddress;         // W[3529..3560]
    pub const MEMORY_COLUMNS: usize = 204;  WITNESS_COLUMNS: usize = 3560;
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;           // EMPTY
}

pub mod delegation {          // docs/spec/delegation.md §4 and §5; S23, shared by the two below
    pub const CYCLE: PolyAddress;  LIVE;  BASE;  ANCHOR_VALUE;                 // M[0..4]
    pub const WORD_ADDR: u32 = 0;  WORD_READ_TS;  WORD_READ_VALUE;  WORD_WRITE_VALUE;
    pub const HEAD_COLUMNS: usize = 4;  GAP_BITS: usize = 38;
    pub const BASE_LOW_BITS: usize = 29;  BASE_ROOM_BITS: usize = 31;
    pub const VALUE_BITS: usize = 256;  CANONICITY_BITS: usize = 264;  WORDS_PER_VALUE = 8;
    pub fn word(j: usize, field: u32) -> PolyAddress;        // M[4 + 4j + f]
    pub fn gap_bit(j, bit) -> PolyAddress;  base_low_bit(words, bit);  base_room_bit(words, bit);
    pub fn memory_names(words) -> Vec<String>;  witness_names(words);  frame_witness(words);
    pub fn leaves_a_side(words: usize) -> usize;
}

pub mod poseidon2 {                               // docs/spec/delegation.md §12; S23
    pub const CYCLE; LIVE; BASE; ANCHOR_VALUE; WORD_*;       // delegation's, re-exported
    pub fn word(j, field);  gap_bit(j, bit);  base_low_bit(bit);  base_room_bit(bit);
    pub fn value_bit(v, k, t);  diff_bit(v, k, t);  borrow_bit(v, k);   // v < 6: 3 in, 3 out
    pub const MEMORY_COLUMNS: usize = 100;  WITNESS_COLUMNS: usize = 4092;
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;           // EMPTY
}

pub mod fr_arith {                                // docs/spec/delegation.md §13; S23
    pub const CYCLE; LIVE; BASE; ANCHOR_VALUE; WORD_*;
    pub fn word(j, field);  gap_bit(j, bit);  base_low_bit(bit);  base_room_bit(bit);
    pub fn value_bit(v, k, t);  diff_bit(v, k, t);  borrow_bit(v, k);   // v < 3: a, b, out
    pub fn selector(i: usize);  prod();  inv();  is_zero();
    pub const MEMORY_COLUMNS: usize = 104;  WITNESS_COLUMNS: usize = 2576;
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;           // EMPTY
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
- **Two queries name their address space per row, and both do it through an `M` column.**
  `DELEG`'s is the delegation type (S21, `docs/spec/delegation.md` §5.1) and, since S25b,
  `LOAD`'s is `RAM` or `ADVICE` by the address (`docs/spec/advice.md` §3.2). For every
  other query the `AS` term is the literal `FRAME_SPACE[q]` times the mask and vanishes
  with it; for these two it is the frame's one extra column at coefficient 1, which is
  **0 on a row without the query** — the mask is inside the column instead. The reason is
  `check_memory`'s provenance rule: a leaf may read no `W` column, and the `is_advice` bit
  a family commits is one, so the tag crosses into the leaf through a memory column the
  family pins to that bit with a literal-coefficient gate. `deleg_space` and `load_space`
  are the **same slot**, `M[1 + 5w]`, and `frame_body` asserts no frame holds both queries:
  add/sub holds `deleg` and no `load`, the two memory families `load` and no `deleg`,
  `ATOMICS` neither. `frame_query_takes` is the routing rule both sides read — `DELEG`
  takes any of `address_space::DELEGATION`, `LOAD` takes `RAM` or `ADVICE`, and `RAM`, the
  store-and-atomic query, takes `RAM` alone, which is what makes advice read-only by frame
  construction rather than by a rule of its own.
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
- **`advice_window_artifact` is `zero_window_artifact`'s shape plus one free column**
  (S25b, `docs/spec/advice.md` §5): `M[0]` teardown ts, `M[1]` teardown value, `M[2]`
  **init value**, `V[row]`, no enforcing gate and no obligation. That third column is the
  whole family, and `M` is what it must be — `check_memory` refuses a `W` column in a leaf
  and `S` is what program identity commits, which is where the privacy would go, so
  `program::setup_commitments` returns an empty list for this family deliberately. Nothing
  outside the guest constrains an advice word: the prover picks it. What the circuit does
  give is *consistency* — only this family's init leaf writes a tuple stamped 0 in the
  advice space, so every read of an address chains back to one value — and §2 of that page
  is what the value itself is worth.
- **`family_circuit` is the one registry of circuits** (`docs/spec/shard-proof.md` §11).
  A verifying key's circuits are byte for byte what it returns for the key's families and
  heights, so a circuit is a protocol constant given a family and a height; a later family
  is one arm here and one fill in `crates/prover`. It returns `None` above
  `MAX_TRACE_VARS` and for **any of the seven execution families below 19 variables**, the
  timestamp channel's bound. The **three** window families have no channels and take any
  height. Since S19 it holds every family the master prompt names, and since S21 the ones
  it does not: `ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT`, `SHIFT_BITWISE`, `MUL_DIV`,
  `MEM_WORD`, `MEM_SUBWORD`, `ATOMICS`, the three windows — `INIT_TEARDOWN`,
  `ZERO_WINDOWS` and S25b's `ADVICE_WINDOWS` — and the three delegation families
  `KECCAK_F`, `POSEIDON2` and `FR_ARITH`. **The minimum-height guard must
  name every execution family**: `HEIGHT_MENU` legally holds `2^16` and `2^18`,
  `VerifyingKey::check` builds a circuit from a key's own `VmConfig`, and a family missing
  from the guard would reach `lookup::channel_trees`' `BITS <= trace_vars` assertion — a
  panic inside key validation, in a `no_std` crate the recursion guest links, on bytes a
  verifier was handed. **`KECCAK_F`'s arm sits below the guard, deliberately**: a family with
  no lookup channel reaches no such assertion, so there is nothing to pre-empt, and putting
  it in the guard would refuse the only height it has, `2^8`. That is why a delegation
  family **must** carry no channel (`docs/spec/lookup.md` §3). `ADVICE_WINDOWS`' arm sits
  outside the guard for the same reason and beside its two siblings: a window family has no
  channel either. It takes `INIT_TEARDOWN`'s height by **rule**:
  `verifier_core::window_height` binds all three window families to one number — the RAM
  pair because they tile one region between them, advice because its region's stride is
  read twice, by the window count and by the fill (`docs/spec/advice.md` §5.0).
- **A circuit that reads the `GENERIC` channel names the packed table as its last three
  setup columns** (S17). `FamilyCircuit::reads_generic_table` is whether any channel spec
  is `GENERIC`. At S17 only `JUMP_BRANCH_SLT` reads it: its `S[0..7]` are identity's
  decoded table, and its `S[7..10]` (`jump_branch_slt::GENERIC_TABLE`) are the packed
  table. A shard of such a family opens those three columns against the verifying key's
  one `generic_table`, which the key's SRS digest covers and identity does not;
  `VerifyingKey::check` holds a registered circuit to this order
  (`docs/spec/shard-proof.md` §7.2).
- **A family's sub-circuit is a `FamilySpec`, and a function that builds one is named
  `family_spec`** (the owner's naming, S17): the witness and setup columns, virtual
  tables, enforcing gates, lookups and channels a family adds beside its memory frame,
  collected once and handed to `frame_with_channels_artifact`. `add_sub` builds one
  inline, `jump_branch_slt` behind the private `family_spec` function its `assemble` seam
  takes; a later family names its own the same way. S15 called the type `Extras`.
- **`add_sub` is §8 as data**, S15's `frame_with_channels_artifact` over the family's **eight**
  frame queries plus 28 witness columns, the 7-column decoded table as `S`, 76 enforcing
  gates, 24 lookups and three channels. Its gates are the family's whole semantics:
  one-hot kinds and the packed mask the table's domain; each query's mask the row kind's
  use of it times `m_pc`; each written value the kind's arithmetic with a boolean carry
  and a 16+16-bit range split; every other row's `next_pc` the decoded fall-through, with a
  boolean `pc_wrap`. **Its ecall rows are a partition of five kinds** — the exit
  (`a7 = 93`, status `a0`, `next_pc = HALT_PC`), a request of each of the three registered
  delegation types, a `read` and a `write` — each a free boolean selector with three gates,
  and `is_exit` written out as the remainder. **S25a pinned what an I/O row may claim**:
  `read_descriptor` and `write_descriptor` hold the call's `a0` to its own pair of file
  descriptors through one shared boolean, `FD_UNCOMMITTED`;
  `write_count_is_the_request` holds a `write`'s answer to the count `a2` asked for; and the
  `read_count_gap_range` obligation bounds a `read`'s answer to `[0, READ_WORD_BYTES]`, the
  one number this family bounds rather than fixes (`docs/spec/ecall-abi.md` §4.1). A set of
  two descriptors is not an interval, which is why it is a committed boolean and not a range
  check: `is_read·fd·(fd − 3)` is degree 3 and `validate` refuses it.
  `const` assertions pin `system_code::ECALL == 0`, every provable ecall number pairwise
  distinct, and each descriptor pair ordered and distinct, so a renumbering fails the build;
  `artifact` asserts each channel's obligation count — 16, 7, 1 — when it builds the circuit,
  so a dropped obligation panics at construction. **The `RANGE16` tree has no pad left**:
  seven obligations and the table fraction fill its eight leaves exactly, so the next
  obligation this family takes costs a gate list.
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
- **`shift_bitwise` is `docs/spec/shift-bitwise.md` as data** (S18): the four-query frame
  plus 54 witness columns, S11's seven-column decoded table and the packed generic table as
  `S`, 48 enforcing gates, 39 lookups and four channels. **One merged family**, never split
  into shift and bitwise halves. Its semantics are linear forms over twelve one-hot kind
  bits — only `f_shift` and `f_bitwise` become columns, each being a lookup selector, which
  `validate` requires a booleanity gate for. One expression `rs2 + imm` is the second
  operand of all twelve, one addend always being zero. **One product serves both shift
  directions**: `shift_in` selects the multiplicand and `shift_prod = shift_in·pow` is
  ungated, which is what keeps the two arms degree 2. The residue bound is the copower
  pattern — `scaled = 2·residue·copow` range-checked, plus `residue`'s own direct pair,
  which `check_copowers` refuses the circuit without. XOR and OR are derived from the one
  AND accumulator, inlined as a linear form over the four `byte_and` columns; there is no
  XOR table and no OR table, and the `rd` term is gated by `f_bitwise`, not by the bracket.
  `artifact` asserts each channel's obligation count — 8, 24, 6, 1 — and runs
  `check_copowers` over all six scaled columns: `residue`, `amount` and the four byte
  keys, each under its own selector.
- **`mul_div` is `docs/spec/mul-div.md` as data** (S18): the four-query frame plus 47
  witness columns, S11's **six**-column decoded table — this family's tuple has no `imm` —
  and the packed generic table as `S`, 54 enforcing gates, 27 lookups and four channels.
  **One product identity serves all four multiplies and the division alike**: `mx` and `my`
  select the multiplicands, and `product_rule` is the only multiplication of two row values.
  The division identity is gated to division rows, and must be: an ungated one makes an
  ordinary `mul` of `−2^31` by `−1` unprovable. `r_sign` is *defined* as
  `f_div·s1·(1 − [r = 0])`, which is what separates truncated division from floored;
  `|rem| < |divisor|` is one range-checked gap carrying a `2^32·dz` correction, so a zero
  divisor imposes no bound; and `q_sign` is a **free** boolean pinned only by `q`'s range —
  tying it to bit 31 of `q` would make `−2^31 ÷ −1` unprovable. The signed overflow
  therefore needs no pin; div-by-zero needs one gate. `arithmetic_gates(word_bits)` is the
  width seam the exhaustive reduced-width check drives, as `comparison_equation` is at S17.
  `artifact` asserts each channel's obligation count — 8, 16, 2, 1.
- **`mem_word`, `mem_subword` and `atomics` are `docs/spec/memory-ops.md` as data** (S19),
  and **§2's addressing is shared by all three**: `addr = 4·word_index (+ 2·bit1 + bit0)`
  is an alignment check over the integers and nothing at all over `Fr`, so what makes the
  split base-4 is three `RANGE16` obligations on `word_index` — the direct pair and a
  scaled one, which caps `word_index` at `2^30 − 1` and is exactly tight at the top
  of the address space. Every RAM query's address is `4·word_index`, so a sub-word access,
  a word access and an atomic name one cell. `atomics` scales `word_index_hi` by 4 and
  passes `(word_index_hi, m_pc)` to `check_copowers`; **since S25b the two load-carrying
  families scale `word_index_hi_rest` by 8 and pass that instead**, the same obligation
  re-split about bit 13 (`docs/spec/advice.md` §3.1).
  - **The advice selector is four gates, and the two load-carrying families carry the same
    four** (S25b). `advice_split` is `word_index_hi − 2^13·is_advice − word_index_hi_rest
    = 0` with `is_advice_boolean` beside it, and `8·word_index_hi_rest < 2^16` bounds the
    remainder below `2^13`, so `is_advice` **is** the address's bit 31 in both directions:
    an advice address cannot be read as RAM and a RAM address cannot be read as advice.
    `load_space_rule` moves that bit into the frame's `load_space` column,
    `load_space − RAM·m_load − (ADVICE − RAM)·m_load·is_advice = 0`, and
    `no_store_to_advice` is `m_ram·is_advice = 0`, which refuses a store into the region
    **locally, as `Constraint`, naming the gate** where the multiset would refuse it
    globally and namelessly. The region starting at a power of two is what keeps all of
    this to one boolean and one re-split rather than a comparison gadget, a gap column and
    its obligation.
  - **`atomics` carries no advice gate of its own**, having no `load` query: an atomic's
    address rides the `ram` query, whose tag is the literal `RAM`, so an atomic on the
    advice range stages a RAM write at an address no RAM window initialized and the global
    multiset refuses it. The emulator refuses it fatally first.
  - **`mem_word`**: the six-query frame — 32 `M` columns since S25b, `1 + 5·6` plus the
    `load_space` one — and 17 witness columns, S11's seven-column decoded table as `S`,
    37 enforcing gates (the frame's 13 and this family's 24), 19 lookups and **three**
    channels — it reads
    no generic lookup, the second registered family after `ADD_SUB_LUI_AUIPC` with none,
    so `reads_generic_table` is false and its setup list is identity's alone. It carries no
    offset bits at all, which is what makes a misaligned `lw` or `sw` unrepresentable.
    `rd_selected` carries a 16+16 pair, which is what keeps every register value in the VM
    locally 32-bit (`memory-ops.md` §5.1).
  - **`mem_subword`**: the same frame plus 48 witness columns, the decoded table and the
    packed generic table as `S`, 57 enforcing gates (13 and 44), 37 lookups and four
    channels.
    **There is no `MemoryOffsetGetBits` table**: the splice power `p` and its halved
    copower are degree-2 gates over the address's own two offset bits (`p_rule`,
    `pcopow_rule`, `wph_rule`), which is the owner's decision at S19 and strictly stronger
    than the prompt's seven-row table — it adds no key to bound and does not move the
    packed table's commitments. `half_aligned` is load-bearing twice: it is the halfword
    alignment rule *and* what keeps `w·p` a divisor of `2^32`, on which §4.7's bound on
    what a store writes rests. `splice_gates(byte_bits)` is the width seam the exhaustive
    reduced-width check drives, as `mul_div::arithmetic_gates` is at S18. One `U16GetSign`
    lookup serves both widths because `sign_in` is `256·sub` on a byte row and `sub` on a
    halfword one, and its single `RANGE16` obligation is the exact key bound — the one
    place a bare obligation, not a pair, is right. `check_copowers` takes `high`, `sub`,
    `low` and `src_sub` beside `word_index_hi`.
  - **`atomics`**: the five-query frame — `pc rs1 rs2 ram rd`, with the RAM query and the
    `rd` query sharing Δ = 3 at distinct address spaces, the one family with two queries in
    one Δ slot — plus 46 witness columns, S11's **six**-column decoded table (no `imm`, so the
    packed table sits at `S[6..9]`) and 46 enforcing gates, 36 lookups and four channels.
    One `ram_value_rule` selects all eleven arms; `rd` takes the **old** word on every kind
    but `sc.w`, which always succeeds and writes 0 (a conformance deviation, `memory-ops.md`
    §6.6). OR and XOR are derived from the one AND accumulator, inlined as a linear form;
    `f_bitwise` is the **three** bitwise kinds, not `amoand` alone. `assemble` asserts the
    comparison gadget's four parameters — selector, `lhs`, `rhs` and `signed` — because each
    wrong choice is a silent, total break of the four min/max kinds and nothing else in the
    circuit would catch it. Every arm indexes `KINDS` through its `extra_mask` constant and
    never by position: the stage prompt lists `amoand` and `amoor` in the opposite order to
    `constants::extra_mask::atomics`.
- **`gadgets` is S17's pair of reusable constructors, frozen for S18 and S19.** `is_zero`
  is `x·inv + z − enable = 0, z·x = 0`, and S14's x0 rule is built on it with its bytes
  unchanged (the frame fixtures hold that); `comparison` is the ungated degree-2 ordering
  equation, `lt`'s booleanity, three 16+16 range pairs and two `U16GetSign` lookups, and
  `comparison_equation` exposes the equation at any width so the exhaustive reduced-width
  check evaluates the gate itself. S18 used `is_zero` twice, for `rem ≠ 0` and the
  zero-divisor test, and did **not** use `comparison`: its magnitude bound is a directly
  range-checked gap, which is where the zero-divisor correction lives and which the
  gadget's operand ranges and sign lookups would only duplicate (`docs/spec/mul-div.md`
  decision 1).
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

`tests/vectors/memory_frame_{alu,reg,mem,atomics}.bin`, `image_window.bin`,
`zero_window.bin` and, since S25b, `advice_window.bin`: the `memory` constructors at
`trace_vars` 22 — four distinct frames and three windows. One frame fixture per
*distinct* frame — families sharing a query list share their artifact byte for byte, so
`reg` is `JUMP_BRANCH_SLT`, `SHIFT_BITWISE` and `MUL_DIV`, and `mem` is `MEM_WORD` and
`MEM_SUBWORD` — with a test holding each of the seven execution families to one of the
four files, so four fixtures pin all seven. The `mem` frame's bytes moved at S25b, where
a load's frame gained its `load_space` column. `cargo run -p kat-gen -- memory` rewrites
them, CI regenerates and diffs them, and `tests/memory.rs` pins their SHA-256 and holds
each to its constructor's bytes. The leaves' independent description is the plain
arithmetic of `crates/gkr/tests/memory.rs`.

`tests/vectors/{keccak,poseidon2,fr_arith}.txt`: **digests, not artifacts.**
`keccak::artifact(8).to_bytes()` is 100,254,040 bytes — 974 times the largest committed
circuit — and the two S23 circuits are 2.1 MB and 1.1 MB, so what is committed is one line
apiece: the shape counts and the artifact's SHA-256. `cargo run -p kat-gen -- delegation`
writes them, kat-gen's own unit test holds each to its constructor, and CI regenerates and
diffs them like every other fixture. The owner chose the digest at S21 over committing the
bytes or committing nothing. Their readable accounts are
`docs/spec/constraint-manifest.md` §12, §13 and §14; there is
no `checker dump` of keccak's, because a 358,525-relation listing is not a readable account of
anything.

`tests/vectors/{add_sub,jump_branch_slt,shift_bitwise,mul_div}.bin`: one per registered
execution family — S16's `add_sub::artifact`, S17's `jump_branch_slt::artifact` and S18's
`shift_bitwise::artifact` and `mul_div::artifact` — each at `trace_vars` 22, the height the
first three default to. `cargo run -p kat-gen -- family` rewrites all four, kat-gen's own
unit test holds each to its constructor, CI regenerates and diffs them, and the matching
suite in `crates/checker/tests` pins each SHA-256 and holds its gates to
`docs/spec/shard-proof.md` §8, `docs/spec/jump-branch-slt.md`,
`docs/spec/shift-bitwise.md` and `docs/spec/mul-div.md`.

## Tests
| File | Covers |
| --- | --- |
| `tests/wire.rs` | both fixtures round-trip byte for byte; a format version other than 1 refused before decoding; `VirtualKind`'s tags and `V[ram_live]`'s address and name; a lookup against its hand-written bytes; `Quadratic` against its hand-written bytes for no terms, linear only, products only and both, and each malformed `Quadratic` refused; every refusal of the reader; every single-bit flip of a fixture decodes or errors, never panics |
| `tests/laws.rs` | one mutation of the toy per rule, each refused with its error — structured variants matched whole, prose details by the rule and the address or name they carry — beside the toy validating; each lookup rule broken alone, refused naming the lookup, beside one and two lawful lookups and an `M` selector; the degree-3 gate; `Quadratic`'s degree, its identically zero and unread-column cases, Law 4 against an `AffineProduct` relation, and its refusal to inline; cache-free inlining and its refusals |
| `tests/memory.rs` | every committed fixture pinned and equal to its constructor — the four frames and, since S25b, all **three** windows; every constructor validating and passing `check_memory` at 12 and 22; two roots named `read_root`, `write_root`, an all-zero padding row, `trace_vars` halving lists; every read tuple's parts at their `PART_*` positions; the frame's layout, leaf order, widths and enforcing gates by name; its 16 obligations whole, `gap_lo_pc`'s constant `−1`; acceptance 11 exhaustively at reduced width, 5-bit chunks over a 10-bit clock, each query's own `gap_lo` expression read from the frame with its high chunk at 0, every `(cycle, read_ts)` pair admitted exactly when `read_ts < 4·cycle + Δ`; §8's pinned read sets; `check_memory` refusing a leaf fed from `W` (acceptance 9); the forward-provenance counterexample as a producing and as an enforcing gate of list 1, each beside its lawful control; a slot and a `W` column meeting through two cached entries, a cached entry itself carrying both, and a slot over a cached entry; a frame without `pc_mask_boolean` and one without `rd_mask_boolean`, whose mask another gate still reads; a window leaf masked by `S[0]` and by `V[row]`; a global slot over an inner column; and a write root read from a `W` column alone, which provenance does not see — each mutant still passing `validate`, each test run against the mutant it names |
| `src/gadgets.rs` (unit) | two range halfwords are the comparison's 32-bit word; the comparison returns two gates and eight lookups, each sign lookup the generic table's width; the equation built at 1 and 32 bits and refused at 0 and 33; a `const` assertion holds `U16GetSign`'s keys above AND's |
| `src/shift_bitwise.rs` (unit) | the legal masks are twelve distinct single bits; the two halves and the two shift directions partition the kinds; and through the private `assemble` seam, the honest family spec gives `artifact`, and the build is refused for an obligation dropped, for `residue`'s direct pair moved under a narrower selector than its scaled obligation (S18's tightened copower check) and for a gate nonzero on the all-zero row |
| `src/mul_div.rs` (unit) | the legal masks are eight distinct single bits; the multiplies and the divisions partition the kinds; `arithmetic_gates` built at 1 and 32 bits and refused at 0 and 33; and through the `assemble` seam, the honest spec gives `artifact` and the build is refused for a dropped obligation and for a gate nonzero on the all-zero row |
| `src/jump_branch_slt.rs` (unit) | the legal masks are twelve distinct single bits; through the private `assemble` seam, the honest family spec gives `artifact`, and the build is refused for an obligation dropped (the channel count), for `next_pc`'s direct bound replaced (the copower check) and for a gate nonzero on the all-zero row |
| `src/add_sub.rs` (unit, and four `const` assertions) | the three system codes pairwise distinct, which is what lets `system_split`, `ecall_code` and `fence_code` refuse every `ebreak` row; and, since S21, `const _: () = assert!(..)` items holding the provable ecall numbers **pairwise** distinct and each in its ABI range, and every delegation type's address-space tag distinct too — what makes `ecall_is_exit` and the per-type number gates a partition rather than gates that can all hold. S23 made that loop over `constants::delegation::TYPES` rather than naming one number. A `const` assertion rather than a test, because a violation there is a mis-numbered ABI and should not compile. Neither gate spells a number: both read `constants::ecall`. The gates themselves are `crates/checker/tests/add_sub.rs`' |
| `src/poseidon2.rs`, `src/fr_arith.rs` (`check_shape`, run on every build) | the same discipline as `keccak`'s, over each circuit's own shape: the column counts, no setup column and **no channel**, every row-wise layer's width equal to its three regions' (poseidon2), the depth, the named relations present **by name**, and every counted family of gates counted on the emitted artifact. `fr_arith` additionally asserts that no relation's name contains `assume` |
| `src/keccak.rs` (`check_shape`, run on every build) | every row-wise layer's width equal to its three parts' — the offset helpers all index off that split, and a layer one column out would read a neighbour's with no other symptom; the column counts; no setup column and **no channel**; the depth; gate list 0's enforcing count; `base_aligned` and `base_in_window` present **by name**; and 50 each of `addr_w`, `gap_w`, `input_w` and `output_w`, counted on the emitted artifact. S21's must-be-exact 4: a bound that exists only in a comment is not a bound, and a name check is what an `assume_*` hypothesis cannot stand in for |
| `src/memory.rs` (unit) | acceptance 12: the frame with one obligation dropped before the artifact is written panics at the count assertion |
| `tests/audit.rs` | every `GateDef` variant, all six, emitted across both compilations, counts written by hand; the catalogue; the two compilations' identical shape |
