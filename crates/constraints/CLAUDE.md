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
pub enum VirtualKind { RowIndex, RamLive, Range19, Range16, Xor8A, Xor8B, Xor8Out }
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
    pub fn table_vars(channel: u32) -> u32;         // the variables a channel's table needs
    pub fn xor8_table() -> Vec<PolyAddress>;        // S26d: (a, b, a^b) as three closed forms
    pub fn row_denominator(l: &LookupExpr) -> GateDef;      // E_l + g, one Quadratic
    pub fn table_denominator(spec: &ChannelSpec) -> GateDef; // T + g, one Linear
    pub fn check_discharge(a: &CircuitArtifact, specs: &[ChannelSpec]) -> Result<(), String>;
    pub fn check_copowers(a: &CircuitArtifact, scaled: &[(PolyAddress, PolyAddress)])
        -> Result<(), String>;   // (column, the selector its scaled obligation carries); S18
}

pub mod memory {                                   // docs/spec/memory.md §2, §3.3, §7, §8
    pub const CYCLE: PolyAddress;                  // M[0]
    pub const FIELD_MASK: u32 = 0;  FIELD_ADDR = 1;  FIELD_READ_TS = 2;  FIELD_READ_VALUE = 3;  FIELD_WRITE_VALUE = 4;
    pub const FRAME_QUERIES: usize = 7;            // the QUERY TABLE's size, never a frame's width
    pub const FRAME_NAMES: [&str; 7];              // pc rs1 rs2 load ram rd deleg
    pub const FRAME_SPACE: [u8; 7];                // PC REG REG RAM RAM REG 0 — DELEG's space is the ROW's
    pub const FRAME_DELTA: [u64; 7];               // 0 1 2 2 3 3 3
    pub const PC: usize = 0;  RS1 = 1;  RS2 = 2;  LOAD = 3;  RAM = 4;  RD = 5;  DELEG = 6;
    pub const FRAME_READ_ONLY: [usize; 3];         // RS1 RS2 LOAD, the write-back queries
    pub fn frame_query_takes(q: usize, space: u8, delta: u64) -> bool;   // the one routing rule
    pub fn deleg_space(width: usize) -> PolyAddress;                     // M[1 + 5·width]
    pub fn frame_queries(family: u32) -> &'static [usize];   // the frozen per-family subset
    pub fn frame(slot: usize, field: u32) -> PolyAddress;            // M[1 + 5·slot + field]
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
    pub fn zero_window_artifact(trace_vars: u32) -> CircuitArtifact;   // ZERO_WINDOWS, and PUBLIC_OUTPUT
    pub fn value_window_artifact(trace_vars: u32) -> CircuitArtifact;  // PUBLIC_INPUT, ADVICE_WINDOWS; S-IO
    pub fn field_window_artifact(trace_vars: u32) -> CircuitArtifact;  // FIELD_WINDOWS, a cell a row; S-RECURSION
    pub fn check_memory(a: &CircuitArtifact) -> Result<(), String>;
}

pub struct FamilyCircuit { pub family: u32, pub artifact: CircuitArtifact,
                           pub channels: Vec<lookup::ChannelSpec> }
impl FamilyCircuit { pub fn reads_generic_table(&self) -> bool; }   // S17: a GENERIC channel spec
pub fn family_circuit(family: u32, trace_vars: u32) -> Option<FamilyCircuit>;      // the base format's registry
pub fn recursion_circuit(family: u32, trace_vars: u32) -> Option<FamilyCircuit>;   // S-RECURSION: the recursion format's

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
    pub const MULTIPLICITIES: [PolyAddress; 3];    // W[21..24]: timestamp, range16, decoder
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
    pub const MULTIPLICITIES: [PolyAddress; 4];    // W[51..55]
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

pub mod add_sub {                         // docs/spec/shard-proof.md §8; recursion.md §1.4
    pub const DECODED: [PolyAddress; 6];           // W[8..14]: next_pc rs1 rs2 rd imm mask
    pub const KINDS: [PolyAddress; 6];             // W[14..20]: system addi auipc add sub lui
    pub const IS_ECALL: PolyAddress;  IS_FENCE;                                // W[20..22]
    pub const fn is_delegation(i: usize) -> PolyAddress;   // W[22 + i]: delegation::TYPES[i]'s selector
    pub const fn wrap(types: usize);  rd_hi(types);  pc_wrap(types);  next_pc_hi(types);   // W[22+t..26+t]
    pub const fn multiplicities(types: usize) -> [PolyAddress; 3];   // W[26+t..29+t]: timestamp, range16, decoder
    pub const IS_DELEGATION: [PolyAddress; BASE_TYPES];  // W[22..28]; IS_KECCAK is IS_DELEGATION[0]
    pub const WRAP: PolyAddress;  RD_HI;  PC_WRAP;  NEXT_PC_HI;      // W[28..32], the base format's t = 6
    pub const MULTIPLICITIES: [PolyAddress; 3];    // W[32..35]
    pub const TABLE_WIDTH: usize = 7;              // S[0..7], program::lookup_tuple order
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;             // knows TYPES[..BASE_TYPES]
    pub fn channels() -> Vec<lookup::ChannelSpec>;
    pub fn recursion_artifact(trace_vars: u32) -> CircuitArtifact;   // S-RECURSION: knows all of TYPES
    pub fn recursion_channels() -> Vec<lookup::ChannelSpec>;
}

pub mod keccak {              // docs/spec/delegation.md §6; S21, re-shaped at S26d
    pub const CYCLE: PolyAddress;  LIVE;  BASE;  ANCHOR_VALUE;                 // M[0..4]
    pub fn word(j: usize, field: u32) -> PolyAddress;        // M[4 + 4j + f], j < 51
    pub const WORD_ADDR: u32 = 0;  WORD_READ_TS;  WORD_READ_VALUE;  WORD_WRITE_VALUE;
    pub fn gap_chunk(j: usize, c: usize) -> PolyAddress;     // W[0..102], two a word
    pub fn base_low();  base_low_hi();  base_room();  base_room_hi();          // W[102..106]
    pub fn round_sel(r: usize) -> PolyAddress;               // W[106..130], one-hot over 24
    pub fn rc(t: usize) -> PolyAddress;                      // W[130..134], IOTA_BYTES order
    pub fn state_in(i: usize, b: usize) -> PolyAddress;      // W[134..334], 25 lanes x 8 BYTES
    pub fn parity(x, b, s);  theta_c(x, b);  c_mask(x, b);  theta_d(x, b);     // W[334..574]
    pub fn theta_a(i, b);  rho_mask(i, b);  rho_out(i, b);                     // W[574..1150]
    pub fn chi_and(i, b);  chi_out(i, b);  iota_out(t);                        // W[1150..1554]
    pub fn range16_multiplicity();  xor8_multiplicity();                       // W[1554..1556]
    pub const MEMORY_COLUMNS: usize = 208;  WITNESS_COLUMNS: usize = 1556;
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;     // 16 <= n; flat, no layered work
    pub fn channels() -> Vec<lookup::ChannelSpec>;           // RANGE16, then XOR8
    pub fn check_shape(a: &CircuitArtifact);
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

pub mod mod_mul {                            // docs/spec/delegation.md §14; S26, S26b
    pub const CYCLE; LIVE; BASE; ANCHOR_VALUE; WORD_*;
    pub fn word(j, field);  gap_bit(j, bit);  base_low_bit(bit);  base_room_bit(bit);
    pub const A: usize = 0;  B: usize = 1;  OUT: usize = 2;  // never a bare index
    pub fn selector(i);                             // i < 4, mod_mul::CODES order, one-hot
    pub fn m_limb(k);                               // the selected modulus, pinned to the selector
    pub fn value_bit(v, k, t);                      // v in {A, B, OUT} -- 8x32 bits each
    pub fn diff_bit(v, i, t);  borrow_bit(v, i);    // v < m, one chain per value
    pub fn q_limb(k);  q_bit(k, t);                 // the quotient, witnessed
    pub fn carry_bit(k, t);                         // 14 signed carries, offset 2^36, 37 bits
    pub const MEMORY_COLUMNS: usize = 104;  WITNESS_COLUMNS: usize = 3364;
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;           // EMPTY
}

pub mod sha256 {             // docs/spec/delegation.md §15; S26c, re-shaped at S26e
    pub const CYCLE; LIVE; BASE; ANCHOR_VALUE; WORD_*;  pub fn word(j, field);   // M[0..104]
    pub fn gap_chunk(j, c);  base_low();  base_low_hi();  base_room();  base_room_hi();
    pub fn group_sel(r: usize) -> PolyAddress;      // r < 16, one-hot
    pub fn a_byte(j: isize, b);  e_byte(j, b);      // A_{-2..3}, E_{-2..3}
    pub fn w_byte(i, b);  n_byte(m, b);             // the window and derived words the sigmas read
    pub enum Round { Bs0M1, Bs0Y, Bs0M3, Bs0X, Bs0Mx, Bs1M6, Bs1Y, Bs1M5, Bs1X, Bs1Mx,
                     ChEf, ChEg, MajAb, MajCab, CarryA, CarryE }
    pub enum Sched { Ss0M3, Ss0Y, Ss0M7, Ss0Shr, Ss0Z, Ss1M2, Ss1Y, Ss1M1, Ss1Shr, Ss1Z, CarryW }
    pub fn round_col(k, Round, b);  sched_col(m, Sched, b);   // 52 a round, 39 a schedule word
    pub fn written_hi(slot);  pub const PAIRED_WORDS: [usize; 4];   // a, e, derived 2 and 3
    pub fn range16_multiplicity();  xor8_multiplicity();
    pub const MEMORY_COLUMNS: usize = 104;  WITNESS_COLUMNS: usize = 520;
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;     // 16 <= n; flat
    pub fn channels() -> Vec<lookup::ChannelSpec>;           // RANGE16, then XOR8
    pub fn check_shape(a: &CircuitArtifact);
}

// S-RECURSION's four field families, docs/spec/recursion.md §3-§6: in recursion_circuit only.
// Each opens with delegation's head and frame words, M[0..4 + 4·words], and its read-only
// RANGE16 frame's witness, W[0..2·words + 4]; the module lists what follows. All four are flat.
pub mod fr_op {                                   // §3: one Fr operation a row
    pub const A_LIVE: PolyAddress;  A_READ_TS;  A;                       // M[20..23], at Δ0
    pub const B_LIVE: PolyAddress;  B_READ_TS;  B;  B_NEW;               // M[23..27], at Δ1
    pub const D_LIVE: PolyAddress;  D_READ_TS;  D;  D_NEW;               // M[27..31], at Δ2
    pub const fn gap_chunk(q: usize, c: usize);     // W[12..18]: a, b, d, two chunks each
    pub const fn selector(i: usize);                // W[18..27]: op code i + 1, fr_op::OPS order
    pub const X: PolyAddress;  PROD;  Z;  MULTIPLICITY;                  // W[27..31]
    pub const MEMORY_COLUMNS: usize = 31;  WITNESS_COLUMNS: usize = 31;
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;     // 16 <= n
    pub fn channels() -> Vec<lookup::ChannelSpec>;           // RANGE16
}

pub mod p2_field {                                // §4: one duplex step a row
    pub const fn state_read_ts(i);  state(i);       // M[24..30]: cells s..s+3, at Δ0
    pub const X_LIVE: PolyAddress;  X_READ_TS;  X;  Y_LIVE;  Y_READ_TS;  Y;   // M[30..36], at Δ1, Δ2
    pub const fn next_read_ts(i);  next_old(i);  next(i);   // M[36..45]: cells d..d+3, at Δ3
    pub const fn gap_chunk(q, c);                   // W[14..30]: state0..2, x, y, next0..2
    pub const LANE0: PolyAddress;  LANE1;           // W[30..32]: the rate after absorbing
    pub const fn permutation_column(i);             // W[32..381]; PERMUTATION_COLUMNS = 349
    pub const MULTIPLICITY: PolyAddress;            // W[381]
    pub const MEMORY_COLUMNS: usize = 45;  WITNESS_COLUMNS: usize = 382;
    pub fn permutation_witness(lanes: [Fr; 3]) -> (Vec<Fr>, [Fr; 3]);   // the fill's columns, the output
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;     // 16 <= n
    pub fn channels() -> Vec<lookup::ChannelSpec>;           // RANGE16
}

pub mod field_io {                                // §5: one move between RAM and a cell a row
    pub const fn data_read_ts(k);  data_read(k);  data_write(k);   // M[16..40]: RAM ptr + 4k, at Δ1
    pub const CELL_READ_TS: PolyAddress;  CELL_OLD;  CELL_NEW;      // M[40..43], at Δ0
    pub const fn gap_chunk(k, c);                   // W[10..28]: data0..7, then k = 8 the cell
    pub const IMPORT: PolyAddress;  EXPORT;         // W[28..30]
    pub const fn word_hi(k);                        // W[30..38]: each exported word's high halfword
    pub const MULTIPLICITY: PolyAddress;            // W[38]
    pub const MEMORY_COLUMNS: usize = 43;  WITNESS_COLUMNS: usize = 39;
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;     // 16 <= n
    pub fn channels() -> Vec<lookup::ChannelSpec>;           // RANGE16
}

pub mod fq_op {                                   // §6: one Fq operation a row
    pub const G_ADDR: PolyAddress;  G_READ_TS;  DIGIT;      // M[20..23]: the digit cell, at Δ0
    pub const fn addr(q);  a_read_ts(i);  read_ts(q);  a(i);  b(i);  d_old(i);  d_new(i);   // M[23..48]
    pub const GAPS: usize = 7;  pub const fn gap_hi(k);     // W[12..19]: g, a0..a3, b, d
    pub const fn selector(i);                       // W[19..24]: op code i + 1
    pub const IND_D: PolyAddress;  IND_A;  IND_B;   // W[24..27]
    pub const fn y(j);  d_chunk(i, c);  k_chunk(j, c);  carry_chunk(g, c);   // W[27..71]
    pub const MULT_TIMESTAMP: PolyAddress;  MULT_RANGE16;   // W[71..73]
    pub const MEMORY_COLUMNS: usize = 48;  WITNESS_COLUMNS: usize = 73;  CARRY_OFFSET_BITS: u32 = 75;
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;     // 19 <= n, so 2^20 on the even menu
    pub fn channels() -> Vec<lookup::ChannelSpec>;           // TIMESTAMP, then RANGE16
    pub struct Witness { pub y, pub d_chunks, pub k_chunks, pub carry_chunks }
    pub fn witness(code: u32, a: [u64; 4], b: [u64; 4], d_new: [u64; 4]) -> Witness;
    pub fn canonical(x);  mul_mod_q(a, b);  add_mod_q(a, b);  sub_mod_q(a, b);  inv_mod_q(a);  limb(v: Fr);
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
- **Seven virtual kinds, append-only**: `RowIndex` (`V[row]`, tag 0), `RamLive`
  (`V[ram_live]`, tag 1, `docs/spec/gkr.md` §2.1), S15's range tables `Range19` (tag 2)
  and `Range16` (tag 3), each the low `BITS` bits of the row index
  (`docs/spec/lookup.md` §3), and S26d's `Xor8A` (tag 4), `Xor8B` (5) and `Xor8Out` (6) —
  the `XOR8` channel's three table columns, the row index's low byte, its next byte, and
  their XOR (`docs/spec/lookup.md` §14). `Xor8Out` is the first closed form that is not a
  weighted sum of the row's bits: `Σ_{j<8} 2^j·(y_j + y_{j+8} − 2·y_j·y_{j+8})`, which is
  multilinear because `y ^ z = y + z − 2yz` is. Their closed forms are `gkr-verify`'s.
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
  gates, the names and the four artifact constructors are there and nowhere else: `trace`
  fills the columns, `gkr-verify`'s boundary evaluates `read_tuple` through the kernel, and
  `kat-gen` writes the constructors' bytes. One exception since S17: the x0 rule's first
  two gates come from `gadgets::is_zero`, with their bytes unchanged.
- **`value_window_artifact` is S-IO's one new constructor, and two families share it**
  (`docs/spec/public-values.md` §4). It is `zero_window_artifact` with one committed column
  added: `M[0] teardown_ts`, `M[1] teardown_value`, `M[2] init_value`, `V[row]`; the
  teardown tuple on the read side and the init tuple, value `M[2]`, on the write side; then
  `trace_vars` halving lists to the two roots. **No enforcing gate, no lookup, no channel,
  no setup column, degree 1 throughout** — two leaves and a product tree. `PUBLIC_INPUT` and
  `ADVICE_WINDOWS` take it and differ only in what the verifier does with `M[2]`: holds it to
  the statement's `input` at the shard's own opening point, or to nothing at all, which is
  what makes advice advice. `INIT_TEARDOWN`'s init column is `S[0]` instead because program
  identity binds it, and one execution's public values have no business in every execution's
  identity.
- **`field_window_artifact` is S-RECURSION's one new memory constructor, and it is
  `zero_window_artifact` at a stride of one cell a row** (`docs/spec/recursion.md` §2.2). Both
  are one private `zero_window(trace_vars, stride)`, whose teardown and init tuples carry
  `(α_addr, V[row])` `stride` times: `WORD_BYTES`, four, for a RAM window, and once for a field
  window, so row `y` of window `w` is cell `h·w + y`. Nothing else differs — `M[0]
  teardown_ts`, `M[1] teardown_value`, `V[row]`, init value the literal 0, no gate, no lookup,
  no channel — so the registry builds it at any height; `FIELD_WINDOWS`' default is `2^20`.
  The windows are consecutive from cell 0, shard `i` being window `i`. **The address space
  is not in the artifact**: it is the derived slot 5's alone, `γ_M + FIELD + α_addr·h·w`, which
  `gkr_verify::field_window_challenges` derives as `window_challenges` derives RAM's. The
  artifact's stride and slot 5's are one convention kept on two sides, and at window 0 the
  second is invisible, `α_addr·h·w` being 0 there.
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
- **`family_circuit` is the base format's one registry of circuits**
  (`docs/spec/shard-proof.md` §11). A verifying key's circuits are byte for byte what it returns for the key's families and
  heights, so a circuit is a protocol constant given a family and a height; a later family
  is one arm here and one fill in `crates/prover`. It returns `None` above
  `MAX_TRACE_VARS` and for **any of the seven execution families below 19 variables**, the
  timestamp channel's bound. The window families have no channels and take any height.
  Since S19 it holds every family the master prompt names, and since S21 the first that it
  does not: `ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT`, `SHIFT_BITWISE`, `MUL_DIV`, `MEM_WORD`,
  `MEM_SUBWORD`, `ATOMICS`, the two RAM windows, `KECCAK_F`, S23's `POSEIDON2` and
  `FR_ARITH`, and S26's `MOD_MUL`. **S-IO added three arms and exactly one constructor.** `PUBLIC_OUTPUT` takes
  `memory::zero_window_artifact` — the *same* function `ZERO_WINDOWS` takes, so the journal's
  circuit is `ZERO_WINDOWS`' **byte for byte**, and that is the point: its init leaf is the
  literal 0, so there is no init column for a prover to pre-load the journal into at
  timestamp 0 and then never store a word. Nothing checks that, because there is nothing to
  check; it is structural where a verifier-side check could be forgotten
  (`docs/spec/public-values.md` §5). `PUBLIC_INPUT` and `ADVICE_WINDOWS` share
  `memory::value_window_artifact`. **The minimum-height guard is derived from each family's own
  channels, and since S26c it is not a list**: `HEIGHT_MENU` legally holds `2^16` and `2^18`,
  `VerifyingKey::check` builds a circuit from a key's own `VmConfig`, and a family whose floor
  the guard did not know would reach `lookup::channel_trees`' `BITS <= trace_vars` assertion —
  a panic inside key validation, in a `no_std` crate the recursion guest links, on bytes a
  verifier was handed. `family_circuit` therefore takes each family's `channels()`, takes the
  widest range channel's `BITS` as its floor, and tests that **before** building the artifact:
  the seven execution families get 19 as they always did, `MOD_MUL`, `EC_ADD` and — since S26d —
  `KECCAK_F` get 16, and the three channel-free delegation families get 0, which is what lets
  them take `2^8`. **Since S26d the per-channel number is `lookup::table_vars` and not `BITS`
  with an `IS_RANGE` filter**: `XOR8`'s table is 65,536 rows without being a range channel, so
  the filter would have given a family carrying it alone a floor of 0 and an incomplete table
  at every height below `2^16`
  (`docs/spec/delegation.md` §9.2, §10.3). It named the seven execution families explicitly
  until S26c, with a delegation family's arm below it; that worked only while no delegation
  family had a channel, and keeping a list in step with two families whose heights differ from
  every other's is exactly the drift the derivation removes.
- **Since S-RECURSION there are two registries, one a format, over one private `circuit`
  match** (`docs/spec/recursion.md` §1.2). `recursion_circuit` is `family_circuit` but in two
  ways: its `ADD_SUB_LUI_AUIPC` is `add_sub::recursion_artifact` with `recursion_channels`, and
  it holds the five recursion families — `FIELD_WINDOWS`, `FR_OP`, `P2_FIELD`, `FIELD_IO`,
  `FQ_OP` — whose arms are guarded `if recursion`, so `family_circuit` returns `None` for them
  and **a base key cannot name one**. Every other family's circuit is the base registry's byte
  for byte. Nothing on the wire says which registry applies: `verifier_core::VmConfig::circuit`
  reads the recursion one exactly when the config holds `FIELD_WINDOWS` (`is_recursion`), and
  both `VerifyingKey::check` and the prover's `register` go through it. One match is also what
  lets the derived floor serve both: `FIELD_WINDOWS` has no channel and gets 0; `FR_OP`,
  `P2_FIELD` and `FIELD_IO` carry `RANGE16` alone and get 16; `FQ_OP` carries `TIMESTAMP` and
  gets 19, which the menu's even heights make `2^20`.
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
- **`add_sub` is §8 as data**, S15's `frame_with_channels_artifact` over the family's
  **five** frame queries plus 27 witness columns, the 7-column decoded table as `S`, 52
  enforcing gates of its own beside the frame's 11, five lookups and three channels — one
  selector column and three gates of those for each of the six delegation types it knows,
  so the counts were 25 and 46 until S26c's two. Its gates are the family's whole semantics:
  one-hot kinds and the packed mask the table's domain; each query's mask the row kind's
  use of it times `m_pc`; each written value the kind's arithmetic with a boolean carry
  and a 16+16-bit range split; `ecall` as `exit` (`a7 = 93`) or one registered delegation
  request, an exit's status `a0` and its `next_pc` `HALT_PC`; every other row's `next_pc`
  the decoded fall-through, with a boolean `pc_wrap`. A `const` assertion pins
  `system_code::ECALL == 0`, so a renumbering fails the build, and `artifact` asserts each
  channel's obligation count — 10, 4, 1 — when it builds the circuit, so a dropped
  obligation panics at construction.
- **Three of that family's mask rules are gone, and they proved nothing.** Until the POSIX
  layer went, the frame carried `arg1`, `arg2` and `ram`, and each had a `<q>_mask_rule`
  reading `mask == 0`: an ecall's `a1` and `a2` were `read`'s and `write`'s alone, and the
  `ram` query was the transfer row's. The family already forbade all three by holding the
  mask to zero, so the columns were five `M` columns and two obligations apiece that no
  honest row could make nonzero and no cheating one could use. Dropping the queries drops
  the gates with them: **42 memory columns become 27, 11 witness become 8, 16 obligations
  become 10, and the frame's own enforcing gates go 16 to 11.** The frame also starts paying
  a pad: eight queries were a power of two a side, five are not, so gate list 0 carries
  three literal-1 leaves a side, as `ATOMICS`' has always done.
- **`add_sub::recursion_artifact` is the recursion format's `ADD_SUB`, and `artifact` keeps
  S26c's bytes** (`docs/spec/recursion.md` §1.2, §1.4). Both are one private `build(trace_vars,
  types)` over the first `types` rows of `constants::delegation::TYPES`: `artifact` passes
  `BASE_TYPES`, 6, and `recursion_artifact` all ten. Each row a circuit knows costs a selector,
  `is_delegation(i) = W[22 + i]`, three gates, and a term in each gate that sums over the
  selectors, and every column after the selectors moves with the count — which is why
  `wrap`, `rd_hi`, `pc_wrap`, `next_pc_hi` and `multiplicities` take `types` and the constants
  of those names are the base values. The recursion form commits 39 witness columns to the
  base's 35 and carries 64 gates of its own to 52. **One gate differs by format**: in place of
  `deleg_writes_no_register` the recursion form carries `deleg_a0_rule`,
  `Σ_t is_deleg_t·rd_selected − Σ_{t ≥ BASE_TYPES} is_deleg_t·(v_rs2 + 4·words_t) = 0`, `v_rs2`
  being the `rs2` query's read, which on an ecall row is `a0`. The rule it states is per type:
  a recursion request writes `constants::delegation::a0_after` — its frame base advanced past
  its frame — and a base type writes 0 in either circuit; either way the request writes no
  value of its own choosing, which is what the zeroing was for. **`BASE_TYPES` is frozen**: a
  row appended to `TYPES` moves the recursion `ADD_SUB` and no base key, and
  `tests/vectors/recursion.txt` pins it.
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
  split base-4 is three `RANGE16` obligations on `word_index` — the direct pair and
  `4·word_index_hi`, which caps `word_index` at `2^30 − 1` and is exactly tight at the top
  of the address space. Every RAM query's address is `4·word_index`, so a sub-word access,
  a word access and an atomic name one cell. All three pass `(word_index_hi, m_pc)` to
  `check_copowers`.
  - **`mem_word`**: the six-query frame plus 15 witness columns, S11's seven-column
    decoded table as `S`, 33 enforcing gates, 18 lookups and **three** channels — it reads
    no generic lookup, the second registered family after `ADD_SUB_LUI_AUIPC` with none,
    so `reads_generic_table` is false and its setup list is identity's alone. It carries no
    offset bits at all, which is what makes a misaligned `lw` or `sw` unrepresentable.
    `rd_selected` carries a 16+16 pair, which is what keeps every register value in the VM
    locally 32-bit (`memory-ops.md` §5.1).
  - **`mem_subword`**: the same frame plus 46 witness columns, the decoded table and the
    packed generic table as `S`, 53 enforcing gates, 36 lookups and four channels.
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
- **S-RECURSION's four field families share one shape, built from `delegation.rs`'s
  crate-private pieces** (`docs/spec/recursion.md` §2–§6). The frame is read-only over
  `RANGE16`, `read_only_frame_range16`: `frame_gates_range16` plus one `writes_back_w{j}` a
  word, over `frame_witness_range16(words) = 2·words + 4` witness columns, `MOD_MUL`'s layout.
  Each access a row makes besides its frame is an `Access`: a word or cell `addr + offset` of a
  space, under a mask, read at a `read_ts` column and written at `4·cycle + Δ` for its slot Δ,
  a read-only access writing back its read column. Its leaves are `masked_leaf`, S21's `leaf`
  under that mask and offset — at `LIVE` and offset 0 it is `leaf` term for term, so no earlier
  delegation family moved — and `leaves_with` appends every access's read and write after the
  anchor's and the frame's, one power of two a side. An access's gap is two `RANGE16` chunks,
  four obligations under its mask whose top chunk `scaled` hands `check_copowers`, everywhere
  but `FQ_OP`, whose gaps are `TIMESTAMP`'s. All
  four go through `memory::assemble` with no layer of their own, as `KECCAK_F` does, so each is
  validated, held to `check_memory` and to the discharge rule as it is built, and each
  `artifact` asserts its `M` and `W` widths. A `const` assertion beside S21's refuses a frame
  query at `(RAM, field_io::DATA_DELTA)`, so `FIELD_IO`'s data words, like a frame's, are never
  filed into the requesting row.
- **`fr_op` is §3 as data**: one field operation a row over the three cells its frame's words
  name — `a` at Δ0, `b` at Δ1, `d` at Δ2, so any two may alias — in 31 `M` and 31 `W` columns
  and 44 enforcing gates, 11 the frame's. Nine op selectors are boolean, sum to `live` and
  recompose frame word 0, and each access's mask is the sum of the selectors of the ops that
  touch it: `IMM` reads no `a`, `EQ` writes no `d`. **One product serves every op that
  multiplies**: `x` is `b` on `MUL` and `MAC` and `d′` on `INV`, so `prod = a·x` is the one
  product of two row values and each op's equation is degree 2 under its selector. `INV` is
  the is-zero gadget — `a·d′ = 1 − z`, `z·a = 0`, `z·d′ = 0`, `z` boolean and 0 off `INV` — so
  `d′` is `a⁻¹`, and 0 at `a = 0`. **`DIGIT` is the one op that writes two cells**: `a = d′ +
  2^8·b′`, `d′` below `2^8` by its direct `RANGE16` obligation and its `2^8`-scaled one under
  `DIGIT`'s selector, the pair `check_copowers` requires, and `b_kept` writing `b` back
  unchanged on every other row. `RANGE16` carries 36 obligations, 37 leaves of 64. Its floor is
  16 and its `2^20` a choice: one shard holds the 312,984 calls the measured leaf makes (§8.3).
- **`p2_field` is §4 as data**: one step of the transcript's duplex a row, frame `[n, s, x, y,
  d]`. It reads the state at cells `s`, `s + 1`, `s + 2` — one address at offsets 0 to 2 — at
  Δ0, `x` at Δ1 under `x_live` and `y` at Δ2 under `y_live`, with `n = x_live + y_live`, `y`
  only with `x` and either only on a live row; commits `lane0` and `lane1`, the rate
  overwritten and zero-filled, beside the capacity `s₂ + n`; and writes their permutation to
  cells `d` to `d + 2` at Δ3, reading what those cells held. 45 `M`, 382 `W` and 372 enforcing
  gates. **Flat, not layered**: each of the 80 S-boxes commits `u²` and `u⁴` and each round but
  the last its three output lanes, 349 columns, the last round landing on the next state's `M`
  columns — every gate degree 2 on one list, where S23's `POSEIDON2` is ~200 layers deep and a
  parent pays a sumcheck a layer. **Each round constant enters as `rc·live`**, so a padding
  row's permutation is zero, and `artifact` asserts the all-zero row valid.
  `permutation_witness` is the fill's arithmetic in the gates' column order and must spell the
  permutation as `transcript::poseidon2_permute` does: `checker`'s recursion suite takes the
  next state from the emulator and breaks `r63_out*` where the two differ. `RANGE16` carries 58
  obligations, 59 leaves of 64, so six more double its tree. `2^18`, above a floor of 16.
- **`field_io` is §5 as data**: one move a row between eight RAM words `ptr + 4k`, at Δ1 — a
  slot the frame's Δ0 is not, so a frame and its data may overlap — and the field cell the
  frame names, at Δ0. 43 `M`, 39 `W` and 24 enforcing gates. `IMPORT` sets the cell to
  `Σ_k w_k·2^{32k}` in `Fr` — it **reduces**, the element being what a verifier computes with —
  and keeps the words; `EXPORT` keeps the cell and writes words whose sum is congruent to it,
  each below `2^32` by a 16+16 pair under `EXPORT`: **congruence, not canonicity**, and a guest
  that needs canonical limbs compares them with `p` in RAM itself. **No address column and no
  address bound**: a data word's address is the frame's `ptr` plus `4k`, read straight into its
  leaves, and the memory argument alone makes it a word some window initializes. `RANGE16`
  carries 70 obligations, 71 leaves of 128. `2^18`, above a floor of 16.
- **`fq_op` is §6 as data, and the one field family on `TIMESTAMP`**, which forces its `2^20`
  where the other three choose a height above 16. An element of BN254's base field is four
  consecutive cells of 64-bit limbs, below `2^256` and congruent to the element but not
  necessarily below `q`: reduction is lazy, and only this family writes one. The frame `[op, d,
  a, b]` is read-only; `op_word` recomposes the code, the flags `ind_d`, `ind_a`, `ind_b` and
  the digit cell `op >> 6`, and an indirect operand's first cell is its word plus `8·digit`,
  the digit read from that cell at Δ0. **One identity serves every op**: `a·y + z = q·K + d′`
  over the integers — `y` four committed columns, `b` on `MUL` and `MULEQ`, 1 on `ADD` and
  `SUB`, 0 on `FROM128`, and `z`'s limbs `b_k`, `6q_k − b_k` or `d′_k` by selector — checked as
  `group0..3` over limb positions `(0,1)`, `(2,3)`, `(4,5)` and `(6)` with three signed
  carries. Every term is below `2^208` for any assignment the ranges admit, so no equation
  wraps mod p and the four are the integer identity: **the ranges are the soundness** — `d′`'s
  limbs and `K₀..K₂` 64 bits over `RANGE16`, `K₃` and each carry plus `2^75` 76 bits in
  `TIMESTAMP`'s 19-bit chunks, the carry's `−2^75·live` term making the all-zero row's carry 0.
  `MULEQ` keeps `d`, and so asserts `a·b ≡ d`; `FROM128` has `y = 0`, so `K = 0`, and spells
  `a`'s two cells as `d′`'s four limbs. **`b`'s and `d`'s four cells share one read timestamp
  and one gap**, only this family writing an element and all four at once; `a`'s carry one
  each, `FROM128`'s operand being transcript limbs imported one at a time — whence §6's two
  rules for a guest. 48 `M`, 73 `W` and 38 enforcing gates. `artifact` asserts the channels'
  counts, `TIMESTAMP`'s 30 filling 31 of 32 leaves and `RANGE16`'s 50 filling 51 of 64: **two
  more `TIMESTAMP` obligations double that tree**. `witness` is a row's arithmetic — `K` by
  exact 2-adic division, `(a·y + z − d′)·q⁻¹ mod 2^576`, asserted back against `q·K`, and the
  carries over the field — and `canonical` and the four `*_mod_q` are plain arithmetic mod `q`
  for the native reading and the host.

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

`tests/vectors/{keccak,poseidon2,fr_arith,mod_mul,sha256,ec_add}.txt`: **digests, not
artifacts.** A delegation row is a whole field operation, a whole permutation or — since S26d — one keccak round, so the
artifacts run to megabytes — `poseidon2::artifact(8).to_bytes()` is 2,056,361 bytes, and
`sha256::artifact(8)`'s was 10,895,760 until S26e made it 845,456 at `2^18` — and what is committed is one line apiece: the shape
counts and the artifact's SHA-256. `cargo run -p kat-gen -- delegation` writes them,
kat-gen's own unit test holds each to its constructor, and CI regenerates and diffs them like
every other fixture. The owner chose the digest at S21 over committing the bytes or committing
nothing. Their readable accounts are `docs/spec/constraint-manifest.md` §12, §13, §14, §18,
§19 and §20. **Keccak's was 100,254,040 bytes until S26d** — 974 times the largest committed
circuit, and the reason the digest convention exists — and one round a row took it to
1,900,468 at the `2^18` the family now takes, small enough that `checker dump` of it is
20,373 readable lines where a 358,525-relation listing was not a readable account of
anything.

`tests/vectors/recursion.txt`: **S-RECURSION's circuits, by digest** on the same convention —
`family n memory witness layers inner relations outputs bytes sha256`, the digest of
`recursion_circuit(family, n).artifact.to_bytes()`. Six lines: the five recursion families at
their default heights, then `ADD_SUB_LUI_AUIPC`'s recursion form at `2^20`, the one family
whose recursion circuit is not its base circuit. The largest is `P2_FIELD`'s 294,425 bytes.
`cargo run -p kat-gen -- recursion` writes it, a default group, and CI regenerates and diffs
it; **unlike the delegation group's, no kat-gen unit test holds a line to its constructor**,
so the regenerate-and-diff is its whole guard. `docs/spec/recursion.md` §1.4 and §2–§6 are its
readable account.

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
| `tests/wire.rs` | both fixtures round-trip byte for byte; a format version other than 1 refused before decoding; **all seven** `VirtualKind` tags and their names, with the first index no kind has refused — the line that has to move when a kind is appended, and it moved from 4 to 7 at S26d — and `V[ram_live]`'s address and name; a lookup against its hand-written bytes; `Quadratic` against its hand-written bytes for no terms, linear only, products only and both, and each malformed `Quadratic` refused; every refusal of the reader; every single-bit flip of a fixture decodes or errors, never panics |
| `tests/laws.rs` | one mutation of the toy per rule, each refused with its error — structured variants matched whole, prose details by the rule and the address or name they carry — beside the toy validating; each lookup rule broken alone, refused naming the lookup, beside one and two lawful lookups and an `M` selector; the degree-3 gate; `Quadratic`'s degree, its identically zero and unread-column cases, Law 4 against an `AffineProduct` relation, and its refusal to inline; cache-free inlining and its refusals |
| `tests/memory.rs` | the three fixtures pinned and equal to their constructors; every constructor validating and passing `check_memory` at 12 and 22; two roots named `read_root`, `write_root`, an all-zero padding row, `trace_vars` halving lists; every read tuple's parts at their `PART_*` positions; the frame's layout, leaf order, widths and enforcing gates by name; each family's `2w` obligations whole, `gap_lo_pc`'s constant `−1`; acceptance 11 exhaustively at reduced width, 5-bit chunks over a 10-bit clock, each query's own `gap_lo` expression read from the frame with its high chunk at 0, every `(cycle, read_ts)` pair admitted exactly when `read_ts < 4·cycle + Δ`; §8's pinned read sets; `check_memory` refusing a leaf fed from `W` (acceptance 9); the forward-provenance counterexample as a producing and as an enforcing gate of list 1, each beside its lawful control; a slot and a `W` column meeting through two cached entries, a cached entry itself carrying both, and a slot over a cached entry; a frame without `pc_mask_boolean` and one without `rd_mask_boolean`, whose mask another gate still reads; a window leaf masked by `S[0]` and by `V[row]`; a global slot over an inner column; and a write root read from a `W` column alone, which provenance does not see — each mutant still passing `validate`, each test run against the mutant it names |
| `src/gadgets.rs` (unit) | two range halfwords are the comparison's 32-bit word; the comparison returns two gates and eight lookups, each sign lookup the generic table's width; the equation built at 1 and 32 bits and refused at 0 and 33; a `const` assertion holds `U16GetSign`'s keys above AND's |
| `src/shift_bitwise.rs` (unit) | the legal masks are twelve distinct single bits; the two halves and the two shift directions partition the kinds; and through the private `assemble` seam, the honest family spec gives `artifact`, and the build is refused for an obligation dropped, for `residue`'s direct pair moved under a narrower selector than its scaled obligation (S18's tightened copower check) and for a gate nonzero on the all-zero row |
| `src/mul_div.rs` (unit) | the legal masks are eight distinct single bits; the multiplies and the divisions partition the kinds; `arithmetic_gates` built at 1 and 32 bits and refused at 0 and 33; and through the `assemble` seam, the honest spec gives `artifact` and the build is refused for a dropped obligation and for a gate nonzero on the all-zero row |
| `src/jump_branch_slt.rs` (unit) | the legal masks are twelve distinct single bits; through the private `assemble` seam, the honest family spec gives `artifact`, and the build is refused for an obligation dropped (the channel count), for `next_pc`'s direct bound replaced (the copower check) and for a gate nonzero on the all-zero row |
| `src/add_sub.rs` (unit, and four `const` assertions) | the three system codes pairwise distinct, which is what lets `system_split`, `ecall_code` and `fence_code` refuse every `ebreak` row; and, since S21, `const _: () = assert!(..)` items holding the provable ecall numbers **pairwise** distinct and each in its ABI range, and every delegation type's address-space tag distinct too — what makes `ecall_is_exit` and the per-type number gates a partition rather than gates that can all hold. S23 made that loop over `constants::delegation::TYPES` rather than naming one number, and it covers every row — S-RECURSION's four too — whichever prefix a circuit knows; S-RECURSION added `BASE_TYPES <= TYPES`. A `const` assertion rather than a test, because a violation there is a mis-numbered ABI and should not compile. Neither gate spells a number: both read `constants::ecall`. The gates themselves are `crates/checker/tests/add_sub.rs`' |
| `src/poseidon2.rs`, `src/fr_arith.rs` (`check_shape`, run on every build) | the same discipline as `keccak`'s, over each circuit's own shape: the column counts, no setup column and **no channel**, every row-wise layer's width equal to its three regions' (poseidon2), the depth, the named relations present **by name**, and every counted family of gates counted on the emitted artifact. `fr_arith` additionally asserts that no relation's name contains `assume` |
| `src/keccak.rs` (`check_shape`, run on every build) | the column counts, no setup column, four virtual tables, six outputs and the obligation count; **the two channels' obligation counts separately** — 210 on `RANGE16` and exactly 1,020 on `XOR8` — and that `(1,020 + 1).next_power_of_two()` is 1,024, which is the cost cliff `docs/spec/delegation.md` §6.5 records and the reason iota is four obligations and not eight; the depth; `live_boolean`, `base_aligned`, `base_in_window`, `round_rule`, `one_round_a_live_row` and `writes_back_w0` present **by name** and one `round{r}_boolean` per round; 51 `addr_w`, 50 each of `input_w` and `output_w`, and 200 `rho_pi_l`; and that the all-zero row is a valid padding row. S21's must-be-exact 4: a bound that exists only in a comment is not a bound, and a name check is what an `assume_*` hypothesis cannot stand in for |
| `src/sha256.rs` (`check_shape`, run on every build, and unit) | S26e: the column counts, a round's 52 and a schedule word's 39, no setup column, four virtual tables, six outputs; **114 obligations on `RANGE16` and 336 on `XOR8`**, under 128- and 512-leaf trees; `live_boolean`, `base_aligned`, `base_in_window`, `group_rule`, `one_group_a_live_row` and `writes_back_w0` by name, 25 `addr_w`, the four rounds' `r{k}_a`/`r{k}_e` and the four `s{m}_sum`, 19 window gates; flatness and a valid all-zero row. The unit tests hold the witness names to the layout and the circuit to building at 16 and not at 14 |
| `src/keccak.rs` (unit) | the rho/pi index map is a permutation of the 25 lanes and its three whole-byte rotations are the ones `mask_slot` exempts; **the rotation's literal weights reproduce `u64::rotate_left`** on every lane's own offset over four pseudo-random states each, evaluated over `Fr` exactly as a gate would — the one place the circuit's arithmetic is checked at the level of the weights themselves; the witness names are the layout, each once; and the circuit builds at 16 and `family_circuit` refuses 8 |
| `src/memory.rs` (unit) | acceptance 12: the frame with one obligation dropped before the artifact is written panics at the count assertion |
| `tests/audit.rs` | every `GateDef` variant, all six, emitted across both compilations, counts written by hand; the catalogue; the two compilations' identical shape |
| `tests/recursion.rs` | S-RECURSION's registry, in ordinary CI: each of the five recursion families builds at its default height in `recursion_circuit` — which runs `validate`, `check_memory` and the discharge rule — with a valid all-zero padding row, and `family_circuit` returns `None` for it, so a base key cannot name one; and every other family id below `family::COUNT` is in both registries or neither, its artifact identical in the two but `ADD_SUB_LUI_AUIPC`'s, whose recursion form commits `TYPES.len() − BASE_TYPES` more witness columns. The circuits' rows are `crates/checker/tests/recursion.rs`' |
| `src/fr_op.rs`, `src/p2_field.rs`, `src/field_io.rs`, `src/fq_op.rs` (run on every build) | each `artifact` asserts its `M` and `W` widths against `MEMORY_COLUMNS` and `WITNESS_COLUMNS` and passes `check_copowers` over its scaled columns — the frame's, then, but for `FQ_OP`, each access's gap top chunk and `FR_OP`'s digit; `P2_FIELD` asserts a valid all-zero row and `FQ_OP` its two channels' obligation counts, 30 and 50; and in `FR_OP` and `FQ_OP` a `const` assertion holds `OPS[i]` to `i + 1`, the selector index a gate reads off a code, `FQ_OP`'s with `OPS.len() < 2^CODE_BITS` |
| `src/p2_field.rs` (unit) | `the_witness_is_the_permutation`: `permutation_witness` fills `PERMUTATION_COLUMNS` columns, the witness names are `WITNESS_COLUMNS` long, and every permutation gate, evaluated by hand over `Fr` on one row's witness and output, vanishes — so the gates and the fill read one column order |
| `src/fq_op.rs` (unit) | `q·q⁻¹ = 1` mod `2^576`, the inverse `witness` divides by; and the plain arithmetic mod `q` — `canonical` of `q − 1` and of `q`, `(q − 1)² = 1`, a difference wrapping below zero, a sum past `q`, an inverse that inverts, and 0's inverse 0 |
