#![no_std]
//! Constants and tags for the whole workspace.
//!
//! This crate holds constant items, a few `const fn` lookups over its own
//! tables, and doc comments: no traits, no macros, no tests. Guest-side code
//! links it, so it is `#![no_std]`.
//!
//! Changing any value here is a protocol change.

/// Protocol version
pub const PROTOCOL_VERSION: u32 = 3;

/// **One tag, one message kind.** The typed layer frames every message as
/// `tag, length, payload...` and nothing more, so injectivity of the absorbed
/// stream rests on each tag naming exactly one kind of message — scalars *or*
/// bytes *or* a challenge, never two. Each constant below records its kind; a
/// message of `F_{p^2}` values is scalars, two lanes a value. Adding a tag is
/// free; reusing one across kinds is a soundness bug. See
/// `docs/spec/transcript.md` §4.
pub mod transcript_tags {
    /// Scalars. The protocol suite and version preamble, `[PROTOCOL_VERSION]`:
    /// the first message of the statement's global transcript
    /// (`docs/spec/proof.md` §2, G1). The shard transcripts and the identity
    /// and I/O sponges open with their own tags instead.
    pub const PROTOCOL_SUITE: u64 = 1;

    /// Scalars. The statement's public I/O: `io_digest`'s 8 lanes, the global
    /// transcript's G6 message (`docs/spec/proof.md` §2).
    pub const PUBLIC_INPUTS: u64 = 2;

    /// Scalars. One sumcheck round polynomial's coefficients.
    pub const SUMCHECK_ROUND: u64 = 3;

    /// Challenge. Every challenge a sumcheck draws: first the `n` eq-randomizers
    /// `r` that fix the zerocheck's equality polynomial, then the per-round
    /// challenge for the round just absorbed. One tag, one kind; the two roles
    /// are separated by their fixed position in the transcript script, not by
    /// their tag.
    pub const SUMCHECK_CHALLENGE: u64 = 4;

    /// Scalars. The digest that binds a witness's columns to the transcript
    /// before any challenge is drawn over them. The same tag frames the
    /// messages inside the separate sponge that produces it; see
    /// `crates/sumcheck`.
    pub const WITNESS_DIGEST: u64 = 5;

    /// Scalars. A sumcheck's `final_evals`: the claimed value of every input
    /// polynomial at the fully bound point, absorbed before any later challenge.
    pub const SUMCHECK_FINAL_EVALS: u64 = 6;

    /// Bytes. The statement's public input inside `io_digest`'s own sponge.
    /// Absorbed first, before the output, which is what domain-separates the
    /// two. `docs/spec/public-values.md` §5.
    pub const PUBLIC_INPUT_STREAM: u64 = 7;

    /// Bytes. The statement's public output, the journal, inside
    /// `io_digest`'s own sponge, absorbed second. Distinct from
    /// [`PUBLIC_INPUT_STREAM`] so that swapping two unequal byte strings
    /// changes the digest. `docs/spec/public-values.md` §5.
    pub const PUBLIC_OUTPUT_STREAM: u64 = 8;

    /// Scalars. The first message of the program-identity sponge: the single
    /// element `code version`. It is what opens that sponge, so the identity
    /// is domain-separated from every other digest in the protocol.
    /// `docs/spec/program.md` §8. Also the global transcript's G5 message, the
    /// identity's 8 lanes (`docs/spec/proof.md` §2).
    pub const PROGRAM_IDENTITY: u64 = 9;

    /// Scalars. The static `VmConfig`: the family ids in ascending order, then
    /// their heights in the same order, then `bytecode_size_words`. The first
    /// of the statement descriptor's three messages, and the second message of
    /// the program-identity sponge.
    pub const VM_CONFIG: u64 = 10;

    /// Scalars. The per-proof shard count of every family in the `VmConfig`,
    /// in the same ascending order. The second of the statement descriptor's
    /// three messages, always absorbed immediately after the [`VM_CONFIG`]
    /// message it counts shards for and before [`MEMORY_WINDOWS`].
    pub const SHARD_COUNTS: u64 = 11;

    /// Scalars. A GKR circuit's claimed outputs, one value per output-map
    /// entry in output-map order, as one message, absorbed before the first
    /// [`GKR_BATCH`] is drawn so that no output can be chosen after the batch
    /// is known. `docs/spec/gkr.md` §5.2.
    pub const GKR_OUTPUTS: u64 = 12;

    /// Challenge. The RLC that batches a layer transition's claims — one per
    /// column of the layer written, then its enforcing gates — into the one
    /// claim its sumcheck proves. Drawn after every claim it batches is
    /// absorbed.
    pub const GKR_BATCH: u64 = 14;

    /// Scalars. The claimed values of the layer a transition reads, at the
    /// point its sumcheck bound, in one message: one per column, or both
    /// children per column for a halving transition.
    pub const GKR_LAYER_CLAIMS: u64 = 15;

    /// Challenge. The point `τ` on the line through a halving transition's
    /// two child claims, drawn after both are absorbed.
    pub const GKR_CHILD: u64 = 16;

    /// Scalars. The statement's RAM window list `[w_1 … w_k]`, the
    /// `ZERO_WINDOWS` family's shard windows ascending, absorbed immediately
    /// after [`SHARD_COUNTS`] and before program identity.
    /// `docs/spec/memory.md` §6.1.
    pub const MEMORY_WINDOWS: u64 = 17;

    /// Scalars. The 64 register and pc boundary scalars
    /// `[t_0 … t_31, t_pc, v_1 … v_31]`, one message, absorbed after the
    /// statement's public values and before the memory challenges are drawn.
    /// `docs/spec/memory.md` §4.1 and §6.1.
    pub const MEMORY_BOUNDARY: u64 = 18;

    /// Scalars. The program-identity sponge's `entry_pc`, one element,
    /// absorbed after [`VM_CONFIG`]: its last message.
    /// `docs/spec/program.md` §8.
    pub const PROGRAM_ENTRY: u64 = 19;

    /// Challenge. The LogUp channels' two shard-local challenges, `g` then
    /// `β`, drawn in that order after the shard's seed and timestamp window.
    /// One tag, one kind; the two roles are separated by their fixed position
    /// in the shard's script, as [`SUMCHECK_CHALLENGE`]'s are.
    /// `docs/spec/lookup.md` §2.
    pub const LOOKUP_CHALLENGE: u64 = 20;

    /// Challenge. The global memory challenges `γ_M, α_addr, α_ts, α_val`,
    /// drawn in that order after the boundary scalars. One tag, one kind; the
    /// four roles are separated by position. `docs/spec/proof.md` §2.
    pub const MEMORY_CHALLENGE: u64 = 21;

    /// Challenge. The global state digest, drawn once after the memory
    /// challenges; every shard transcript is seeded with it.
    /// `docs/spec/proof.md` §2.
    pub const GLOBAL_STATE_DIGEST: u64 = 22;

    /// Scalars. `[global state digest, family, shard index]`, the digest's two
    /// lanes first: the first message of every shard transcript.
    /// `docs/spec/proof.md` §4.
    pub const SHARD_SEED: u64 = 23;

    /// Scalars. `[start, end]`, the shard's timestamp window, immediately after
    /// the seed. `docs/spec/proof.md` §4.
    pub const SHARD_TS_WINDOW: u64 = 24;

    /// Scalars. One family's setup-column commitment, its slices' payloads in
    /// order: the program-identity sponge's messages after [`PROGRAM_ENTRY`],
    /// one per config family in its order. `docs/spec/program.md` §8.
    pub const SETUP_COMMITMENT: u64 = 25;

    /// Scalars. One statement shard's memory-column commitment, its slices'
    /// payloads in order, absorbed between G6 and G7 in statement order.
    /// `docs/spec/proof.md` §2.
    pub const MEMORY_COMMITMENT: u64 = 26;

    /// Scalars. The shard's witness-column commitment, multiplicities
    /// included, between S2 and S3. `docs/spec/proof.md` §4.
    pub const WITNESS_COMMITMENT: u64 = 27;

    /// Scalars or extension elements. Every prover message of an opening:
    /// payloads, partials, round polynomials, claims, nonces, the response.
    /// The roles are separated by their fixed position in the opening's
    /// script, as [`SUMCHECK_CHALLENGE`]'s are. `docs/spec/pcs.md` §7.
    pub const PCS_MESSAGE: u64 = 28;

    /// Challenge. Every challenge of an opening, by position.
    pub const PCS_CHALLENGE: u64 = 29;

    /// Scalars. The coefficients the terminal's last-block digest commits,
    /// inside that digest's own sponge. `docs/spec/pcs.md` §7.
    pub const PCS_DIGEST: u64 = 30;

    /// Every tag's name, indexed by `tag - 1`. **Documentation, never
    /// semantics**, as `challenge_slot::NAMES` is: the number is the tag, and
    /// nothing reads a name to decide anything. `checker::tape` renders a
    /// transcript's absorb sequence with them, which is what makes a tape
    /// diffable against the order `docs/spec/proof.md` §2 specifies.
    ///
    /// One entry per tag above, and `"RETIRED"` at the retired 13. The lookup
    /// itself lives in `checker::tape`.
    pub const NAMES: [&str; 30] = [
        "PROTOCOL_SUITE",
        "PUBLIC_INPUTS",
        "SUMCHECK_ROUND",
        "SUMCHECK_CHALLENGE",
        "WITNESS_DIGEST",
        "SUMCHECK_FINAL_EVALS",
        "PUBLIC_INPUT_STREAM",
        "PUBLIC_OUTPUT_STREAM",
        "PROGRAM_IDENTITY",
        "VM_CONFIG",
        "SHARD_COUNTS",
        "GKR_OUTPUTS",
        "RETIRED",
        "GKR_BATCH",
        "GKR_LAYER_CLAIMS",
        "GKR_CHILD",
        "MEMORY_WINDOWS",
        "MEMORY_BOUNDARY",
        "PROGRAM_ENTRY",
        "LOOKUP_CHALLENGE",
        "MEMORY_CHALLENGE",
        "GLOBAL_STATE_DIGEST",
        "SHARD_SEED",
        "SHARD_TS_WINDOW",
        "SETUP_COMMITMENT",
        "MEMORY_COMMITMENT",
        "WITNESS_COMMITMENT",
        "PCS_MESSAGE",
        "PCS_CHALLENGE",
        "PCS_DIGEST",
    ];
}

/// The external challenge slots a GKR circuit's coefficients may name. A slot
/// number is never reassigned.
///
/// A `constraints::Coeff::Challenge(slot)` names one of these numbers, and the
/// caller supplies its value in `ExternalChallenges`. The number is the
/// semantics; [`challenge_slot::NAMES`] is documentation for dumps and
/// diagnostics, indexed by slot, exactly as a tag's constant name is.
pub mod challenge_slot {
    /// The test circuits' one challenge. No production circuit reads it.
    pub const TOY: u32 = 0;

    /// `γ_M`, the memory tuple's additive challenge. Drawn once per
    /// statement, after everything `docs/spec/memory.md` §6.1 absorbs.
    pub const MEM_GAMMA: u32 = 1;

    /// `α_addr`, the weight of a memory tuple's address. Drawn.
    /// `docs/spec/memory.md` §1.
    pub const MEM_ALPHA_ADDR: u32 = 2;

    /// `α_ts`, the weight of a memory tuple's timestamp. Drawn.
    /// `docs/spec/memory.md` §1.
    pub const MEM_ALPHA_TS: u32 = 3;

    /// `α_val`, the weight of a memory tuple's value, or of its low word for a
    /// register. Drawn. `docs/spec/memory.md` §1.
    pub const MEM_ALPHA_VAL: u32 = 4;

    /// A RAM window shard's constant `γ_M + RAM + α_addr·4h·w`. **Derived,
    /// not drawn**: the verifier computes it from slots 1 and 2 and the window
    /// id bound in the statement, and never reads it from a proof.
    /// `docs/spec/memory.md` §3.3.
    pub const MEM_WINDOW_CONSTANT: u32 = 5;

    /// `g`, the LogUp channels' additive challenge. Drawn **per shard**, from
    /// that shard's own transcript, after its seed and timestamp window.
    /// `docs/spec/lookup.md` §2.
    pub const LOOKUP_G: u32 = 6;

    /// `β`, the LogUp tuple-compression challenge: a tuple is
    /// `Σ_j β^j·col_j`, `β^0` being the literal 1. Drawn per shard,
    /// immediately after [`LOOKUP_G`].
    pub const LOOKUP_BETA: u32 = 7;

    /// `β^2`. **Derived**: a gate coefficient is one literal or one challenge,
    /// so every power above the first is a slot of its own, computed by the
    /// verifier from [`LOOKUP_BETA`] and never read from a proof.
    pub const LOOKUP_BETA_2: u32 = 8;
    /// `β^3`, derived.
    pub const LOOKUP_BETA_3: u32 = 9;
    /// `β^4`, derived.
    pub const LOOKUP_BETA_4: u32 = 10;
    /// `β^5`, derived.
    pub const LOOKUP_BETA_5: u32 = 11;
    /// `β^6`, derived.
    pub const LOOKUP_BETA_6: u32 = 12;

    /// `β^j`'s slot for `j = 1 ..= 6`, indexed by `j - 1`. `β^0` is the
    /// literal 1 and has no slot, which is why a range channel's one-column
    /// tuple names no power at all.
    pub const LOOKUP_BETA_POWERS: [u32; 6] = [
        LOOKUP_BETA,
        LOOKUP_BETA_2,
        LOOKUP_BETA_3,
        LOOKUP_BETA_4,
        LOOKUP_BETA_5,
        LOOKUP_BETA_6,
    ];

    /// `g − Σ_{j < W} β^j`, the decoder channel's denominator at a padding
    /// row, `W` being that circuit's decoder tuple width. **Derived**: the
    /// decoder's neutral tuple is `MINUS_ONE` in every column
    /// (`docs/spec/lookup.md` §5), and a `Coeff` is one literal or one
    /// challenge, so the sum it compresses to is a slot rather than a
    /// constant.
    pub const LOOKUP_DECODER_NEUTRAL: u32 = 13;

    /// `α_hi`, the weight of a register value's high word: a register holds 64
    /// bits as two words, and one weighted sum of both would not be injective
    /// below `p`. Drawn, right after [`MEM_ALPHA_VAL`]. `docs/spec/memory.md` §1.
    pub const MEM_ALPHA_HI: u32 = 14;

    /// Every slot's display name, indexed by slot number.
    pub const NAMES: [&str; 15] = [
        "toy",
        "mem_gamma",
        "mem_alpha_addr",
        "mem_alpha_ts",
        "mem_alpha_val",
        "mem_window_constant",
        "lookup_g",
        "lookup_beta",
        "lookup_beta_2",
        "lookup_beta_3",
        "lookup_beta_4",
        "lookup_beta_5",
        "lookup_beta_6",
        "lookup_decoder_neutral",
        "mem_alpha_hi",
    ];
}

/// The lookup channels a lookup expression names. A channel number is never
/// reassigned.
///
/// A `LookupExpr`'s `channel` is one of these numbers. A channel is either a
/// **range** channel, whose one expression holds on a row when its canonical
/// integer is below `2^BITS[channel]`, or a **table** channel, whose tuple
/// holds when it is a row of the channel's table, a set of setup columns.
/// [`lookup_channel::NAMES`] is documentation, indexed by channel, as
/// [`challenge_slot::NAMES`] is. `docs/spec/lookup.md` §1 and §3.
pub mod lookup_channel {
    /// Range. The timestamp gap's two 19-bit chunks: `[0, 2^19)`.
    pub const TIMESTAMP: u32 = 0;

    /// Range. A halfword, `[0, 2^16)`: two of them bound a 32-bit value, under
    /// the range convention of `docs/spec/memory.md` §7.
    pub const RANGE16: u32 = 1;

    /// Table. The generic tables, packed into one table under the gated-key
    /// convention of `docs/spec/lookup.md` §4.
    pub const GENERIC: u32 = 2;

    /// Table. A family's decoded instruction table, `crates/program`'s
    /// `lookup_tuple(family)` columns in their fixed order.
    pub const DECODER: u32 = 3;

    /// How many channels this table defines.
    pub const COUNT: u32 = 4;

    /// Whether channel `i` is a range channel, indexed by channel. A range
    /// channel's table is the closed form of `docs/spec/lookup.md` §3; a table
    /// channel's is setup columns.
    pub const IS_RANGE: [bool; COUNT as usize] = [true, true, false, false];

    /// A range channel's bound, as a bit width, indexed by channel; 0 where
    /// [`IS_RANGE`] is false, which is not a bound of `[0, 1)` but the absence
    /// of one.
    ///
    /// This is a **bound**, not a table size: what decides the fewest
    /// variables a circuit declaring a channel may be built at is
    /// `constraints::lookup::table_vars`, which reads this for a range channel.
    pub const BITS: [u32; COUNT as usize] = [19, 16, 0, 0];

    /// Every channel's display name, indexed by channel.
    pub const NAMES: [&str; COUNT as usize] = ["timestamp", "range16", "generic", "decoder"];

    /// The widest lookup tuple any channel carries: `beta` powers exist for
    /// positions `0 .. MAX_TUPLE`, and `challenge_slot::LOOKUP_BETA_POWERS`
    /// has one slot per position above 0. The decoder's seven-column tuple is
    /// the widest built (`crates/program`'s `lookup_tuple`).
    pub const MAX_TUPLE: usize = 7;
}

/// The generic channel's table: its width and sub-table tags.
/// `crates/program`'s `lookup_tables` builds the table; its numbers live here
/// because a circuit, which cannot depend on `program`, names them.
/// `docs/spec/lookup.md` §9.
///
/// Every row is `(tag + 1, key, v1, v2)`, and the tag names its sub-table, so a
/// lookup's key is bounded by the sub-table it names and never by an
/// obligation of its own:
///
/// ```text
/// row 0                        the ZeroEntry, all zero
/// rows 1 ..= 2^16              AND:     (AND + 1,    a, b,       a & b)     a, b < 2^8
/// rows 2^16+1 ..= 2^17         SIGN:    (SIGN + 1,   h, h >> 15, 0)         h < 2^16
/// rows 2^17+1 ..= 2^17+64      POW:     (POW + 1,    s, 2^s as (lo, hi))    s < 64
/// rows 2^17+65 ..= 2^17+96     POW_W:   (POW_W + 1,  s, 2^s,     0)         s < 32
/// ```
pub mod generic_table {
    /// The table's tuple width: a tag, a key and two values.
    pub const WIDTH: usize = 4;

    /// The AND byte table: `(a, b, a & b)` over bytes.
    pub const AND: u32 = 0;

    /// `SIGN`: a halfword and its bit 15.
    pub const SIGN: u32 = 1;

    /// The 64-bit shift powers: an amount below 64 and `2^s` as a register's
    /// two words.
    pub const POW: u32 = 2;

    /// The 32-bit shift powers: an amount below 32 and `2^s`, the high word 0.
    /// A sub-table of its own so a W shift's amount is bounded below 32 by the
    /// tag it names (`docs/spec/mul-div.md` §2).
    pub const POW_W: u32 = 3;
}

/// The circuit families, by number. A family number is never reassigned.
///
/// A family is one arithmetization shape covering a set of program counters.
/// The number is what everything else cites: canonical ordering is ascending
/// `FamilyId`, the program-identity digest absorbs families in that order, and
/// shard transcripts are seeded with it. Ids 0–6 are the execution families
/// and 7–11 the window families (`docs/spec/circuits.md` §1); a delegation
/// family ([`crate::delegation`]) would follow them.
///
/// Which mnemonic each instruction family claims is `crates/program`'s
/// `row_kind`, and `docs/spec/program.md` §4 is the table.
pub mod family {
    /// `add`, `sub`, `addi`, `lui`, `auipc`, and the system row kind:
    /// `ecall`, `ebreak`, `fence`.
    pub const ADD_SUB_LUI_AUIPC: u32 = 0;
    /// `jal`, `jalr`, the six branches, `slt`, `sltu`, `slti`, `sltiu`.
    pub const JUMP_BRANCH_SLT: u32 = 1;
    /// `and`, `or`, `xor` and their immediate forms.
    pub const BITWISE: u32 = 2;
    /// The M extension, its W forms, and every shift: a product or a quotient
    /// by a power of two.
    pub const MUL_DIV: u32 = 3;
    /// `ld`, `sd`, `lw`, `lwu`, `sw`.
    pub const MEM_WORD: u32 = 4;
    /// `lb`, `lh`, `lbu`, `lhu`, `sb`, `sh`.
    pub const MEM_SUBWORD: u32 = 5;
    /// `lr`, `sc` and the nine AMOs, each in `.w` and `.d`.
    pub const ATOMICS: u32 = 6;
    /// Memory initialisation and teardown of RAM window 0, the image window:
    /// exactly one shard. Claims no pc; present in every `VmConfig`, at the
    /// height of [`ZERO_WINDOWS`]. `docs/spec/memory.md` §3.
    pub const INIT_TEARDOWN: u32 = 7;
    /// Memory initialisation and teardown of the zero-initialized RAM windows
    /// above window 0, one shard per window the execution touches. Claims no
    /// pc; present in every `VmConfig`, at the height of [`INIT_TEARDOWN`].
    /// `docs/spec/memory.md` §3.
    pub const ZERO_WINDOWS: u32 = 8;
    /// The **public input** window: the verifier-known input of the
    /// statement, at [`guest_memory::PUBLIC_INPUT_ORIGIN`]. Claims no pc,
    /// owns no cycle, and is in **every** `VmConfig` at
    /// [`PUBLIC_WINDOW_HEIGHT`], proving exactly one shard.
    ///
    /// Its init column is what the verifier holds to the statement's `input`;
    /// its teardown column is free, because a guest may overwrite its own
    /// input buffer (`docs/spec/public-values.md` §5).
    pub const PUBLIC_INPUT: u32 = 9;
    /// The **public output** window — the journal — at
    /// [`guest_memory::PUBLIC_OUTPUT_ORIGIN`]. In every `VmConfig` at
    /// [`PUBLIC_WINDOW_HEIGHT`], proving exactly one shard.
    ///
    /// Its init leaf is the **literal 0** of [`ZERO_WINDOWS`]' artifact, which
    /// is what stops a prover supplying the journal at timestamp 0 instead of
    /// storing it; its teardown column is what the verifier holds to the
    /// statement's `output` (`docs/spec/public-values.md` §5).
    pub const PUBLIC_OUTPUT: u32 = 10;
    /// The **advice** windows: prover-supplied initial values for the
    /// region at [`guest_memory::ADVICE_ORIGIN`], one shard per window, `k`
    /// of them counted from [`guest_memory::ADVICE_ORIGIN`] upward. In every
    /// `VmConfig` at the window height, with `k >= 0` shards.
    ///
    /// **Nothing binds its init column, by design.** Advice is what the
    /// prover chose; a guest owes a check of it against something public
    /// (`docs/spec/public-values.md` §6).
    pub const ADVICE_WINDOWS: u32 = 11;

    /// How many families this table defines.
    pub const COUNT: u32 = 12;

    /// The pinned height of [`PUBLIC_INPUT`] and [`PUBLIC_OUTPUT`].
    ///
    /// **Pinned by arithmetic, not by taste, and `2^12` is the ceiling.** A
    /// window's first address is `4 * height * window`, so the height is what
    /// places the windows, and both must sit in the hole
    /// `[0, guest_memory::RAM_ORIGIN)` that no RAM window family initializes —
    /// 64 KiB, and not a byte more without moving every program's load address.
    /// Two windows of `2^12` are `2 * 16 KiB` and land on
    /// [`guest_memory::PUBLIC_INPUT_ORIGIN`] = `0x8000` and
    /// [`guest_memory::PUBLIC_OUTPUT_ORIGIN`] = `0xC000`, ending flush against
    /// `RAM_ORIGIN`; `[0, 0x8000)` stays a hole, which is where the null
    /// dereference argument lives. `2^14` would need 128 KiB for two windows
    /// and leaves only window 0 in the hole — and window 0 initializes address
    /// 0, so a null dereference would balance. There is no step above this one.
    ///
    /// 16,380 payload bytes is what the geometry allows
    /// (`docs/spec/public-values.md` §9).
    ///
    /// The price is the verifier's step 10c, two 4,096-point multilinear
    /// evaluations — 4,095 `Fp2` multiplies, the first 2,048 by a base
    /// difference, and 49,152 live bytes a shard (`2^11` `Fp2` of fold scratch
    /// plus the 4,096 `u32` words of the window itself), 8,190 and 98,304
    /// across the two.
    pub const PUBLIC_WINDOW_HEIGHT: u32 = 1 << 12;

    /// [`PUBLIC_INPUT`]'s window id at [`PUBLIC_WINDOW_HEIGHT`].
    pub const PUBLIC_INPUT_WINDOW: u32 =
        crate::guest_memory::PUBLIC_INPUT_ORIGIN / (4 * PUBLIC_WINDOW_HEIGHT);
    /// [`PUBLIC_OUTPUT`]'s window id at [`PUBLIC_WINDOW_HEIGHT`].
    pub const PUBLIC_OUTPUT_WINDOW: u32 =
        crate::guest_memory::PUBLIC_OUTPUT_ORIGIN / (4 * PUBLIC_WINDOW_HEIGHT);

    /// Whether a family's rows are **execution cycles**, indexed by
    /// `FamilyId`.
    ///
    /// The seven instruction families own cycles; the window families own
    /// addresses — a RAM window's rows are words, not cycles
    /// (`docs/spec/memory.md` §3). A block's time-window rules apply to
    /// cycle-owning families alone (`docs/spec/proof.md` §8): only their
    /// shards partition an execution in time.
    pub const CYCLE_OWNING: [bool; COUNT as usize] = [
        true,  // ADD_SUB_LUI_AUIPC
        true,  // JUMP_BRANCH_SLT
        true,  // BITWISE
        true,  // MUL_DIV
        true,  // MEM_WORD
        true,  // MEM_SUBWORD
        true,  // ATOMICS
        false, // INIT_TEARDOWN
        false, // ZERO_WINDOWS
        false, // PUBLIC_INPUT
        false, // PUBLIC_OUTPUT
        false, // ADVICE_WINDOWS
    ];

    /// The trace-height menu, ascending: the heights the registries build
    /// circuits at.
    ///
    /// What closes a height to a family is a channel whose **table needs more
    /// variables**, not carrying a channel at all: `constraints::lookup::
    /// table_vars` is 19 for `TIMESTAMP` and 16 for `RANGE16`, while `GENERIC`
    /// and `DECODER` report **0** — their tables are setup columns rather than
    /// closed forms, so they raise the floor by nothing.
    /// `constraints::family_circuit` returns `None` below the widest table its
    /// channels declare, and nothing rests on the two zeros: every family
    /// reading `GENERIC` also carries `TIMESTAMP`, whose 19 puts it at `2^20`
    /// regardless.
    ///
    /// `2^12` is the two **public-value** families' and nothing else's: it is
    /// below every channel floor an execution family reaches, and a window
    /// family at `2^12` reaches `0x4000`, short of the public windows' end, so
    /// `verifier_core::window_height` refuses it.
    pub const HEIGHT_MENU: [u32; 5] = [1 << 12, 1 << 16, 1 << 18, 1 << 20, 1 << 22];

    /// The default trace height of every family, indexed by `FamilyId`.
    ///
    /// **No execution family defaults below `2^20`.** A circuit carrying a
    /// timestamp gap obligation needs `lookup_channel::BITS[TIMESTAMP] = 19`
    /// variables (`docs/spec/lookup.md` §3), and `2^20` is the first height
    /// of [`HEIGHT_MENU`] that has them, so it is the floor for every family
    /// that runs cycles.
    pub const DEFAULT_HEIGHTS: [u32; COUNT as usize] = [
        1 << 22, // ADD_SUB_LUI_AUIPC
        1 << 22, // JUMP_BRANCH_SLT
        1 << 22, // BITWISE
        1 << 20, // MUL_DIV
        1 << 22, // MEM_WORD
        1 << 22, // MEM_SUBWORD
        1 << 20, // ATOMICS
        1 << 22, // INIT_TEARDOWN
        1 << 22, // ZERO_WINDOWS
        1 << 12, // PUBLIC_INPUT, and it is the only admissible one
        1 << 12, // PUBLIC_OUTPUT, likewise
        1 << 22, // ADVICE_WINDOWS, at the window height
    ];

    /// The default `bytecode_size_words`: `2^20` words, a 4 MiB ceiling on the
    /// span from `RAM_ORIGIN` to the last file-backed byte of the image.
    pub const DEFAULT_BYTECODE_SIZE_WORDS: u32 = 1 << 20;

    /// The version of the decoded-table construction. Absorbed first into the
    /// program-identity sponge. Changing it re-registers every program.
    pub const CODE_VERSION: u32 = 1;
}

/// The bit positions of `family_extra_mask`, per family. A bit position is
/// never reassigned (`docs/spec/program.md` §6).
///
/// Every live row's mask is **one-hot**: exactly one bit is set, naming the
/// row's kind, which is its mnemonic — except the add/sub/lui/auipc family's
/// bit 0, the *system* row kind shared by `ecall`, `ebreak` and `fence`, whose
/// rows tell the three apart by the `imm` codes in [`system_code`]. A circuit
/// unpacks the mask into selector bits, and one-hotness then comes from the
/// decoded table's domain rather than from a constraint.
///
/// Within a family the bits are in canonical ascending order: ascending
/// `(opcode, funct3, funct7)` of the encoding, `funct5` for the atomics. The
/// system kind is pinned to bit 0 ahead of that order. The 64-bit-only forms
/// follow the forms they extend.
///
/// Bit [`IMM_NEGATIVE`] is the row's immediate's sign, not a kind.
pub mod extra_mask {
    /// The bit a live row sets when its immediate is negative: the instruction
    /// uses the 64-bit sign extension of the table's `imm` word, whose high
    /// word is `2^32 − 1` times this bit (`docs/spec/program.md` §6).
    pub const IMM_NEGATIVE: u32 = 31;

    /// `family::ADD_SUB_LUI_AUIPC`.
    pub mod add_sub_lui_auipc {
        pub const SYSTEM: u32 = 0;
        pub const ADDI: u32 = 1;
        pub const AUIPC: u32 = 2;
        pub const ADD: u32 = 3;
        pub const SUB: u32 = 4;
        pub const LUI: u32 = 5;
        pub const ADDIW: u32 = 6;
        pub const ADDW: u32 = 7;
        pub const SUBW: u32 = 8;
    }

    /// `family::JUMP_BRANCH_SLT`.
    pub mod jump_branch_slt {
        pub const SLTI: u32 = 0;
        pub const SLTIU: u32 = 1;
        pub const SLT: u32 = 2;
        pub const SLTU: u32 = 3;
        pub const BEQ: u32 = 4;
        pub const BNE: u32 = 5;
        pub const BLT: u32 = 6;
        pub const BGE: u32 = 7;
        pub const BLTU: u32 = 8;
        pub const BGEU: u32 = 9;
        pub const JALR: u32 = 10;
        pub const JAL: u32 = 11;
    }

    /// `family::BITWISE`.
    pub mod bitwise {
        pub const XORI: u32 = 0;
        pub const ORI: u32 = 1;
        pub const ANDI: u32 = 2;
        pub const XOR: u32 = 3;
        pub const OR: u32 = 4;
        pub const AND: u32 = 5;
    }

    /// `family::MUL_DIV`.
    pub mod mul_div {
        pub const MUL: u32 = 0;
        pub const MULH: u32 = 1;
        pub const MULHSU: u32 = 2;
        pub const MULHU: u32 = 3;
        pub const DIV: u32 = 4;
        pub const DIVU: u32 = 5;
        pub const REM: u32 = 6;
        pub const REMU: u32 = 7;
        pub const MULW: u32 = 8;
        pub const DIVW: u32 = 9;
        pub const DIVUW: u32 = 10;
        pub const REMW: u32 = 11;
        pub const REMUW: u32 = 12;
        pub const SLLI: u32 = 13;
        pub const SRLI: u32 = 14;
        pub const SRAI: u32 = 15;
        pub const SLLIW: u32 = 16;
        pub const SRLIW: u32 = 17;
        pub const SRAIW: u32 = 18;
        pub const SLL: u32 = 19;
        pub const SRL: u32 = 20;
        pub const SRA: u32 = 21;
        pub const SLLW: u32 = 22;
        pub const SRLW: u32 = 23;
        pub const SRAW: u32 = 24;
    }

    /// `family::MEM_WORD`.
    pub mod mem_word {
        pub const LW: u32 = 0;
        pub const SW: u32 = 1;
        pub const LD: u32 = 2;
        pub const SD: u32 = 3;
        pub const LWU: u32 = 4;
    }

    /// `family::MEM_SUBWORD`.
    pub mod mem_subword {
        pub const LB: u32 = 0;
        pub const LH: u32 = 1;
        pub const LBU: u32 = 2;
        pub const LHU: u32 = 3;
        pub const SB: u32 = 4;
        pub const SH: u32 = 5;
    }

    /// `family::ATOMICS`, ascending `funct5`, the `.w` forms and then the `.d`
    /// ones in the same order, bit `k + DOUBLE` being bit `k`'s `.d` form. `aq`
    /// and `rl` are not recorded: on a single hart they order nothing.
    pub mod atomics {
        pub const AMOADD_W: u32 = 0;
        pub const AMOSWAP_W: u32 = 1;
        pub const LR_W: u32 = 2;
        pub const SC_W: u32 = 3;
        pub const AMOXOR_W: u32 = 4;
        pub const AMOOR_W: u32 = 5;
        pub const AMOAND_W: u32 = 6;
        pub const AMOMIN_W: u32 = 7;
        pub const AMOMAX_W: u32 = 8;
        pub const AMOMINU_W: u32 = 9;
        pub const AMOMAXU_W: u32 = 10;
        /// How far a `.d` form's bit sits above its `.w` form's.
        pub const DOUBLE: u32 = 11;
        pub const AMOADD_D: u32 = AMOADD_W + DOUBLE;
        pub const AMOSWAP_D: u32 = AMOSWAP_W + DOUBLE;
        pub const LR_D: u32 = LR_W + DOUBLE;
        pub const SC_D: u32 = SC_W + DOUBLE;
        pub const AMOXOR_D: u32 = AMOXOR_W + DOUBLE;
        pub const AMOOR_D: u32 = AMOOR_W + DOUBLE;
        pub const AMOAND_D: u32 = AMOAND_W + DOUBLE;
        pub const AMOMIN_D: u32 = AMOMIN_W + DOUBLE;
        pub const AMOMAX_D: u32 = AMOMAX_W + DOUBLE;
        pub const AMOMINU_D: u32 = AMOMINU_W + DOUBLE;
        pub const AMOMAXU_D: u32 = AMOMAXU_W + DOUBLE;
    }

    /// The `imm` of a system row, which is how its one mask bit tells its
    /// three instructions apart. `ECALL` and `EBREAK` are their encodings'
    /// own `funct12`; `FENCE` is every fence, whatever its `pred`, `succ` and
    /// `fm`, because on one hart every fence is a no-op.
    pub mod system_code {
        pub const ECALL: u32 = 0;
        pub const EBREAK: u32 = 1;
        pub const FENCE: u32 = 2;
    }
}

/// The guest memory map.
///
/// RAM is the one region a program is loaded into. `crates/guest-sdk/apogee.ld`
/// states the same two numbers for the linker, and
/// `crates/constants/tests/memory.rs` holds it to these.
///
/// `crates/loader` refuses a `PT_LOAD` segment that does not lie inside this
/// window. Outside it a guest reaches only the two public windows and the
/// advice region, none of which is in the ELF, so a program that wants to be
/// loaded there is not a program this VM can run — and enforcing it also
/// bounds what a hostile ELF can make the loader allocate.
pub mod guest_memory {
    /// First addressable byte, and where `_start` is placed.
    pub const RAM_ORIGIN: u32 = 0x0001_0000;

    /// Length of the region. `RAM_ORIGIN + RAM_LENGTH` is the initial `sp`,
    /// and lands on `0x8000_0000` — a window of just under 2 GiB.
    pub const RAM_LENGTH: u32 = 0x7FFF_0000;

    /// The top of RAM the stack keeps for itself. guest-sdk's
    /// allocator never hands out a block reaching into the last
    /// `STACK_RESERVE` bytes below `RAM_ORIGIN + RAM_LENGTH`, nor one above
    /// the live `sp`. 8 MiB: a native main thread's default stack on Linux and
    /// macOS, so a program whose call depth fits on the host fits here. Not
    /// part of the linker's map — `apogee.ld` has no symbol for it — but a
    /// number the SDK and its documents agree on.
    pub const STACK_RESERVE: u32 = 0x0080_0000;

    /// First byte of the **public input** window: the verifier-known input a
    /// statement is about (`docs/spec/public-values.md` §2).
    ///
    /// No RAM window family initializes an address in `[0, RAM_ORIGIN)`:
    /// `INIT_TEARDOWN` masks RAM window 0's rows below `2^14` with
    /// `V[ram_live]` and `ZERO_WINDOWS` never claims window 0
    /// (`docs/spec/memory.md` §3.3). The two public windows claim the
    /// **whole** of that range above `0x8000` — `2^12` words each, ending
    /// flush against `RAM_ORIGIN` — which is what makes that height the
    /// ceiling, and `[0, 0x8000)` stays a hole: a null dereference is a read
    /// of a tuple nothing wrote, and cannot balance.
    ///
    /// The address is not a free choice either. A window's first address is
    /// `4 * height * window`, so at [`family::PUBLIC_WINDOW_HEIGHT`] this is
    /// exactly window [`family::PUBLIC_INPUT_WINDOW`], and the address-space
    /// tag stays [`address_space::RAM`]. That is what keeps the three
    /// memory-op families' address decomposition, their load path and their
    /// store path untouched: to `mem_word` a public value is an ordinary RAM
    /// word.
    pub const PUBLIC_INPUT_ORIGIN: u32 = 0x0000_8000;

    /// First byte of the **public output** window — the journal — the next
    /// window up from [`PUBLIC_INPUT_ORIGIN`].
    ///
    /// At [`family::PUBLIC_WINDOW_HEIGHT`] = `2^12` the pair is windows 2 and
    /// 3 and ends flush against [`RAM_ORIGIN`]: the range below `RAM_ORIGIN`
    /// holds exactly two public windows and no more.
    pub const PUBLIC_OUTPUT_ORIGIN: u32 = 0x0000_C000;

    /// Bytes in each public window: `4 * family::PUBLIC_WINDOW_HEIGHT`.
    pub const PUBLIC_WINDOW_BYTES: u32 = 4 * crate::family::PUBLIC_WINDOW_HEIGHT;

    /// How many payload bytes a public window carries.
    ///
    /// Word 0 of each window is the payload's **byte length**, which is what
    /// makes a proof bind a byte string rather than merely its zero-padded
    /// word vector: without it `[1, 2, 3]` and `[1, 2, 3, 0]` fill the same
    /// window and a prover picks whichever suits it
    /// (`docs/spec/public-values.md` §3).
    pub const PUBLIC_PAYLOAD_BYTES: u32 = PUBLIC_WINDOW_BYTES - 4;

    /// First byte of the **advice** region: prover-supplied witness data,
    /// read with ordinary loads (`docs/spec/public-values.md` §6).
    ///
    /// It sits above RAM rather than inside it, so it competes with no heap
    /// and no stack. The address-space tag is [`address_space::RAM`] here
    /// too: what makes an advice word advice is that its window family's init
    /// column is bound to nothing, not a tag a load would have to name.
    pub const ADVICE_ORIGIN: u32 = 0x8000_0000;

    /// Words the advice region spans: `[ADVICE_ORIGIN, 2^32)`, 2 GiB.
    pub const ADVICE_WORDS: u32 = 1 << 29;
}

/// The guest ecall ABI: its numbers, in one place.
///
/// **A number is assigned once.** A program's identity binds its ABI, and
/// redefining a number does not fail loudly — it quietly makes an old program
/// compute something else — so numbers here are never reused, exactly like
/// `transcript_tags`. A *retired* number is struck out and never reassigned:
/// **63 and 64**, POSIX `read` and `write`, and **0x0507 and 0x0508**, a
/// keccak-f round and four SHA-256 rounds, are retired
/// (`docs/spec/ecall-abi.md` §3).
///
/// An ecall carries its number in `a7`, its arguments in `a0`-`a5` and its
/// result in `a0`, with errors as a negated errno. **An Apogee guest is an
/// Apogee-SDK program, not a Linux one**: it has no file descriptors, no
/// streams and no I/O syscall at all. Its public input, its advice and its
/// journal are *memory the proof system binds* — ordinary loads and stores
/// against three fixed regions (`docs/spec/public-values.md`) — so the only
/// ecalls a guest issues are [`EXIT`] and the delegation calls, which are
/// exactly the provable ones. `docs/spec/ecall-abi.md` specifies the table.
pub mod ecall {
    /// Terminate. `a0` is the exit status; a nonzero status is a failed
    /// execution, which is still an execution and is reported rather than
    /// refused.
    ///
    /// The only ecall a guest may issue besides the delegation calls. Its
    /// number is 93, and nothing downstream reads any meaning into the value.
    pub const EXIT: u32 = 93;

    /// Linux `ENOSYS`. Every number but [`EXIT`] and the delegation calls
    /// returns `-ENOSYS` in `a0`: a number nobody has assigned, or a retired
    /// one (`docs/spec/ecall-abi.md` §4). Such a call executes and cannot be
    /// proved.
    pub const ENOSYS: u32 = 38;
}

/// The memory argument's address spaces (`docs/spec/execution-trace.md` §2).
///
/// A memory query names one of these, and the tag is the `AS` term of the
/// compressed tuple `gamma_M + AS + alpha_addr*ADDR + ...`. The tags are
/// nonzero on purpose: `(REG, x0, ts 0, value 0)` is a real initial tuple, and
/// with `REG = 0` it would be the all-zero tuple — the same reason the decoded
/// tables pad with `MINUS_ONE` rather than 0. A tag is never reassigned.
pub mod address_space {
    /// The 32 registers. A query's address is the register index, `0..32`,
    /// and its value a 64-bit register as two words: the one space whose tuples
    /// carry a high word (`docs/spec/memory.md` §1).
    pub const REG: u8 = 1;
    /// Guest RAM, word-granular. A query's address is the byte address of the
    /// 4-aligned word, so always a multiple of 4.
    pub const RAM: u8 = 2;
    /// The program counter: one address, `0`. Every cycle reads `pc` and
    /// writes `next_pc` here.
    pub const PC: u8 = 3;
}

/// The memory argument's clock and its own numbers.
///
/// Cycle `c` occupies timestamps `TS_STEP * c + delta` for the four in-cycle
/// slots `delta` in `0..TS_STEP`. Timestamp 0 is the initial write of every
/// address, so the first executed cycle is **cycle 1**: a cycle-0 pc query
/// would write at timestamp 0 and could not strictly follow the initial write
/// it reads. Every timestamp is below `2^TS_BITS`.
///
/// `docs/spec/execution-trace.md` §1 specifies the clock and
/// `docs/spec/memory.md` the rest.
pub mod memory {
    /// Timestamps per cycle, one per in-cycle slot.
    pub const TS_STEP: u64 = 4;
    /// The width of a timestamp, in bits.
    pub const TS_BITS: u32 = 38;

    /// The halting sentinel: the `next_pc` an exit row writes, and the pc's
    /// final value the verifier fixes. Odd, so no instruction's `next_pc` can
    /// be it, and below `guest_memory::RAM_ORIGIN`, so no decoded-table row
    /// claims it. `docs/spec/memory.md` §5.
    pub const HALT_PC: u32 = 1;

    /// A memory tuple's parts, in order: `AS`, added unweighted; then `ADDR`,
    /// `TS`, `VAL` and `VAL_HI`, weighted by `α_addr`, `α_ts`, `α_val` and
    /// `α_hi`. `VAL_HI` is a register's high word, absent from a `RAM` or `PC`
    /// tuple. `docs/spec/memory.md` §1.
    pub const PART_AS: usize = 0;
    /// The tuple's address part.
    pub const PART_ADDR: usize = 1;
    /// The tuple's timestamp part.
    pub const PART_TS: usize = 2;
    /// The tuple's value part.
    pub const PART_VAL: usize = 3;
    /// The tuple's high-word part: a register's bits 32–63.
    pub const PART_VAL_HI: usize = 4;

    /// The output-map position of every memory artifact's read root: the
    /// product of its read tuples. `docs/spec/memory.md` §1.
    pub const READ_ROOT: usize = 0;
    /// The output-map position of every memory artifact's write root.
    pub const WRITE_ROOT: usize = 1;

    /// Window 0's rows `y < 2^RAM_LIVE_BIT` lie below `RAM_ORIGIN`, which is
    /// `4 << RAM_LIVE_BIT`, and `ram_live` masks them. `docs/spec/memory.md`
    /// §3.1 and §3.3.
    pub const RAM_LIVE_BIT: u32 = 14;
}

/// The delegation ABI: an ecall that hands a fixed-width frame of RAM words to
/// a circuit other than the CPU's.
///
/// The ecall is one cycle of the requesting family, `a0` the frame's
/// word-aligned base. The work is one **invocation**: a row of the delegation
/// family, which reads and writes every frame word at the requesting cycle's
/// timestamp plus [`FRAME_DELTA`]. A delegation family claims no pc, so a
/// guest **declares** what it links: each SDK shim emits a record
/// ([`MARKER_MAGIC`], then the ecall number) and `program` puts exactly the
/// declared families in the `VmConfig`.
///
/// [`TYPES`] is the registry. A new delegation is a row here and one arm each
/// in `constraints::family_circuit` (its circuit, over
/// `constraints::delegation`'s frame), `emulator`'s `delegate` (the function),
/// `prover`'s `family_fill` (its witness) and a `guest_sdk` shim (the record
/// and the call).
pub mod delegation {
    /// The in-cycle slot of every frame access an invocation makes: 0.
    /// `(RAM, 0)` is a pair no query of `constraints::memory`'s frame holds.
    pub const FRAME_DELTA: u64 = 0;

    /// The in-cycle slot at which an invocation's anchor tuple is read back,
    /// the requesting row's slot 3: the invocation writes
    /// `(space, base, 0, 0)`, the request is to consume it and write
    /// `(space, base, 4·cycle + ANCHOR_DELTA, value)`, which the invocation
    /// reads, pairing the two one to one.
    ///
    /// **UNFINISHED: the request side.** The add/sub circuit holds every ecall
    /// row's `a7` to `EXIT` and has no delegation query, so its fill refuses a
    /// delegation's ecall row and no row meets either anchor leaf: an
    /// execution that delegates runs and traces, and is not provable.
    pub const ANCHOR_DELTA: u64 = 3;

    /// The eight bytes that open a declaration record.
    pub const MARKER_MAGIC: [u8; 8] = *b"APOGDEL1";

    /// A declaration record's length: [`MARKER_MAGIC`], then the declared
    /// ecall number as a little-endian `u32`.
    pub const MARKER_BYTES: usize = 12;

    /// Every delegation as `(family, ecall number, anchor space, frame
    /// words)`, ascending by family. The anchor space is a
    /// [`super::address_space`] tag of the delegation's own: not memory, but
    /// the space whose tuple pairs an invocation with the ecall that requested
    /// it ([`ANCHOR_DELTA`]). A row is never reassigned.
    ///
    /// **UNFINISHED: no delegation is registered.** The mechanism waits for
    /// its first row: the declaration scan in `program`, the dispatch in
    /// `emulator`, the invocation buffer in `trace`, the frame in
    /// `constraints::delegation`, its fill in `prover` and the call in
    /// `guest_sdk`.
    pub const TYPES: [(u32, u32, u8, usize); 0] = [];
}
