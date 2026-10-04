# The constraint-system manifest: every circuit, every column, every gate

> **What this page is.** An accounting document. The specs say *why*: `gkr.md` the engine,
> `memory.md` the memory argument, `lookup.md` the channels, `shard-proof.md` §8 the add/sub
> family, `jump-branch-slt.md` the jump/branch/slt family, `shift-bitwise.md` the shift and
> bitwise family, `mul-div.md` the M extension, `memory-ops.md` the three memory-op families.
> `delegation.md` the delegation ABI and the keccak-f family, and `recursion.md` the recursion
> format — its registry, its field memory and the five families only it holds. This page says
> *what exists*: every circuit `constraints::family_circuit` and
> `constraints::recursion_circuit` return; every committed and virtual column with its position,
> name, meaning and readers; every intermediate multilinear by layer and offset; and every gate
> with its formula. It gives columns and gates descriptive names and one-line purposes that the
> code does not carry, and puts beside each the identifiers that find it in the code: the
> `PolyAddress`, the artifact's own name for it, and the Rust constant or constructor that makes
> it.
>
> **Status: S-RECURSION.** All **eighteen** circuits of the base registry are registered:
> `ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT`, `SHIFT_BITWISE`, `MUL_DIV`, `MEM_WORD`, `MEM_SUBWORD`,
> `ATOMICS`, `INIT_TEARDOWN`, `ZERO_WINDOWS`, `KECCAK_F`, `POSEIDON2`, `FR_ARITH`,
> `PUBLIC_INPUT`, `PUBLIC_OUTPUT`, `ADVICE_WINDOWS`, S26's `MOD_MUL` (§18) and S26c's
> `SHA256_COMP` (§19) and `EC_ADD` (§20). `MOD_MUL` was the fourth delegation family and the
> first whose behaviour depends on a **selector** — one frame word names one of four fixed
> Ethereum fields, secp256k1's two and BN254's two, and the circuit supplies the modulus' limbs
> as literals. S26 carried that modulus as a witnessed operand instead; S26b removed it, which
> is what let the circuit state `a < m` and `b < m` (`delegation.md` §10.2). The EVM's `MULMOD`
> takes an arbitrary modulus and is **not** served here.
>
> **S-RECURSION adds a second registry.** `constraints::recursion_circuit` is the recursion
> format's (`recursion.md` §1.2): a statement is in that format exactly when its `VmConfig` holds
> `FIELD_WINDOWS`, and `VmConfig::circuit` then takes every circuit from it. It returns every
> family above byte for byte as `family_circuit` does but one — `ADD_SUB_LUI_AUIPC`, whose
> recursion form knows ten delegation types where the base form knows six (§3.11) — and it alone
> holds five more: the field memory's window family `FIELD_WINDOWS` (§21) and four delegation
> families over that memory, `FR_OP` (§22), `P2_FIELD` (§23), `FIELD_IO` (§24) and `FQ_OP`
> (§25). `family_circuit` returns `None` for all five at every height, and no base circuit's
> bytes moved. `FQ_OP` is the first delegation family to carry `TIMESTAMP`, at `2^20`.
>
> **S26c's two are the fifth and sixth delegation families, and they broke a rule this page
> stated in four places.** `EC_ADD` carries the `RANGE16` channel and `MOD_MUL` was re-shaped to
> carry it too, where "a delegation family carries no lookup channel" had been an invariant;
> `delegation.md` §10.3 is the amendment. What decides which channel a family can carry is its
> height against the channel's table: `RANGE16`'s and `XOR8`'s tables need sixteen variables
> and `TIMESTAMP`'s 19-bit table nineteen, which on this menu is `2^20`. So the two families at
> `2^8` carry no channel, and no base delegation family — at `2^8`, `2^16` or `2^18` — carries
> `TIMESTAMP`; the recursion registry's `FQ_OP`, at `2^20`, does (§25). The consequences reach
> §0.4, §0.5, §1.1, §1.2, §1.3 and §12.1, and the reshape moved every number in §18. `EC_ADD`
> is also the first family whose row is **one third** of the operation it serves: a complete
> point addition is three invocations glued by the frame, not by a bus. Every execution family
> the decoder routes to has a circuit and a fill, and no `FamilyId` in `constants::family` is
> without one. S21 added the
> first family that is **invoked rather than decoded** (§12) and, with it, the `deleg` memory
> query — the mirror a delegation request makes — which changed `ADD_SUB_LUI_AUIPC`'s frame, its
> shape and every relation number in §3. S-IO added the three **RAM window** families that carry
> an execution's public input, its public output and the prover's advice (§15, §16, §17), and one
> new artifact constructor, `memory::value_window_artifact`, shared by two of them; it changed no
> existing circuit, added no enforcing gate anywhere, and drew no new challenge. **S-STREAM
> raised the two public families' pinned height from `2^8` to `2^12`** and moved the journal's
> window from `0x8400` to `0xC000` with it, which moves no relation either: a height reaches a
> window artifact only through the halving phase, so §15's and §16's layer counts, root
> relations and artifact byte lengths moved and nothing else in them did (§15.1).
>
> **S26e rewrote `SHA256_COMP` (§19)**: four rounds and four schedule words a row, a compression
> sixteen invocations glued by the frame, every Boolean operation an `XOR8` obligation and no bit
> anywhere, at `2^18`. It is `KECCAK_F`'s S26d trade made a second time, and it changed no other
> circuit — `ADD_SUB_LUI_AUIPC`'s artifact bytes moved only because its request gate reads the
> new ecall number, `0x0508` (§1.2, §3).
>
> **The query table is seven entries, and §3 is rewritten over the narrower frame.** `read` (63)
> and `write` (64) are retired and their numbers burned (`ecall-abi.md` §4), so `arg1` and
> `arg2` — an ecall row's `a1` and `a2`, which only those two calls passed — became unreachable
> and were removed rather than kept as columns nothing can make nonzero; the table dropped from
> nine entries to seven and every other query kept its id (`memory.md` §2.1, §2.1 here).
> `ADD_SUB_LUI_AUIPC` lost a third query with them: its `ram` query was the ecall **transfer
> row's** alone, no instruction routed there touches memory, and an ecall is now exactly one
> cycle. Its frame is five queries, its layout is §3.3's throughout, three `mask = 0` gates went
> with the queries they refused, and the circuit is **five** row-wise lists deep again (§1.2,
> §1.3, §26 observation 2). **No other circuit changed**: the other six execution families' query
> lists are what they were, and their `M` and `W` indices are computed from their own `w`.
>
> **Descriptive, not normative.** Where this page and the code disagree, the registry is right
> and this page is wrong; where it and a spec disagree, the spec rules. The descriptive names
> are documentation only, as the artifact's own names are (`gkr.md` §4.2): no code reads either.
>
> **Kept current by rule.** A stage that adds or changes a circuit family updates its entry
> here in the same pull request (`prompts/00-master.md`, implementation rule 12). §27 is what an
> entry must hold.
>
> **Machine-derived.** Every count, position, name and formula below was read out of
> `family_circuit`'s artifacts, not off the source by eye. Appendix A's commands print the
> committed `n = 22` artifacts, against which every name, position and positional formula can be
> checked; the `n = 16`, `n = 18` and `n = 20` counts were read from `family_circuit` directly, and the
> §3.10 and §4.10 probes by a program over `family_circuit` and those two suites' `honest_rows`
> that is not committed. Each family's §x.9 shows a handful of the rows its suite holds to every
> gate, every range obligation and, from §4 on, both table channels in CI: ten of the seventeen
> in `crates/checker/tests/add_sub.rs`, nine of the 47 in `jump_branch_slt.rs`, nine of the 35
> in `shift_bitwise.rs` and nine of the 64 in `mul_div.rs`. §12 has no such table: a keccak row
> is 1,764 committed cells, so §12.9 is the chain of independent readings its suite carries
> instead — a whole permutation's 24 rows evaluated row-locally, and the round held to
> `emulator::keccak_round`, which is held to `tiny-keccak` twenty-four at a time.
> §7.9, §8.9 and §9.9 show instead
> rows of `guests/mem`'s own shards, as the three fills write them and as
> `crates/checker/tests/mem_fill.rs` holds them in CI, and name the hand-built catalogue each
> family's row suite carries beside them. §15, §16 and §17 have no such table either, for §10's
> and §11's reason — a window family has no enforcing gate, so there is no per-cell account to
> give — and what holds them in CI is `crates/checker/tests/public_values.rs`, which pins each
> family's shape, the layout of both public windows and of the advice region, and the equality
> of the prover's committed column with the verifier's own extension of the same bytes.
> §5.10, §6.10, §7.10, §8.10 and §9.10, unlike §3.10 and §4.10, are read from their suites'
> own committed tamper tables rather than from a probe. **§3.11 and §21–§25 were read from
> `recursion_circuit`'s artifacts**, written to files and dumped (Appendix A): none is committed
> as bytes, and `crates/constraints/tests/vectors/recursion.txt` pins each by its shape line and
> SHA-256.

---

## 0. Reading this page

### 0.1 Where the truth is

| what | where |
| --- | --- |
| the circuit a verifying key must carry | `constraints::family_circuit(family, trace_vars)` in the base format and `constraints::recursion_circuit(family, trace_vars)` in the recursion format, `VmConfig::circuit` choosing by whether the config holds `FIELD_WINDOWS`; both in `crates/constraints/src/lib.rs` |
| the add/sub circuit, and its recursion form | `constraints::add_sub::{artifact, channels, recursion_artifact, recursion_channels}`, `crates/constraints/src/add_sub.rs` |
| the jump/branch/slt circuit | `constraints::jump_branch_slt::{artifact, channels}`, `crates/constraints/src/jump_branch_slt.rs` |
| the shift/bitwise circuit | `constraints::shift_bitwise::{artifact, channels}`, `crates/constraints/src/shift_bitwise.rs` |
| the mul/div circuit, and its width seam | `constraints::mul_div::{artifact, channels, arithmetic_gates}`, `crates/constraints/src/mul_div.rs` |
| the word load/store circuit | `constraints::mem_word::{artifact, channels}`, `crates/constraints/src/mem_word.rs` |
| the sub-word circuit, and its width seam | `constraints::mem_subword::{artifact, channels, splice_gates}`, `crates/constraints/src/mem_subword.rs` |
| the atomics circuit | `constraints::atomics::{artifact, channels}`, `crates/constraints/src/atomics.rs` |
| the is-zero and comparison gadgets | `constraints::gadgets::{is_zero, comparison, comparison_equation}`, `crates/constraints/src/gadgets.rs` |
| the frame, the memory tuples, the **four** window circuits | `constraints::memory::{image_window_artifact, zero_window_artifact, value_window_artifact, field_window_artifact}`, `crates/constraints/src/memory.rs` |
| the delegation circuits | `constraints::{keccak, poseidon2, fr_arith, mod_mul, sha256, ec_add}::{artifact, channels}`, and the recursion registry's `constraints::{fr_op, p2_field, field_io, fq_op}::{artifact, channels}`, each in `crates/constraints/src/<module>.rs`; the frame, the anchor and the field accesses they share, `constraints::delegation` (`read_only_frame_range16`, `leaves_with`, `Access`) |
| the fraction trees and their denominators | `constraints::lookup`, `crates/constraints/src/lookup.rs` |
| the layer assembly: reduction, halving, the names of inner nodes | `crates/constraints/src/build.rs`, `assemble` |
| a circuit, printed | `cargo run -p checker -- dump <artifact>` (Appendix A) |
| the columns' values | `trace::{build_memory_columns, build_frame_witness, build_init_teardown_columns, build_value_window_columns, build_multiplicities}` and `prover::family_fill`, `crates/prover/src/fill.rs`; the packed generic table, `program::lookup_tables::generic_table`; the two public windows' and the advice region's layouts, `verifier_core::public_io_words` and `trace::advice_word`; the recursion registry's, `fill::field_window` over `trace::MemoryState::field_cell`, and `fill::{fr_op, p2_field, field_io, fq_op}` over the shared `fill::recursion_frame` |
| the copower check every scaled bound must pass | `constraints::lookup::check_copowers`, `crates/constraints/src/lookup.rs` |

### 0.2 Notation

- **Addresses** are `PolyAddress` in its `Display` form (`gkr.md` §2): `M[i]` a memory-argument
  column, `W[i]` a witness column, `S[i]` a setup column, `V[kind]` a virtual table, `L{k}[j]`
  column `j` of inner layer `k`, `scratch[i]` its alias in the flat list. `C{k}[j]` appears
  nowhere: no registered circuit has a cached entry.
- **Gate list `k`** reads layer `k` and writes layer `k + 1`. Layer 0 is the committed columns,
  `M` then `W` then `S`, plus the virtual tables. The top layer `N` holds the outputs and has no
  gate list.
- **Relation `r`** is entry `r` of `CircuitArtifact::relations`, the flat list.
  `build::assemble` numbers relations list by list, producing gates before enforcing ones. A
  producing gate's relation is named `define_<node>`, and `<node>` is the scratch bijection's
  name for the column it writes. An enforcing gate's relation name is the gate's name.
- **Every producing gate** is `L{k+1}[j](x) = Σ_y eq(x, y)·G(inputs at y)` and **every
  enforcing gate** is `0 = G(inputs at y)` for every row `y`. This page writes only `G`. A
  halving gate reads each operand at both children, `x(y,0)` and `x(y,1)`; the child bit is
  layer `k`'s highest variable (`gkr.md` §1).
- **Literals** are integers in Fr, `−c` being `p − c`. `2^32`, `2^19` and `2^16` are those
  integers. `checker dump` prints a literal below `2^32` in decimal, and `p − k` for
  `0 < k < 2^32` as `-k`, so `−2^19` reads `-524288`. Every other literal is `0x` and 64 hex
  digits, so `2^32` reads `0x00…0100000000` and `−2^32` reads `0x30644e72…f592f0000001` there.
- **Positional form** is a gate as stored, term by term; `×k` marks a term the constructor
  repeats `k` times, because a coefficient is one literal or one challenge and `4·α_ts` is
  neither (`memory.md` §1). **Named form** replaces each `M`, `W`, `S` and inner address by
  its artifact name and merges the repeats. A virtual table's artifact name is the word in its
  address (`V[ram_live]` is `ram_live`): §3's, §4's, §5's and §6's tables keep the address form,
  §10, §11 and §15–§17 write the bare word.
- **`n`** is the circuit's `trace_vars`: a shard has `h = 2^n` rows, and RAM window `w` starts
  at byte address `4h·w`.

### 0.3 What row `y` of a column is

Columns of one layer do not all index the same thing.

| column | row `y` is |
| --- | --- |
| an execution family's `M` and `W` columns, multiplicities excepted | the shard's `y`-th cycle of that family, in execution order; rows past the last are **padding**, every cell 0 in an honest fill |
| a multiplicity column | row `y` of its channel's **table**: how many of the shard's gated tuples equal that row, counted on the lowest row holding a repeated tuple (`lookup.md` §7) |
| a decoded-table `S` column | the halfword at pc `2y`; `MINUS_ONE` in every column where no instruction of the family starts (`crates/program/CLAUDE.md`) |
| a generic-table `S` column (`JUMP_BRANCH_SLT`'s, `SHIFT_BITWISE`'s and `MEM_SUBWORD`'s `S[7..10]`, `MUL_DIV`'s and `ATOMICS`' `S[6..9]`) | row `y` of the packed table (`lookup.md` §9): row 0 the `ZeroEntry`, all 0; rows 1 to `2^16` the AND byte table's `(AND_BASE + a + 1, b, a & b)`; rows `2^16 + 1` to `2^17` `U16GetSign`'s `(SIGN_BASE + h + 1, h >> 15, 0)`; rows `2^17 + 1` to `2^17 + 32` S18's `ShiftPowers`, `(SHIFT_BASE + s + 1, 2^s, 2^(31 − s))`; every later row 0. `AND_BASE = 0`, `SIGN_BASE = 256` and `SHIFT_BASE = SIGN_BASE + 2^16` are `constants::generic_table`'s, so the three key ranges are pairwise disjoint |
| `V[range19]`, `V[range16]` | the value `y mod 2^19`, `y mod 2^16` |
| a RAM window family's `M` columns, `S[0]`, `V[row]`, `V[ram_live]` | the RAM word at byte address `4h·w + 4y`, `w` being the shard's window: 0 for `INIT_TEARDOWN`, the statement's `windows[i]` for `ZERO_WINDOWS`, the constants 32 and 33 for the two public families, and `advice_first_window(h) + i` for `ADVICE_WINDOWS` (§10, §11, §15, §16, §17) |
| `FIELD_WINDOWS`' `M` columns and `V[row]` | field cell `h·w + y` of `address_space::FIELD`, `w` being the shard's index: the windows are consecutive from cell 0 (§21) |

### 0.4 The challenges

`constants::challenge_slot`. A coefficient naming a slot reads the value below. `checker dump`
prints a slot by `challenge_slot::NAMES`, its constant in lower case (`mem_gamma`,
`mem_window_constant`, `lookup_g`, `lookup_beta_2`, `lookup_decoder_neutral`); the symbols are
this page's.

| slot | constant | symbol | value | set by | read by |
| --- | --- | --- | --- | --- | --- |
| 0 | `TOY` | — | — | — | S13's toy only |
| 1 | `MEM_GAMMA` | `γ_M` | drawn once per statement | G10 (`shard-proof.md` §2) | frame leaves; every delegation family's real memory leaves — §12's 102, and in the recursion registry `FR_OP`'s 16, `P2_FIELD`'s 28, `FIELD_IO`'s 26 and `FQ_OP`'s 36 |
| 2 | `MEM_ALPHA_ADDR` | `α_addr` | drawn | G10 | frame leaves; every window tuple of all **six** window families, four `(α_addr, V[row])` terms a tuple in the five RAM ones and one in `FIELD_WINDOWS`'; every delegation family's real memory leaves, as slot 1's, `P2_FIELD`'s, `FIELD_IO`'s and `FQ_OP`'s address offsets riding repeated `(α_addr, mask)` terms |
| 3 | `MEM_ALPHA_TS` | `α_ts` | drawn | G10 | frame leaves, window teardown tuples; §12's invocation leaves **but `write_anchor`**, whose timestamp is the literal 0, and every other delegation family's real leaves but its `write_anchor` likewise — 15 in `FR_OP`, 27 in `P2_FIELD`, 25 in `FIELD_IO` and 35 in `FQ_OP` |
| 4 | `MEM_ALPHA_VAL` | `α_val` | drawn | G10 | frame leaves; window tuples carrying a value — every teardown tuple, `INIT_TEARDOWN`'s `α_val·S[0]` init tuple, and `PUBLIC_INPUT`'s and `ADVICE_WINDOWS`' `α_val·M[2]` init tuple, but **not** the init tuple of `ZERO_WINDOWS`, `PUBLIC_OUTPUT` or `FIELD_WINDOWS`, whose value is the literal 0; §12's invocation leaves **but `write_anchor`**, whose value is the literal 0, and every other delegation family's likewise — 15 in `FR_OP`, 27 in `P2_FIELD`, 25 in `FIELD_IO` and 35 in `FQ_OP` |
| 5 | `MEM_WINDOW_CONSTANT` | `WC` | derived per window shard: `γ_M + 2 + α_addr·4h·w` for a RAM window (2 is `address_space::RAM`), and `γ_M + 10 + α_addr·h·w` for a `FIELD_WINDOWS` shard (10 is `address_space::FIELD`, `w` the shard's index) | `gkr_verify::window_challenges`, and `gkr_verify::field_window_challenges` for `FIELD_WINDOWS`, off the window `verifier_core::shard_challenges` names for the shard's family | window tuples |
| 6 | `LOOKUP_G` | `g` | drawn per shard | S4 (`shard-proof.md` §4) | every table denominator, and every lookup row denominator except `decode_row`'s (a pad denominator is the literal 1) |
| 7 | `LOOKUP_BETA` | `β` | drawn per shard, after `g` | S4 | every circuit's decoder denominators; and every generic denominator of the **five** circuits that read that channel — its table's, jump/branch/slt's two sign lookups', shift/bitwise's sign lookup, `shift_powers` and four `and_byte_j`, mul/div's two sign lookups, mem_subword's one sign lookup, atomics' two sign lookups and four `and_byte_j`. Not `MEM_WORD`'s: it reads no generic channel |
| 8 | `LOOKUP_BETA_2` | `β²` | derived: a power of `β` | `gkr_verify::insert_lookup_challenges` | every circuit's decoder denominators; the generic **table**'s denominator in all five that carry it; and of the generic lookups only those whose third tuple position is a column — shift/bitwise's `shift_powers` (`copow`) and its four `and_byte_j` (`byte_and_j`), and atomics' four `and_byte_j`. A sign lookup's third position is the constant 0 and adds no term |
| 9–11 | `LOOKUP_BETA_3` … `LOOKUP_BETA_5` | `β³` … `β⁵` | derived: powers of `β` | `insert_lookup_challenges` | every circuit's two decoder denominators |
| 12 | `LOOKUP_BETA_6` | `β⁶` | derived: a power of `β` | `insert_lookup_challenges` | the decoder denominators of add/sub, jump/branch/slt, shift/bitwise, mem_word and mem_subword, whose tuples are seven wide. **Not mul/div's and not atomics'**: each of those decoded tuples has no `imm` and is six wide (§6.1, §9.1) |
| 13 | `LOOKUP_DECODER_NEUTRAL` | `g_dec` | derived: `g − Σ_{j<W} β^j`, `W` the artifact's own decoder tuple width — 7 in add/sub, jump/branch/slt, shift/bitwise, mem_word and mem_subword, **6 in mul/div and atomics** | `insert_lookup_challenges` | `decode_row`'s denominator |

**Eight circuits read no lookup challenge at all** — no `g`, no `β`, no derived power, no
neutral: the six window families — the base registry's five and the recursion registry's
`FIELD_WINDOWS`, which like `ZERO_WINDOWS` reads exactly slots 2 to 5 — and `POSEIDON2` and
`FR_ARITH`, and for opposite reasons. A window family has no witness to bound; a delegation
family at `2^8` has no table to bound one against, so every bound it makes is a bit
decomposition. **`MOD_MUL` was among them until S26c, `KECCAK_F` until S26d and `SHA256_COMP`
until S26e**, and none is now (§18.1, §12.1, §19).

**Eight delegation families now read `g`, four in each registry's own list.** S26c gave
`MOD_MUL` and `EC_ADD` the `RANGE16` channel at `2^16` (`docs/spec/delegation.md` §10.3), S26d
gave `KECCAK_F` both `RANGE16` and `XOR8` (§10.4), and S26e gave `SHA256_COMP` the same two
(§10.5); the recursion registry's four field families carry range channels alone — `RANGE16`
in `FR_OP`, `P2_FIELD` and `FIELD_IO`, and `TIMESTAMP` and `RANGE16` in `FQ_OP` (§22.6, §23.7,
§24.6, §25.7). A range channel's tuple is **one expression wide**, so a family carrying range
channels alone reads slot **6** (`g`) and **no `β` slot at all** — `β⁰` is the literal 1 and not
a challenge, `β¹` upward belongs to tuples wider than one, and the decoder neutral is a table
channel's. So **eleven** of the base registry's eighteen circuits read `g`: the seven execution
families, `MOD_MUL`, `EC_ADD`, `KECCAK_F` and `SHA256_COMP`. The recursion registry's
twenty-three families read it in **fifteen**: the same eleven, `ADD_SUB_LUI_AUIPC`'s recursion
form (§3.11) standing in for the base one, and `FR_OP`, `P2_FIELD`, `FIELD_IO` and `FQ_OP`;
counted as distinct artifacts, sixteen circuits read `g`. **`FQ_OP` is the one circuit that
carries `TIMESTAMP` and reads no `β`**: every other circuit carrying that channel is an execution
family, and every execution family carries the decoder channel besides.

**`KECCAK_F` and `SHA256_COMP` are the only circuits that read `β¹` and `β²` without reading
`β³`.** Their `XOR8` tuple is three wide, so the two slots are its obligations' second and third
positions — 1,020 in `KECCAK_F`, 336 in `SHA256_COMP` — and nothing else in either artifact
touches them; the decoder neutral is absent, neither family having a decoder channel. Their pad
leaves and `write_anchor` leaves read no challenge past `γ_M`, and their enforcing gates — 385
and 119 — read none at all.

### 0.5 The gate shapes

`GateDef` (`crates/constraints/src/lib.rs`, and `constraints::CATALOGUE`, the same seven rows);
`gkr_verify::eval_gate` evaluates every one. Counts are over one circuit at `n = 20`, except
`KECCAK_F`'s, `SHA256_COMP`'s, `P2_FIELD`'s and `FIELD_IO`'s, which are at `n = 18`, and
`MOD_MUL`'s and `EC_ADD`'s, which are at `n = 16`. `ADD_SUB_LUI_AUIPC`'s recursion form (§3.11)
is the base form's count in every tag but 5.

| tag | shape | `G` | list kind | used by |
| --- | --- | --- | --- | --- |
| 0 | `Linear { terms, constant }` | `Σ c_i·x_i + c_0` | row-wise | add/sub, 58: 43 leaves of list 0 (the **6** memory pads, the 15 leaf numerators, the 3 table numerators and 3 table denominators, the 16 pad-fraction columns), 5 degree-1 enforcing gates, 10 copies in lists 2–4; jump/branch/slt, 71: 54 leaves of list 0 (the 26 leaf numerators, 4 of tables and 22 of lookups, the 4 table denominators, the 24 pad-fraction columns), 3 degree-1 enforcing gates, 14 copies in lists 2–4; shift/bitwise, 108: 77 leaves of list 0 (the 43 leaf numerators, 4 of tables and 39 of lookups, the 4 table denominators, the 30 pad-fraction columns), 9 degree-1 enforcing gates, 22 copies in lists 2–5; mul/div, 108: 81 leaves of list 0 (the 31 leaf numerators, 4 of tables and 27 of lookups, the 4 table denominators, the 46 pad-fraction columns), 5 degree-1 enforcing gates, 22 copies in lists 2–5; mem_word, 54: 38 leaves of list 0 (the 4 memory pads, the 21 leaf numerators, 3 of tables and 18 of lookups, the 3 table denominators, the 10 pad-fraction columns), 6 degree-1 enforcing gates, 10 copies in lists 2–4; mem_subword, 100: 72 leaves of list 0 (the 4 memory pads, the 40 leaf numerators, the 4 table denominators, the 24 pad-fraction columns), 6 degree-1 enforcing gates, 22 copies in lists 2–5; atomics, 113: 86 leaves of list 0 (the **6** memory pads, the 40 leaf numerators, the 4 table denominators, the 36 pad-fraction columns), 9 degree-1 enforcing gates, 18 copies in lists 2–5; `ZERO_WINDOWS`, `PUBLIC_INPUT`, `PUBLIC_OUTPUT`, `ADVICE_WINDOWS` and `FIELD_WINDOWS`, 2 unmasked leaves each; **keccak, 1,673**: 1,354 in list 0 (24 pad leaves, the two tables' numerators and denominators, the 1,230 lookup numerators, and the 96 pad-fraction columns), 307 degree-1 enforcing gates, and 12 copies over lists 8–11, where the memory and `range16` trees are already at one node. It was 170,248 at S21, almost all of it state copies through 168 round layers; **`SHA256_COMP`, 929 at `n = 18`**: 842 in list 0 (12 pad leaves, the two tables' numerators and denominators, the 450 lookup numerators, and the 376 pad-fraction columns), 75 degree-1 enforcing gates, and 12 copies over lists 6–9 — it was 7,224 at S26c, its bits' recompositions; **`MOD_MUL`, 824** and **`EC_ADD`, 3,185**, each the sum of its leaves, its degree-1 enforcing gates and the copies its reduction lists carry (§18.1, §20.1); in the recursion registry, **`FR_OP`, 107**: 92 in list 0 (the table's numerator and denominator, the 36 lookup numerators and the 54 pad-fraction columns — no memory pad leaf, its eight leaves a side filling both trees), 9 degree-1 enforcing gates, and 6 copies over lists 4–6, where both memory trees are already at one node; **`P2_FIELD`, 84 at `n = 18`**: 74 in list 0 (the 4 memory pads, the table's numerator and denominator, the 58 lookup numerators and the 10 pad-fraction columns), 6 degree-1 enforcing gates (`writes_back_w0`–`w4` and `n_word`), and 4 copies over lists 5–6; **`FIELD_IO`, 203 at `n = 18`**: 192 in list 0 (the 6 memory pads, the table's numerator and denominator, the 70 lookup numerators and the 114 pad-fraction columns), 5 degree-1 enforcing gates, and 6 copies over lists 5–7; **`FQ_OP`, 150**: 140 in list 0 (the 28 memory pads, the two tables' numerators and denominators, the 80 lookup numerators and the 28 pad-fraction columns), 6 degree-1 enforcing gates, and 4 copies in list 6, where the two product trees and the `timestamp` tree are already at one node |
| 1 | `Product { coeff, left, right }` | `c·x·y` | row-wise | add/sub, 37: the 14 row-wise product-tree nodes (lists 1–3) and the 23 row-wise fraction-node denominators (lists 1–4); jump/branch/slt, 40: the 6 row-wise product-tree nodes (lists 1–2) and the 34 row-wise fraction-node denominators (lists 1–4); shift/bitwise, 59: the 6 product-tree nodes (lists 1–2) and the 53 fraction-node denominators (lists 1–5); mul/div, 56: the 6 product-tree nodes and the 50 fraction-node denominators; mem_word, 37: the 14 row-wise product-tree nodes (lists 1–3) and the 23 fraction-node denominators (lists 1–4); mem_subword, 62: the 14 product-tree nodes and the 48 fraction-node denominators (lists 1–5); atomics, 68: the 14 product-tree nodes and the 54 fraction-node denominators; **keccak, 1,404**: the 126 product-tree nodes that reduce 128 memory leaves to 2 over lists 2–7, and the 1,278 row-wise fraction-node denominators of its two channels over lists 2–11 — 255 for `range16` and 1,023 for `xor8`. It had **no fraction node at all** at S21 and 38,400 `v = B'·B'` gates of chi's first step instead; one round a row moved every one of those into an `XOR8` obligation; **`SHA256_COMP`, 700**: the 62 memory product-tree nodes over lists 1–5 and the 638 row-wise fraction-node denominators of its two channels over lists 1–9 — 127 for `range16` and 511 for `xor8`. It was 9,278 at S26c, 9,216 of them the `x·y` helper of a three-way XOR **bit**, and S26e moved every one of those into an `XOR8` obligation; **`MOD_MUL`, 573** and **`EC_ADD`, 2,301**; in the recursion registry, **`FR_OP`, 77**: the 14 product-tree nodes that reduce eight leaves a side to one over lists 1–3, and the 63 row-wise fraction-node denominators of its `range16` tree over lists 1–6; **`P2_FIELD`, 93**: the 30 product-tree nodes that reduce 16 leaves a side to one over lists 1–4, and its one channel's 63 row-wise fraction-node denominators over lists 1–6; **`FIELD_IO`, 157**: the 30 product-tree nodes over lists 1–4 and the 127 row-wise fraction-node denominators over lists 1–7; **`FQ_OP`, 156**: the 62 product-tree nodes over lists 1–5 and the 94 row-wise fraction-node denominators over lists 1–6 — 31 for `timestamp` and 63 for `range16` |
| 2 | `MaskIntoIdentity { input, mask }` | `x·m + 1 − m` | row-wise | no registered circuit (`memory.md` §2.2 says why) |
| 3 | `AffineProduct { .. }` | `(Σ a_i·x_i + a_0)·(Σ b_j·y_j + b_0)` | row-wise | no registered circuit |
| 4 | `TreeProduct { input }` | `x(y,0)·x(y,1)` | halving | add/sub, 5 per halving list (100, `n = 20`); jump/branch/slt, 6 per halving list (120); shift/bitwise and mul/div, 6 per halving list (120 each); mem_word, 5 per halving list (100); mem_subword and atomics, 6 per halving list (120 each); **each of the six window circuits, 2 per halving list** — 40 at `n = 20`, `FIELD_WINDOWS`' default, 44 at `n = 22` and 24 at the two public families' pinned `n = 12`, where S-IO's `2^8` gave 16; **keccak and, since S26e, `SHA256_COMP`, 4 per list (72 each at `n = 18`)** — the two memory roots and the two channels' denominators; **`MOD_MUL` and `EC_ADD`, 3 per list** (48 each at `n = 16`) — the two memory roots and the `RANGE16` tree's **denominator**, which is what a fourth output costs; in the recursion registry, **`FR_OP`, `P2_FIELD` and `FIELD_IO`, 3 per list** (60 at `FR_OP`'s `n = 20`, 54 each at the other two's `n = 18`) — the two memory roots and the `RANGE16` tree's denominator — and **`FQ_OP`, 4 per list** (80 at `n = 20`) — the two memory roots and the two channels' denominators |
| 5 | `Quadratic { constant, linear, products }` | `c_0 + Σ a_i·x_i + Σ b_j·y_j·z_j` | row-wise | add/sub, 106: **10** memory leaves and 15 lookup row denominators (list 0), 58 degree-2 enforcing gates, and the 23 row-wise fraction-node numerators (lists 1–4); jump/branch/slt, 103: 8 memory leaves and 22 lookup row denominators (list 0), 39 degree-2 enforcing gates, and the 34 row-wise fraction-node numerators (lists 1–4); shift/bitwise, 139: 8 memory leaves and 39 lookup row denominators (list 0), 39 degree-2 enforcing gates, and the 53 fraction-node numerators (lists 1–5); mul/div, 134: 8 memory leaves and 27 lookup row denominators, 49 degree-2 enforcing gates, and the 50 fraction-node numerators; mem_word, 80: 12 memory leaves and 18 lookup row denominators (list 0), 27 degree-2 enforcing gates, and the 23 fraction-node numerators (lists 1–4); mem_subword, 143: 12 memory leaves and 36 lookup row denominators, 47 degree-2 enforcing gates, and the 48 fraction-node numerators (lists 1–5); atomics, 137: 10 memory leaves and 36 lookup row denominators, 37 degree-2 enforcing gates, and the 54 fraction-node numerators; `INIT_TEARDOWN`, 2 leaves — **the only window circuit with a `Quadratic` gate**, the other five being unmasked and degree 1 throughout; **keccak, 2,690**: 1,334 in list 0 (the 104 real memory leaves — 51 frame words and the anchor, a side — and the 1,230 lookup row denominators), 78 degree-2 enforcing gates (`live_boolean`, the 51 `addr_w`, the two frame-pointer checks and the 24 `round{r}_boolean`), and the 1,278 row-wise fraction-node numerators over lists 2–11. **There is no `gap_w{j}` gate**: the gap is four `RANGE16` obligations since S26d. It was 149,735 at S21; **`SHA256_COMP`, 1,184**: 502 in list 0 (the 52 real memory leaves — 25 frame words and the anchor, a side — and the 450 lookup row denominators), 44 degree-2 enforcing gates, and the 638 row-wise fraction-node numerators over lists 1–9; it was 8,569 at S26c. **`MOD_MUL`, 908** and **`EC_ADD`, 3,859**, each its real memory leaves, its lookup row denominators, its degree-2 enforcing gates and its fraction-node numerators; in the recursion registry, add/sub's recursion form, **118**: the base form's 106 and the twelve degree-2 gates its four more delegation types add (§3.11); **`FR_OP`, 150**: 52 in list 0 (the 16 memory leaves — four frame words, the anchor and three field accesses, a side — and the 36 lookup row denominators), 35 degree-2 enforcing gates, and the 63 row-wise fraction-node numerators over lists 1–6; **`P2_FIELD`, 515**: 86 in list 0 (the 28 real memory leaves — 14 a side — and the 58 lookup row denominators), 366 degree-2 enforcing gates (the 352 permutation gates and 14 of the 20 frame and absorption gates), and the 63 row-wise fraction-node numerators over lists 1–6; **`FIELD_IO`, 242**: 96 in list 0 (the 26 real memory leaves — 13 a side — and the 70 lookup row denominators), 19 degree-2 enforcing gates, and the 127 row-wise fraction-node numerators over lists 1–7; **`FQ_OP`, 242**: 116 in list 0 (the 36 real memory leaves — four frame words, the anchor and 13 field accesses, a side — and the 80 lookup row denominators), 32 degree-2 enforcing gates, and the 94 row-wise fraction-node numerators over lists 1–6 |
| 6 | `TreeCross { left, right }` | `p(y,0)·q(y,1) + p(y,1)·q(y,0)` | halving | **keccak and `SHA256_COMP`, 2 per halving list** (36 each at `n = 18`), one per channel — each had none until a stage gave it two channels (S26d and S26e), a circuit with no lookup channel having no fraction tree and this shape being a fraction tree's alone; **`MOD_MUL` and `EC_ADD`, 1 per halving list** (16 each at `n = 16`) — their one `RANGE16` tree's numerator, and the shape that makes a delegation family with a channel visible in this table at all (S26c); add/sub, 3 per halving list (60, `n = 20`); jump/branch/slt, 4 per halving list (80); shift/bitwise and mul/div, 4 per halving list (80 each); mem_word, 3 per halving list (60); mem_subword and atomics, 4 per halving list (80 each); in the recursion registry, **`FR_OP`, `P2_FIELD` and `FIELD_IO`, 1 per halving list** (20 at `FR_OP`'s `n = 20`, 18 each at the other two's `n = 18`) — their one `RANGE16` tree's numerator — and **`FQ_OP`, 2 per halving list** (40 at `n = 20`), one per channel |

### 0.6 The compound expressions

**The memory tuple** (`memory.md` §1), parts in `constants::memory::PART_{AS, ADDR, TS, VAL}`
order. Its code is the private `memory::tuple`, and its read side `memory::read_tuple`: an
unmasked `Linear` that carries `AS` as the term `(AS, m)` and a write's `Δ` as `(α_ts, m) ×Δ`,
so it is `T` only at `m = 1`.

```text
T(AS, ADDR, TS, VAL) = γ_M + AS + α_addr·ADDR + α_ts·TS + α_val·VAL
```

**A frame leaf** (`memory.md` §2.2) for query `q` with mask `m`, address space `AS_q` and slot
delta `Δ_q`; code: the private `memory::leaf` over `tuple`:

```text
read_<q>  = m·T(AS_q, <q>_addr, <q>_read_ts,        <q>_read_value)  + 1 − m
write_<q> = m·T(AS_q, <q>_addr, 4·cycle + Δ_q,      <q>_write_value) + 1 − m
```

Each is stored as one `Quadratic` with constant 1: linear terms `(γ_M, m)`, `(−1, m)`,
`(AS_q, m)`, and on the write side `(α_ts, m) ×Δ_q`; products `(α_addr, addr, m)`, then
`(α_ts, read_ts, m)` or `(α_ts, cycle, m) ×4`, then `(α_val, value, m)`. The stored polynomial
is `m·T + 1 − m` at every `m`, but it is 1 or a tuple only where `m` is 0 or 1, which is why
every mask carries a booleanity gate.

**A window tuple** (`memory.md` §3.3, `public-values.md` §4, `recursion.md` §2.2); code: the
private `memory::window_tuple` and `memory::stride_tuple`, and the inline init tuple in the
private `memory::zero_window`:

```text
WC       = γ_M + 2 + α_addr·4h·w                                  one value per RAM window shard
teardown = WC + 4·α_addr·row + α_ts·teardown_ts + α_val·teardown_value
         = T(RAM, 4h·w + 4·row, teardown_ts, teardown_value)                                  every RAM window family
init     = WC + 4·α_addr·row + α_val·S[0]           = T(RAM, 4·row, 0, init_value)            INIT_TEARDOWN, w = 0
init     = WC + 4·α_addr·row                        = T(RAM, 4h·w + 4·row, 0, 0)              ZERO_WINDOWS, PUBLIC_OUTPUT
init     = WC + 4·α_addr·row + α_val·M[2]           = T(RAM, 4h·w + 4·row, 0, init_value)     PUBLIC_INPUT, ADVICE_WINDOWS

WC       = γ_M + 10 + α_addr·h·w                                  one value per FIELD_WINDOWS shard
teardown = WC + α_addr·row + α_ts·teardown_ts + α_val·teardown_value
         = T(FIELD, h·w + row, teardown_ts, teardown_value)                                   FIELD_WINDOWS
init     = WC + α_addr·row                          = T(FIELD, h·w + row, 0, 0)               FIELD_WINDOWS
```

The three RAM init forms are the three RAM window artifacts: the init value comes from a
**setup** column that program identity binds, from **nothing** — a literal 0 — or from a
**memory** column committed at G8 that one execution chose. `INIT_TEARDOWN` masks both of its
leaves by `V[ram_live]`, which makes them `Quadratic`; the other five carry no mask and are
`Linear`. `FIELD_WINDOWS`' artifact is `ZERO_WINDOWS`' construction at a stride of one cell, one
`(α_addr, V[row])` term a leaf where a RAM window's carries four, and the address space is in
neither artifact: it enters through `WC` alone (§21.3).

**A lookup's fraction** (`lookup.md` §4 to §6). With selector `s` and tuple `e_0 … e_{W−1}`, the
gated tuple is `s·e_j` on a range channel, `s·(e_0 + 1)` then `s·e_j` on the generic channel,
and `s·(e_j + 1) − 1` on the decoder channel. The row denominator (code
`lookup::row_denominator`) and the table denominator (code `lookup::table_denominator`) are:

```text
E + g   =  g + s·e_0                                                     range channel (W = 1)
E + g   =  g + s·(e_0 + 1) + Σ_{j≥1} β^j·s·e_j                           generic channel (W = 3)
E + g   =  g + Σ_j β^j·(s·(e_j + 1) − 1)
        =  g_dec + Σ_j β^j·s + Σ_j β^j·s·e_j                             decoder channel
T + g   =  Σ_j β^j·t_j + g                                               t_j the table's columns
```

A constant in `e_0` folds into the literal on `s`. Above position 0, a constant plus the
channel's offset there (1 on the decoder, 0 elsewhere) must be 0 or 1: a 1 adds the term
`β^j·s`, a 0 adds none, and `row_denominator` panics on anything else, since `β^j·c` is not one
coefficient.

A channel's leaf fractions (code: the private `lookup::channel_tree`) are the table's
`(−mult, T + g)` first, then `(1, E_l + g)` for each lookup in artifact order, then `(0, 1)`
pads up to a power of two. The channel claims `Σ_rows Σ_l 1/(E_l + g) − Σ_t mult_t/(T_t + g) = 0`,
and its root pair must be `num = 0` and `den ≠ 0`.

**Tree nodes** (`build::reduce`, `build::halve`):

```text
product node, row-wise     out = a·b                                         Product
fraction node, row-wise    num = a_num·b_den + b_num·a_den                    Quadratic
                           den = a_den·b_den                                  Product
a tree already one node    each column copied up                              Linear
product node, halving      out = x(y,0)·x(y,1)                                TreeProduct
fraction node, halving     num = num(y,0)·den(y,1) + num(y,1)·den(y,0)        TreeCross { num, den }
                           den = den(y,0)·den(y,1)                            TreeProduct { den }
```

Below, `a + b` between two fraction nodes means that pair of gates, and `a·b` between two
product nodes means the one `Product`.

---

## 1. The registry

### 1.1 What `family_circuit` and `recursion_circuit` return

| id | family | constructor | channels | `Some` for | default height | S16 (`guests/addsub`) | S17 (`guests/control`) | S18 (`guests/alu`) | S19 (`guests/mem`) | S21 (`guests/keccak-test`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | `ADD_SUB_LUI_AUIPC` | `add_sub::artifact(n)` | `add_sub::channels()`: `TIMESTAMP`, `RANGE16`, `DECODER` | `19 ≤ n ≤ 30` | `2^22` | one shard at `2^20` | one shard at `2^20` | one shard at `2^20` | one shard at `2^20` | one shard at `2^20` |
| 1 | `JUMP_BRANCH_SLT` | `jump_branch_slt::artifact(n)` | `jump_branch_slt::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^22` | not in the config: the guest runs no instruction of the family | one shard at `2^20` | one shard at `2^20` | one shard at `2^20` | one shard at `2^20` |
| 2 | `SHIFT_BITWISE` | `shift_bitwise::artifact(n)` | `shift_bitwise::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^22` | — | — | one shard at `2^20` | — | one shard at `2^20` |
| 3 | `MUL_DIV` | `mul_div::artifact(n)` | `mul_div::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^20` | — | — | one shard at `2^20` | — | one shard at `2^20` |
| 4 | `MEM_WORD` | `mem_word::artifact(n)` | `mem_word::channels()`: `TIMESTAMP`, `RANGE16`, `DECODER` — **no generic** | `19 ≤ n ≤ 30` | `2^22` | — | — | — | one shard at `2^20` | one shard at `2^20` |
| 5 | `MEM_SUBWORD` | `mem_subword::artifact(n)` | `mem_subword::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^22` | — | — | — | one shard at `2^20` | one shard at `2^20` |
| 6 | `ATOMICS` | `atomics::artifact(n)` | `atomics::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^20`, **raised from `2^16` at S19** (§9.1) | — | — | — | one shard at `2^20` | not in the config: the guest runs no atomic |
| 7 | `INIT_TEARDOWN` | `memory::image_window_artifact(n)` | none | `0 ≤ n ≤ 30` | `2^22` | one shard at `2^16` | one shard at `2^16` | one shard at `2^16` | one shard at `2^16` | one shard at `2^16` |
| 8 | `ZERO_WINDOWS` | `memory::zero_window_artifact(n)` | none | `0 ≤ n ≤ 30` | `2^22` | at `2^16`, with no shard: the guest touches no RAM | at `2^16`, with no shard | at `2^16`, with no shard | **one shard at `2^16`**, window 8191 | **one shard at `2^16`**, window 8191 |
| 9 | `KECCAK_F` | `keccak::artifact(n)` | `keccak::channels()`: **`RANGE16`** and **`XOR8`** | `16 ≤ n ≤ 30` | `2^18`, **raised from `2^16`** (§12.1) | — | — | — | — | **one shard at `2^18`**, 240 invocations — ten permutations of 24 rounds |
| 10 | `POSEIDON2` | `poseidon2::artifact(n)` | `poseidon2::channels()`: **none** | `0 ≤ n ≤ 30` | `2^8` | — | — | — | — | — |
| 11 | `FR_ARITH` | `fr_arith::artifact(n)` | `fr_arith::channels()`: **none** | `0 ≤ n ≤ 30` | `2^8` | — | — | — | — | — |
| 12 | `PUBLIC_INPUT` | `memory::value_window_artifact(n)` | none | `0 ≤ n ≤ 30` | `2^12`, **pinned**, raised from `2^8` at S-STREAM | one shard at `2^12`, window 2 | one shard at `2^12`, window 2 | one shard at `2^12`, window 2 | one shard at `2^12`, window 2 | one shard at `2^12`, window 2 |
| 13 | `PUBLIC_OUTPUT` | `memory::zero_window_artifact(n)` — `ZERO_WINDOWS`' artifact, byte for byte | none | `0 ≤ n ≤ 30` | `2^12`, **pinned**, ditto | one shard at `2^12`, window 3 | one shard at `2^12`, window 3 | one shard at `2^12`, window 3 | one shard at `2^12`, window 3 | one shard at `2^12`, window 3 |
| 14 | `ADVICE_WINDOWS` | `memory::value_window_artifact(n)` — `PUBLIC_INPUT`'s artifact at another height | none | `0 ≤ n ≤ 30` | the window height, `2^22` | in the config, with no shard: the guest is handed no advice | ditto | ditto | ditto | ditto |
| 15 | `MOD_MUL` | `mod_mul::artifact(n)` | `mod_mul::channels()`: **`RANGE16`** since S26c | `16 ≤ n ≤ 30`, the floor derived from the channel's `BITS` | `2^16` | — | — | — | — | — |
| 16 | `SHA256_COMP` | `sha256::artifact(n)` | `sha256::channels()`: **`RANGE16`** and **`XOR8`** since S26e | `16 ≤ n ≤ 30`, ditto | `2^18`, **raised from `2^8` at S26e** (§19) | — | — | — | — | — |
| 17 | `EC_ADD` | `ec_add::artifact(n)` | `ec_add::channels()`: **`RANGE16`** — the first a delegation family carried | `16 ≤ n ≤ 30`, ditto | `2^16` | — | — | — | — | — |
| 18 | `FIELD_WINDOWS` | `memory::field_window_artifact(n)`, through **`recursion_circuit`** alone: `family_circuit(18, n)` is `None` at every `n` | none | `0 ≤ n ≤ 30`, in `recursion_circuit` | `2^20` | — | — | — | — | — |
| 19 | `FR_OP` | `fr_op::artifact(n)`, through `recursion_circuit` alone | `fr_op::channels()`: **`RANGE16`** | `16 ≤ n ≤ 30` in `recursion_circuit`, the floor derived from the channel's table; `None` at every `n` in `family_circuit` | `2^20` | — | — | — | — | — |
| 20 | `P2_FIELD` | `p2_field::artifact(n)`, through `recursion_circuit` alone | `p2_field::channels()`: **`RANGE16`** | `16 ≤ n ≤ 30` in `recursion_circuit`, ditto | `2^18` | — | — | — | — | — |
| 21 | `FIELD_IO` | `field_io::artifact(n)`, through `recursion_circuit` alone | `field_io::channels()`: **`RANGE16`** | `16 ≤ n ≤ 30` in `recursion_circuit`, ditto | `2^18` | — | — | — | — | — |
| 22 | `FQ_OP` | `fq_op::artifact(n)`, through `recursion_circuit` alone | `fq_op::channels()`: **`TIMESTAMP`** and **`RANGE16`** — the one delegation family carrying `TIMESTAMP` | `19 ≤ n ≤ 30` in `recursion_circuit`, the floor derived from `TIMESTAMP`'s table; `None` at every `n` in `family_circuit` | `2^20`, forced (§25.1) | — | — | — | — | — |

**Families 18 to 22 are the recursion registry's alone.** `constraints::recursion_circuit` is the
recursion format's registry (`recursion.md` §1.2), and `VmConfig::circuit` takes it for a config
holding `FIELD_WINDOWS`, which `program::decode_program` lists exactly when the linked binary
declares one of `program::FIELD_DELEGATIONS` — `FR_OP`, `P2_FIELD`, `FIELD_IO` and `FQ_OP`. Its
arms for families 18 to 22 are guarded by the registry, so `family_circuit` returns `None` for
each at every `n` and no base-format key can name one. For every family above it returns
`family_circuit`'s `FamilyCircuit` byte for byte, at every height, with one exception, family 0
(§3.11); `crates/constraints/tests/recursion.rs` asserts both halves. None of the five
statements in the table declares a field family, so each is a base-format statement and the five
columns read "—" for families 18 to 22. The recursion-format statement is
`crates/prover/tests/field_ops.rs`': `guests/field-ops`, one shard of each of the five, `FQ_OP`
at `2^20` beside the execution families and the other four at `2^16`.

| id | family | constructor | channels | `Some` for | default height |
| --- | --- | --- | --- | --- | --- |
| 0 | `ADD_SUB_LUI_AUIPC`, recursion format | `add_sub::recursion_artifact(n)` | `add_sub::recursion_channels()`: `TIMESTAMP`, `RANGE16`, `DECODER`, with multiplicities at `W[36..39]` | `19 ≤ n ≤ 30` | `2^22`, as in the base format; the recursion programs run it at `2^20` (`recursion.txt`) |

Its fill is `fill::add_sub`, the base form's, which reads the config's format.

A verifying key carries only menu heights (`constants::family::HEIGHT_MENU`, **`2^8` to `2^22`
since S21, with `2^12` inserted at index 1 by S-STREAM**),
which `VmConfig::from_bytes` enforces, so `n` is 8, 12, 16, 18, 20 or 22 in any key — **8 since
S21**, the delegation height the menu opens with (§12.1), and **12 since S-STREAM**, the two
public families' pinned height and nothing else's (§15.1, §16.1); §26 observation 1 notes the
other values the registry accepts. The
prover pairs each circuit with a fill,
`prover::family_fill`: the private `fill::add_sub` for family 0, `fill::jump_branch_slt` for 1,
`fill::shift_bitwise` for 2, `fill::mul_div` for 3, `fill::mem_word` for 4, `fill::mem_subword`
for 5, `fill::atomics` for 6, `fill::window` for 7, 8 **and 13**, `fill::keccak_f` for 9,
`fill::poseidon2` for 10, `fill::fr_arith` for 11, `fill::public_input` for 12,
`fill::advice` for 14, since S26 `fill::mod_mul` for 15, since S26c
`fill::sha256_comp` for 16 and `fill::ec_add` for 17, and since S-RECURSION
`fill::field_window` for 18, `fill::fr_op` for 19, `fill::p2_field` for 20, `fill::field_io` for
21 and `fill::fq_op` for 22. **Every family is provable**, in the registry that holds it.

**Two families' `Some` range is no longer the whole menu, and that is S26c.**
`MOD_MUL` and `EC_ADD` carry `RANGE16`, whose table needs sixteen variables, so
`family_circuit` returns `None` for either below `2^16` — and the guard that says so is
**derived** rather than listed: it reads each family's own `channels()` and takes the most any
one of their tables needs, `lookup::table_vars`, testing the floor before the artifact is built
(the widest range channel's `BITS` until S26d, when `XOR8`'s 65,536-row table, not a range
channel's, made that reading wrong). Until S26c it named the seven execution families
explicitly with a delegation family's arm below it, which worked only while no delegation family
had a channel (`docs/spec/lookup.md` §3, `docs/spec/delegation.md` §10.3). The practical
consequence is in `crates/prover/tests/common`: `MOD_MUL_FIXTURE_VARS = 8` is gone, because that
height no longer exists for the family. The recursion registry's field families take their
floors the same way: 16 for `FR_OP`, `P2_FIELD` and `FIELD_IO`, whose one channel is `RANGE16`,
and **19** for `FQ_OP`, whose `TIMESTAMP` table needs nineteen variables — an execution
family's floor, which on this menu is `2^20`.

**Families 12, 13 and 14 are in every `VmConfig`, and two of them prove a shard in every
statement.** `program::decode_program` lists families 12, 13 and 14 unconditionally, under the
same presence rule that lists `INIT_TEARDOWN` and `ZERO_WINDOWS` — a **RAM window family is in
every config**, and `decode_program`'s three rules stay three — and
`verifier_core::window_height`, inside `VmConfig::from_bytes`, refuses a config missing any of
them or carrying either public family at a height other than `family::PUBLIC_WINDOW_HEIGHT`.
`FIELD_WINDOWS`, the field memory's window family, is outside both rules: it is present exactly
when the binary declares a field family, and `window_height` does not read it (§21.1). `verifier_core::check_memory_windows` then requires
`shard_counts[PUBLIC_INPUT]` and `shard_counts[PUBLIC_OUTPUT]` to be exactly 1, because a count a
prover could drop is a way to publish nothing while having published something; a program that
ignores public values publishes an empty input and an empty journal and pays two `2^12`-row
shards for it. `ADVICE_WINDOWS` is the other way round: `trace::advice_region_words` is 0 for
empty advice, so `advice_window_count` is 0 and a program with no advice pays nothing
(`public-values.md` §4, §6). **The shard-count vectors quoted below are the pre-S-IO ones**, one
entry per family of the config as it then was; every statement in the repository gains three
entries, two of them 1.
The S16 statement is `crates/prover/tests/acceptance.rs`': its config lists families 0, 7 and 8, and its
shard counts are `[1, 1, 0]`. The S17 statement is `crates/prover/tests/control.rs`': its config
lists families 0, 1, 7 and 8, and its shard counts are `[1, 1, 1, 0]`. The S18 statement is
`crates/prover/tests/alu.rs`': its config is
`[(0, 2^20), (1, 2^20), (2, 2^20), (3, 2^20), (7, 2^16), (8, 2^16)]` and its shard counts are
`[1, 1, 1, 1, 1, 0]` — **five shards, one per family that runs**, `ZERO_WINDOWS` being the one
that does not, the guest touching no RAM. `guests/alu` runs 452 live `ADD_SUB_LUI_AUIPC` rows,
96 `JUMP_BRANCH_SLT`, 45 `SHIFT_BITWISE` and 54 `MUL_DIV`, and exits with 96, the number of
checks it made. The S19 statement is `crates/prover/tests/mem.rs`': its config is
`[(0, 2^20), (1, 2^20), (4, 2^20), (5, 2^20), (6, 2^20), (7, 2^16), (8, 2^16)]` and its shard
counts are `[1, 1, 1, 1, 1, 1, 1]` — **seven shards, one per family in the config**, and the
first statement of any stage with a `ZERO_WINDOWS` shard: `guests/mem` writes near the top of
RAM as well as inside window 0, so the derived window list is `[8191]` at `h = 2^16`.
`guests/mem` runs 180 live `ADD_SUB_LUI_AUIPC` rows, 56 `JUMP_BRANCH_SLT`, 53 `MEM_WORD`, 21
`MEM_SUBWORD` and 15 `ATOMICS`, and exits with 50, the number of checks it made.

The S21 statement is `crates/prover/tests/keccak.rs`': its config is
`[(0, 2^20), (1, 2^20), (2, 2^20), (3, 2^20), (4, 2^20), (5, 2^20), (7, 2^16), (8, 2^16),
(9, 2^18), (12, 2^8), (13, 2^8), (14, 2^22)]` and its shard counts give **eleven shards** —
S-IO's two public windows raised it from nine, and `ADVICE_WINDOWS` proves none, this guest
using no advice. It was the first statement of any stage that is not one family one height: ten
of the eleven are the shards a CPU family, a RAM window or a public window gets, and the
eleventh is a **delegation shard**, 262,144 rows of which **240** are invocations — ten
permutations of 24 rounds since S26d, where S21's were ten invocations of 256.
`guests/keccak-test` decodes into 1,429 live `ADD_SUB_LUI_AUIPC` rows, 845 `JUMP_BRANCH_SLT`,
252 `SHIFT_BITWISE`, 24 `MUL_DIV`, 1,555 `MEM_WORD` and 103 `MEM_SUBWORD`; it runs 193,156
cycles and exits with 6, the number of corpus entries it checked. **Those counts and that cycle
figure are S26d's and its debug ELF's**: S21's were 1,707 / 1,018 / 315 / 25 / 1,868 / 145 and
154,708 cycles, and the difference is the 24-round loop in `guest_sdk::keccak256`, which at
`opt-level = 0` is a real call with a stack frame per round. At `--release` the same corpus is
22,509 cycles in total (`docs/spec/delegation.md` §6.0). Its `KECCAK_F` entry is in the config because **its image declares the family**, not
because any pc claims it — the third presence rule, and the one S21 adds
(`delegation.md` §7). `guests/keccak-unused` decodes to exactly the same nine families and
proves **eight** shards: `plan_shards`' `ceil(0 / h)` is 0, so a declared family with no
invocation costs a config entry, a transcript group and no proof.

The S23 statement is `crates/prover/tests/recursion.rs`': `guests/recursion-ops` does ordinary
`field::Fr` arithmetic and calls `transcript::poseidon2_permute`, and the guest-target backends
inside those two crates route both through the delegations (`delegation.md` §13.4). Its config
holds families 0, 1, 2, 3, 4, 5, 7, 8, **10 and 11**, each delegation family at `2^8` with one
shard, and the guest exits 9 — the number of checks it made. It names no shim: the families are
in its `VmConfig` because `Fr`'s operators reach the declaration records, which is what makes
the seam a property of the binary rather than of the call site.
`guests/recursion-unused` declares the same two and proves zero shards of each.

The S-IO statement is `crates/prover/tests/public_io.rs`', and it is the first in the repository
whose public input and public output are **bound to the execution**. `guests/public-io` reads
eight public input bytes — a length and a position-dependent checksum — checksums that many
**advice** bytes against them, and commits the checksum and the advice's first eight bytes to
its **journal**; it issues no ecall but `EXIT`, which is what makes it provable, and every one
of those three accesses is an ordinary load or store. Its config holds families 0 through 5 at
`2^20`, `INIT_TEARDOWN`, `ZERO_WINDOWS` and `ADVICE_WINDOWS` at `2^16`, and `PUBLIC_INPUT` and
`PUBLIC_OUTPUT` at the pinned `2^12`; its shard counts for the three new families are **1, 1 and
1** — 64 bytes of advice is a 68-byte region, 17 words, one window. A guest that publishes nothing still binds that: two
empty byte strings, two public shards, and **no** advice window. No test asserts it since the
suite was abridged — the shard counts come from `window_height` and `shard_counts`, not from a
choice a prover makes.

### 1.2 Master table

The `lookups` column has one slot per channel of `constants::lookup_channel`, in channel order.
It gained a fifth at S26d, and **`KECCAK_F`'s and, since S26e, `SHA256_COMP`'s rows are the only ones that fill it**: every other
circuit's parenthesis lists the four that existed before, a trailing `0` being left off rather
than written out twenty times.

```text
circuit             n  lists (row-wise + halving)  top     M      W   S  V  committed    inner  enforcing (d1/d2)  lookups (ts/r16/gen/dec/xor8)  outputs  relations        bytes
ADD_SUB_LUI_AUIPC  20  25 (5 + 20)                 L25    27     35   7  2         69      298  63 (5/58)          15 (10/4/0/1)                   8        361       70,974
ADD_SUB_LUI_AUIPC  22  27 (5 + 22)                 L27    27     35   7  2         69      314  63 (5/58)          15 (10/4/0/1)                   8        377       72,064
JUMP_BRANCH_SLT    20  25 (5 + 20)                 L25    21     44  10  2         75      372  42 (3/39)          22 (8/11/2/1)                  10        414       75,608
JUMP_BRANCH_SLT    22  27 (5 + 22)                 L27    21     44  10  2         75      392  42 (3/39)          22 (8/11/2/1)                  10        434       76,980
SHIFT_BITWISE      20  26 (6 + 20)                 L26    21     61  10  2         92      458  48 (9/39)          39 (8/24/6/1)                  10        506      101,465
SHIFT_BITWISE      22  28 (6 + 22)                 L28    21     61  10  2         92      478  48 (9/39)          39 (8/24/6/1)                  10        526      102,837
MUL_DIV            20  26 (6 + 20)                 L26    21     54   9  2         84      444  54 (5/49)          27 (8/16/2/1)                  10        498       92,640
MUL_DIV            22  28 (6 + 22)                 L28    21     54   9  2         84      464  54 (5/49)          27 (8/16/2/1)                  10        518       94,012
MEM_WORD           20  25 (5 + 20)                 L25    31     24   7  2         62      298  33 (6/27)          18 (12/5/0/1)                   8        331       59,293
MEM_WORD           22  27 (5 + 22)                 L27    31     24   7  2         62      314  33 (6/27)          18 (12/5/0/1)                   8        347       60,383
MEM_SUBWORD        20  26 (6 + 20)                 L26    31     55  10  2         96      452  53 (6/47)          36 (12/22/1/1)                 10        505       97,474
MEM_SUBWORD        22  28 (6 + 22)                 L28    31     55  10  2         96      472  53 (6/47)          36 (12/22/1/1)                 10        525       98,846
ATOMICS            20  26 (6 + 20)                 L26    26     54   9  2         89      472  46 (9/37)          36 (10/19/6/1)                 10        518      101,593
ATOMICS            22  28 (6 + 22)                 L28    26     54   9  2         89      492  46 (9/37)          36 (10/19/6/1)                 10        538      102,965
INIT_TEARDOWN      16  17 (1 + 16)                 L17     2      0   1  2          3       34  0                  0                               2         34        3,259
INIT_TEARDOWN      22  23 (1 + 22)                 L23     2      0   1  2          3       46  0                  0                               2         46        3,907
ZERO_WINDOWS       16  17 (1 + 16)                 L17     2      0   0  1          2       34  0                  0                               2         34        2,770
ZERO_WINDOWS       22  23 (1 + 22)                 L23     2      0   0  1          2       46  0                  0                               2         46        3,418
KECCAK_F           16  27 (11 + 16)                 L27   208  1,556   0  4      1,764    5,478  385 (307/78)       1,230 (0/210/0/0/1,020)         6      5,863    1,899,700
KECCAK_F           18  29 (11 + 18)                 L29   208  1,556   0  4      1,764    5,490  385 (307/78)       1,230 (0/210/0/0/1,020)         6      5,875    1,900,468
POSEIDON2           8  201 (193 + 8)               L201  100  4,092   0  0      4,192    2,020  4,248 (54/4,194)   0                               2      6,268    2,056,361
FR_ARITH            8   14 (6 + 8)                  L14   104  2,576   0  0      2,680      142  2,701 (46/2,655)   0                               2      2,843    1,063,214
PUBLIC_INPUT       12  13 (1 + 12)                 L13     3      0   0  1          3       26  0                  0                               2         26        2,455
PUBLIC_OUTPUT      12  13 (1 + 12)                 L13     2      0   0  1          2       26  0                  0                               2         26        2,338
ADVICE_WINDOWS     16  17 (1 + 16)                 L17     3      0   0  1          3       34  0                  0                               2         34        2,887
ADVICE_WINDOWS     22  23 (1 + 22)                 L23     3      0   0  1          3       46  0                  0                               2         46        3,535
MOD_MUL            16   26 (10 + 16)               L26   104    221   0  1        325    2,244  125 (54/71)        274 (0/274/0/0)                 4      2,369      550,391
SHA256_COMP        16  26 (10 + 16)               L26   104    520   0  4        624    2,790  119 (75/44)        450 (0/114/0/0/336)             6      2,909      844,688
SHA256_COMP        18  28 (10 + 18)               L28   104    520   0  4        624    2,802  119 (75/44)        450 (0/114/0/0/336)             6      2,921      845,456
EC_ADD             16   28 (12 + 16)               L28   392  1,028   0  1      1,420    8,772  637 (131/506)      1,110 (0/1,110/0/0)             4      9,409    2,350,670
```

What `recursion_circuit` returns and `family_circuit` does not — `ADD_SUB_LUI_AUIPC`'s recursion
form (§3.11) and the five families only the recursion registry holds (§21–§25):

```text
recursion_circuit   n  lists (row-wise + halving)  top     M      W   S  V  committed    inner  enforcing (d1/d2)  lookups (ts/r16/gen/dec/xor8)  outputs  relations        bytes
ADD_SUB_LUI_AUIPC  20  25 (5 + 20)                 L25    27     39   7  2         73      298  75 (5/70)          15 (10/4/0/1)                   8        373       77,987
ADD_SUB_LUI_AUIPC  22  27 (5 + 22)                 L27    27     39   7  2         73      314  75 (5/70)          15 (10/4/0/1)                   8        389       79,077
FIELD_WINDOWS      16  17 (1 + 16)                 L17     2      0   0  1          2       34  0                  0                               2         34        2,326
FIELD_WINDOWS      20  21 (1 + 20)                 L21     2      0   0  1          2       42  0                  0                               2         42        2,758
FR_OP              20  27 (7 + 20)                 L27    31     31   0  1         62      370  44 (9/35)          36 (0/36/0/0)                   4        414       89,741
P2_FIELD           16  23 (7 + 16)                 L23    45    382   0  1        427      384  372 (6/366)        58 (0/58/0/0)                   4        756      293,915
P2_FIELD           18  25 (7 + 18)                 L25    45    382   0  1        427      392  372 (6/366)        58 (0/58/0/0)                   4        764      294,425
FIELD_IO           18  26 (8 + 18)                 L26    43     39   0  1         82      650  24 (5/19)          70 (0/70/0/0)                   4        674      164,713
FQ_OP              20  27 (7 + 20)                 L27    48     73   0  2        121      630  38 (6/32)          80 (30/50/0/0)                  6        668      158,326
```

`committed` is layer 0's width, `M + W + S`. `inner` is the width of every layer above 0,
summed: the multilinears that are never committed, one producing gate each. `relations` is
producing plus enforcing gates. `bytes` is `to_bytes().len()`. The first block's `n = 22` rows
are the committed fixtures: `crates/constraints/tests/vectors/add_sub.bin` (SHA-256 `a6113128…6cae38c7`),
`jump_branch_slt.bin` (`99094d63…742c1305`), `shift_bitwise.bin` (`b0af9325…65e3fd4c`),
`mul_div.bin` (`98f9f3bd…a30c357a`), `mem_word.bin` (`2c8d94ca…f7ca4500`), `mem_subword.bin`
(`2c423eb1…9f596181`), `atomics.bin` (`ae58b1ca…643d3108`), `image_window.bin`
(`39a8655d…2df67ecc`) and `zero_window.bin` (`f08dde67…aa51ec1c`), each pinned by its suite.
**`zero_window.bin` is `PUBLIC_OUTPUT`'s circuit too**, at `n = 22` rather than at the pinned
`n = 12`: the two families take one constructor and `family_circuit(13, n)` and
`family_circuit(8, n)` agree byte for byte at every `n`. `value_window_artifact` has no committed
fixture of its own; §15, §16 and §17 were read from `family_circuit(12, 12)`,
`family_circuit(13, 12)` and `family_circuit(14, 22)` and from a `checker dump` of their bytes
(Appendix A).

**The two public families are the smallest circuits in the registry**, and by a wide margin:
`PUBLIC_OUTPUT` at its pinned `n = 12` is 2,338 bytes and two gates of list 0 and `PUBLIC_INPUT`
2,455 — 1,910 and 2,027 at S-IO's `2^8`, the four halving lists S-STREAM added costing each
artifact the same 428 bytes — against `atomics.bin`'s 102,965 on 132 leaves and `KECCAK_F`'s
1.9 MB. The whole public-values and advice mechanism costs 8 committed columns across three
families — three, two and three — and not one enforcing gate, lookup or channel.
**`atomics.bin` is the largest circuit artifact committed as bytes**, 102,965 of them to
`shift_bitwise.bin`'s 102,837, on 132 leaves to its 124. **`POSEIDON2` is the largest circuit
and none of the six delegation families is committed as bytes**: `POSEIDON2`'s artifact is
2,056,361 of them and `KECCAK_F`'s 1,900,468, so what
`crates/constraints/tests/vectors/{keccak,poseidon2,fr_arith,mod_mul,sha256,ec_add}.txt` hold is
each artifact's SHA-256 beside its shape line above, written by
`cargo run -p kat-gen -- delegation` and diffed by CI like every other fixture. **`KECCAK_F`'s
was 100,254,040 bytes until S26d** — 974 times `atomics.bin`, which is why the digest convention
exists at all — and one round a row took it to 1.9 MB, small enough that
`checker dump` of it at `n = 16` is 20,333 readable lines. Each is at its family's **default**
height: `2^8` for three, `2^18` for `KECCAK_F` — the second of its two rows above, and the one
`keccak.txt` pins — `2^16` for `MOD_MUL` and `EC_ADD`, and `2^12` for `PUBLIC_INPUT` and
`PUBLIC_OUTPUT`.

**The recursion registry's six circuits are committed by digest too, in one file.**
`crates/constraints/tests/vectors/recursion.txt` holds each one's shape line and SHA-256:
`FIELD_WINDOWS`, `FR_OP` and `FQ_OP` at `n = 20` and `P2_FIELD` and `FIELD_IO` at `n = 18`, each
its family's default, and `ADD_SUB_LUI_AUIPC`'s recursion form at `n = 20`, the height the
recursion programs run it at. `cargo run -p kat-gen -- recursion` writes the file, `recursion`
being a default group, and CI regenerates and diffs it; unlike the `delegation` group's six
lines, no kat-gen unit test holds a line to its constructor. The block's other rows —
`FIELD_WINDOWS` and `P2_FIELD` at `n = 16`, the height `crates/prover/tests/field_ops.rs` proves
them at, and the recursion form at `n = 22` — were read from `recursion_circuit` directly. **The
largest is `P2_FIELD`, at 294,425 bytes**, a flat circuit of 372 enforcing gates where
`POSEIDON2`'s same permutation is 2,056,361 bytes over 193 row-wise lists (§23.1).

**`ADD_SUB_LUI_AUIPC` moved when the POSIX layer went, and by more than three columns.** `read`
(63) and `write` (64) are retired and their numbers burned, so the `arg1` and `arg2` queries
went with them and this family's `ram` query — the ecall transfer row's alone — went with the
transfer row (`ecall-abi.md` §4). Its frame is **five** queries where S21 made it eight: 15 `M`
columns, three gap chunks, three mask booleanity gates, two write-backs and the three
`arg1_mask_rule`, `arg2_mask_rule` and `ram_mask_rule` gates are gone, each of the last three
having said `mask = 0` about a query the family could not make. Five is not a power of two, so
**its two product trees pay three pad leaves a side** where eight paid none; and ten gap
obligations with the table fraction is eleven leaves, which fits a 16-leaf tree, so the
timestamp tree stopped setting the depth and the circuit went from six row-wise lists back to
**five**. Depth, every layer width, every relation number, both fixture digests and the proof's
length moved with it, and §3 is rewritten over the narrowed artifact. Its layer widths are now
`MEM_WORD`'s exactly, `L1 … L5` of 68, 34, 18, 10 and 8. No other circuit in the repository
changed.

**Four of the seven execution circuits are six row-wise lists deep, and one tree apiece is why.**
Shift/bitwise's `range16` tree carries 24 obligations beside its table fraction, 25 leaves
padding to 32 (§5.6), and mul/div's carries 16, which with its table fraction is 17 leaves and
pads to 32 too (§6.6); mem_subword's carries 22 and atomics' 19. Everything else about their
shape follows: one more row-wise level, one more gate list, one more transition in every proof.
**Add/sub was the fifth and is not any more**: its timestamp tree carried 16 obligations from
S21 until the POSIX layer went, which with its table fraction was 17 leaves and padded to 32 for
exactly mul/div's reason; at ten obligations it is eleven leaves in a 16-leaf tree and the level
came back off (§3.6, §26 observation 20).

**Two of S19's three are six lists deep for the same reason, and `MEM_WORD` is five.**
Mem_subword's `range16` tree carries 22 obligations and atomics' 19, so each pads to 32 (§8.6,
§9.6); mem_word's carries 5, which with its table fraction is 6 leaves in an 8-leaf tree, and
its deepest tree is the timestamp's 16 — so it is 25 lists deep at `n = 20`, which is §3's and
§4's depth too. **`ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT` and `MEM_WORD` are the three execution
circuits five row-wise lists deep**, and for one reason: none of their trees needs more than 16
leaves. Jump/branch/slt's four queries give four gap pairs and mem_word's six give six, so their
timestamp trees hold 8 and 12 obligations beside a table fraction; add/sub's five give ten.

The proof a shard of each carries, at `n = 20`, by `shard-proof.md` §9's layout over the
circuit's own shape — the formula `crates/prover/tests/mem.rs`' `proof_bytes` computes and
`crates/prover/tests/acceptance.rs`, `control.rs`, `alu.rs`, `mem.rs` and `keccak.rs` each assert
against `ShardProof::to_bytes().len()`:

```text
circuit             n   proof bytes
ADD_SUB_LUI_AUIPC  20        57,196
JUMP_BRANCH_SLT    20        61,612
SHIFT_BITWISE      20        68,564
MUL_DIV            20        67,412
MEM_WORD           20        56,268
MEM_SUBWORD        20        68,116
ATOMICS            20        68,468
KECCAK_F           18       381,100
```

A proof's length is one transition per gate list, `128` bytes per sumcheck round and `32` per
final claim, plus `64` per **witness** commitment and `32` per output. **`MEM_WORD`'s is the
shortest of the seven execution families and add/sub's is the second**, and the gap between them
is 928 bytes: the two circuits have the same depth, the same `L1` and the same inner widths
since the frame narrowed, so all of it is add/sub's eleven extra witness commitments (704) and
its seven-column wider base layer (224). Add/sub's 57,196 is the formula's over the six-type
artifact, 192 bytes above the four-type one's 57,004 — two selectors, each one more witness
commitment and one more base-layer claim — and it is the literal `acceptance.rs` asserts.
`MEM_SUBWORD`'s and `ATOMICS`' are the longest of the seven, on a wider base layer, a wider `L1`
and the extra transition their `range16` trees buy.

**`KECCAK_F`'s proof was 11,880,012 bytes until S26d and is 381,100 at `2^18`**, and the
comparison is the clearest single number this page carries. S21's row was a whole permutation, so
the shard was 3,764 witness commitments and 358,540 final claims — 11,473,280 bytes of claims
alone — for **256 permutations**. One round a row at `2^18` is 1,556 commitments and 7,356
claims for **10,922 permutations**: 34.9 proof bytes a permutation against 46,406, a factor of
**1,330** (`docs/spec/delegation.md` §6.0). That 381,100 is **derived and not measured**:
`proof_bytes` is a closed form over the artifact and it reproduces S26d's measured 373,276 at
`2^16` exactly, which is what licenses reading it forward. It is still the largest delegation
proof of the six, and it is now of the same order as a CPU shard's rather than 173 times one.

**The recursion registry's circuits have no row here.** A recursion-format shard commits its
`M` and `W` columns as stacks (`recursion.md` §1.3), where `proof_bytes`' layout is one
commitment a column, so the formula does not give their proofs' lengths and this page gives
none.

### 1.3 Shape formulas

`build::assemble` builds **every** circuit the same way since S26d, `KECCAK_F` included. Let `R`
be the largest `log2` leaf count among its trees; then the depth is `N = 1 + R + n`. Gate list 0
writes the leaves, lists `1 … R` reduce row-wise, and lists `R + 1 … R + n` halve. S21's keccak
was the one exception — a layered circuit with 24 round blocks, assembled by `keccak.rs`'s own
`Assembly` — and one round a row removed the exception along with the blocks: its `R` is 10, the
`XOR8` tree's depth, and `29 = 1 + 10 + 18`.

- **add/sub.** Five trees: `read` and `write` with 8 leaves each — five queries and **three**
  pads a side — `timestamp` with 16 fractions, `range16` with 8, `decoder` with 2; so `R = 4`,
  the timestamp tree setting it. Layers `L1 … L5` are 68, 34, 18, 10 and 8 wide, and
  `L6 … L{n+5}` 8 each: `inner = 138 + 8n`, which is mem_word's formula exactly. Relations
  0–67 are list 0's leaves, 68–130 its enforcing gates, 131–164 list 1, 165–182 list 2,
  183–192 list 3, 193–200 list 4, and halving list `k` (`5 ≤ k ≤ n + 4`) holds
  `201 + 8(k − 5)` to `208 + 8(k − 5)`. The roots are relations `193 + 8n` to `200 + 8n`:
  353–360 at `n = 20`, 369–376 at `n = 22`. **All of this moved when the POSIX layer went**,
  as all of it had moved at S21 when the frame took an eighth query; the S21 numbers are in
  `docs/handoff/S21-keccak256.md`, and §3.1 has the before-and-after. S26c's two delegation
  types then moved every relation from 109 on up by six, three gates apiece, and no layer width.
- **add/sub, recursion format.** The same five trees as add/sub's, so `R = 4`: `L1 … L5` are 68,
  34, 18, 10 and 8 wide, and `inner = 138 + 8n`. Relations 0–67 are list 0's leaves, 68–142 its
  75 enforcing gates, 143–176 list 1, 177–194 list 2, 195–204 list 3 and 205–212 list 4, and
  halving list `k` (`5 ≤ k ≤ n + 4`) holds `213 + 8(k − 5)` to `220 + 8(k − 5)`. The roots are
  relations `205 + 8n` to `212 + 8n`: 365–372 at `n = 20`, 381–388 at `n = 22`. Every number from
  relation 109 up is the base form's plus 12 (§3.11).
- **jump/branch/slt.** Six trees: `read` and `write` with 4 leaves each, `timestamp` with 16
  fractions, `range16` with 16, `generic` with 4, `decoder` with 2; so `R = 4`, the two
  16-fraction trees setting it. Layers `L1 … L5` are 84, 42, 22, 14 and 10 wide, and
  `L6 … L{n+5}` 10 each: `inner = 172 + 10n`. Relations 0–83 are list 0's leaves, 84–125 its
  enforcing gates, 126–167 list 1, 168–189 list 2, 190–203 list 3, 204–213 list 4, and halving
  list `k` (`5 ≤ k ≤ n + 4`) holds `214 + 10(k − 5)` to `223 + 10(k − 5)`. The roots are
  relations `204 + 10n` to `213 + 10n`: 404–413 at `n = 20`, 424–433 at `n = 22`.
- **shift/bitwise.** Six trees: `read` and `write` with 4 leaves each, `timestamp` with 16
  fractions, `range16` with **32**, `generic` with 8, `decoder` with 2; so `R = 5`, the
  32-fraction `range16` tree setting it alone. Layers `L1 … L6` are 124, 62, 32, 18, 12 and 10
  wide, and `L7 … L{n+6}` 10 each: `inner = 258 + 10n`. Relations 0–123 are list 0's leaves,
  124–171 its enforcing gates, 172–233 list 1, 234–265 list 2, 266–283 list 3, 284–295 list 4,
  296–305 list 5, and halving list `k` (`6 ≤ k ≤ n + 5`) holds `306 + 10(k − 6)` to
  `315 + 10(k − 6)`. The roots are relations `296 + 10n` to `305 + 10n`: 496–505 at `n = 20`,
  516–525 at `n = 22`.
- **mul/div.** Six trees: `read` and `write` with 4 leaves each, `timestamp` with 16 fractions,
  `range16` with **32**, `generic` with 4, `decoder` with 2; so `R = 5`, again the `range16`
  tree alone — 17 leaves is one past 16. Layers `L1 … L6` are 116, 58, 30, 18, 12 and 10 wide,
  and `L7 … L{n+6}` 10 each: `inner = 244 + 10n`. Relations 0–115 are list 0's leaves, 116–169
  its enforcing gates, 170–227 list 1, 228–257 list 2, 258–275 list 3, 276–287 list 4, 288–297
  list 5, and halving list `k` (`6 ≤ k ≤ n + 5`) holds `298 + 10(k − 6)` to `307 + 10(k − 6)`.
  The roots are relations `288 + 10n` to `297 + 10n`: 488–497 at `n = 20`, 508–517 at `n = 22`.
- **mem_word.** Five trees: `read` and `write` with 8 leaves each, `timestamp` with 16
  fractions, `range16` with 8, `decoder` with 2; so `R = 4`, the timestamp tree setting it.
  Layers `L1 … L5` are 68, 34, 18, 10 and 8 wide, and `L6 … L{n+5}` 8 each: `inner = 138 + 8n`,
  which is add/sub's formula exactly. Relations 0–67 are list 0's leaves, 68–100 its enforcing
  gates, 101–134 list 1, 135–152 list 2, 153–162 list 3, 163–170 list 4, and halving list `k`
  (`5 ≤ k ≤ n + 4`) holds `171 + 8(k − 5)` to `178 + 8(k − 5)`. The roots are relations
  `163 + 8n` to `170 + 8n`: 323–330 at `n = 20`, 339–346 at `n = 22`.
- **mem_subword.** Six trees: `read` and `write` with 8 leaves each, `timestamp` with 16
  fractions, `range16` with **32**, `generic` with 2, `decoder` with 2; so `R = 5`, the
  32-fraction `range16` tree setting it alone — 23 leaves is seven past 16. Layers `L1 … L6`
  are 120, 60, 32, 18, 12 and 10 wide, and `L7 … L{n+6}` 10 each: `inner = 252 + 10n`.
  Relations 0–119 are list 0's leaves, 120–172 its enforcing gates, 173–232 list 1, 233–264
  list 2, 265–282 list 3, 283–294 list 4, 295–304 list 5, and halving list `k`
  (`6 ≤ k ≤ n + 5`) holds `305 + 10(k − 6)` to `314 + 10(k − 6)`. The roots are relations
  `295 + 10n` to `304 + 10n`: 495–504 at `n = 20`, 515–524 at `n = 22`.
- **atomics.** Six trees: `read` and `write` with 8 leaves each — five queries and **three**
  pads a side — `timestamp` with 16 fractions, `range16` with **32**, `generic` with 8,
  `decoder` with 2; so `R = 5`, again the `range16` tree alone. Layers `L1 … L6` are 132, 66,
  34, 18, 12 and 10 wide, and `L7 … L{n+6}` 10 each: `inner = 272 + 10n`. Relations 0–131 are
  list 0's leaves, 132–177 its enforcing gates, 178–243 list 1, 244–277 list 2, 278–295 list 3,
  296–307 list 4, 308–317 list 5, and halving list `k` (`6 ≤ k ≤ n + 5`) holds
  `318 + 10(k − 6)` to `327 + 10(k − 6)`. The roots are relations `308 + 10n` to `317 + 10n`:
  508–517 at `n = 20`, 528–537 at `n = 22`.
- **The six windows.** `INIT_TEARDOWN`, `ZERO_WINDOWS`, `PUBLIC_INPUT`, `PUBLIC_OUTPUT`,
  `ADVICE_WINDOWS` and the recursion registry's `FIELD_WINDOWS` share one shape. Two trees of one
  leaf each, so `R = 0`: `L1 … L{n+1}` are 2 wide and `inner = 2n + 2`. Relation 0 is the
  teardown leaf, 1 the init leaf, and halving list `k` (`1 ≤ k ≤ n`) holds `2k` (read side) and
  `2k + 1` (write side). The roots are relations `2n` and `2n + 1`: 24 and 25 at the two public
  families' `n = 12`, 40 and 41 at `FIELD_WINDOWS`' default `n = 20`, 44 and 45 at
  `ADVICE_WINDOWS`' default `n = 22`. The four constructors differ only in the base layer and
  gate list 0's two leaves: the init value is `S[0]`, nothing or `M[2]` (§0.6), and
  `field_window_artifact`'s stride is one cell where the RAM windows' is four bytes (§21.3). So
  every relation number, node name and layer width above `L1` is the same in all six.
- **keccak.** Two trees, `read` and `write`, of 64 leaves each — 50 frame words, the anchor, and
  13 pads a side — and no fraction tree at all, the family having no channel. `R` is 6, but the
  depth is **not** `1 + R + n`: the permutation's 24 blocks of 7 sub-layers stack above gate list
  0 and the trees reduce underneath them, so `depth = 169 + n` — 168 round layers, the output
  list, and `n` halving lists — and the trees reach their two roots at `L7`, 162 layers before
  they are needed. `L1` is 2,419 wide (128 tree + 51 carried + 2,240 permutation); `L2 … L7` are
  2,035, 2,003, 1,987, 1,659, 3,255 and 1,653; `L{7r+1} … L{7r+7}` for `1 ≤ r ≤ 23` are 2,293,
  1,973, 1,973, 1,973, 1,653, 3,253 and 1,653, **14,771 a block**; `L169` is 2 and so is every
  halving layer. `inner = 354,746 + 2n`. Relations 0–2,418 are list 0's producing gates,
  2,419–6,131 its 3,713 enforcing gates, 6,132–358,456 lists 1–167, 358,457–358,458 the output
  list's two root copies and 358,459–358,508 its 50 `output_w` gates, and halving list `169 + s`
  (`0 ≤ s < n`) holds `358,509 + 2s` and `358,510 + 2s`. The roots are relations `358,507 + 2n`
  and `358,508 + 2n`: 358,523 and 358,524 at `n = 8`. Every one of those numbers is independent
  of `n` but the last two, because only the halving phase depends on it.

- **mod_mul.** Three trees: `read` and `write` with 32 leaves each — 25 frame words, the
  anchor, and **6 pads a side** — and `range16` with **512** fractions, 274 obligations and a
  table fraction padding to it; so `R = 9`, the `range16` tree setting it alone, a 32-leaf
  product tree being 5 deep. Layers `L1 … L10` are 1,088, 544, 272, 136, 68, 34, 18, 10, 6 and
  4 wide, and `L11 … L{n+10}` 4 each: `inner = 2,180 + 4n`. Relations 0–1,087 are list 0's
  leaves, 1,088–1,212 its 125 enforcing gates, 1,213–1,756 list 1, 1,757–2,028 list 2,
  2,029–2,164 list 3, 2,165–2,232 list 4, 2,233–2,266 list 5, 2,267–2,284 list 6, 2,285–2,294
  list 7, 2,295–2,300 list 8, 2,301–2,304 list 9, and halving list `k` (`10 ≤ k ≤ n + 9`) holds
  `2,305 + 4(k − 10)` to `2,308 + 4(k − 10)`. The roots are relations `2,301 + 4n` to
  `2,304 + 4n`: 2,365–2,368 at `n = 16`. **Until S26c this circuit was six row-wise lists and
  158 inner columns**: the channel's fraction tree is four levels deeper than the product trees
  it sits beside, which is what moved every number here (§18.1, §18.6).

- **sha256.** Four trees since S26e: `read` and `write` of 32 leaves each — 25 frame words, the
  anchor and **6 pads** a side — `range16` with 128 fractions (114 obligations and the table
  fraction) and `xor8` with **512** (336 and the table fraction); so `R = 9`, the `xor8` tree
  setting it alone, and the depth is `1 + R + n = 10 + n`, `build::assemble`'s shape. `L1` is
  1,344 wide, `L2 … L10` are 672, 336, 168, 84, 42, 22, 12, 8 and 6, and `L11 … L{n+10}` 6 each:
  `inner = 2,694 + 6n`. Relations 0–1,343 are list 0's producing gates, 1,344–1,462 its 119
  enforcing gates, 1,463–2,812 lists 1–9, and halving list `10 + s` (`0 ≤ s < n`) holds
  `2,813 + 6s` to `2,818 + 6s`. The roots are relations `2,807 + 6n` to `2,812 + 6n`: 2,915–2,920
  at `n = 18`. Every number but the last is independent of `n`. **Until S26e this circuit was
  `delegation::Assembly`'s**, two lists of bit-level work riding inside a 32-leaf tree's five
  reduction lists, `inner = 16,672 + 2n` (§19).

- **ec_add.** Three trees: `read` and `write` with 128 leaves each — 97 frame words, the
  anchor, and **30 pads a side** — and `range16` with **2,048** fractions, 1,110 obligations
  and a table fraction padding to it; so `R = 11`, the `range16` tree setting it alone.
  Layers `L1 … L12` are 4,352, 2,176, 1,088, 544, 272, 136, 68, 34, 18, 10, 6 and 4 wide, and
  `L13 … L{n+12}` 4 each: `inner = 8,708 + 4n`. Relations 0–4,351 are list 0's leaves,
  4,352–4,988 its enforcing gates, 4,989–7,164 list 1, 7,165–8,252 list 2, 8,253–8,796 list 3,
  8,797–9,068 list 4, 9,069–9,204 list 5, 9,205–9,272 list 6, 9,273–9,306 list 7,
  9,307–9,324 list 8, 9,325–9,334 list 9, 9,335–9,340 list 10, 9,341–9,344 list 11, and
  halving list `k` (`12 ≤ k ≤ n + 11`) holds `9,345 + 4(k − 12)` to `9,348 + 4(k − 12)`. The
  roots are relations `9,341 + 4n` to `9,344 + 4n`: 9,405–9,408 at `n = 16`.

- **fr_op.** Three trees: `read` and `write` with 8 leaves each and **no pad** — four frame
  words, the anchor and the three field accesses `a`, `b`, `d` — and `range16` with **64**
  fractions, 36 obligations and a table fraction padding to it; so `R = 6`, the `range16` tree
  setting it alone, an 8-leaf product tree being 3 deep. Layers `L1 … L7` are 144, 72, 36, 18,
  10, 6 and 4 wide, and `L8 … L{n+7}` 4 each: `inner = 290 + 4n`. Relations 0–143 are list 0's
  leaves, 144–187 its 44 enforcing gates, 188–259 list 1, 260–295 list 2, 296–313 list 3,
  314–323 list 4, 324–329 list 5, 330–333 list 6, and halving list `k` (`7 ≤ k ≤ n + 6`) holds
  `334 + 4(k − 7)` to `337 + 4(k − 7)`. The roots are relations `330 + 4n` to `333 + 4n`:
  410–413 at `n = 20`. The recursion registry's alone (§22).

- **p2_field.** Three trees: `read` and `write` with 16 leaves each — five frame words, the
  anchor, eight field accesses and **two pads a side** — and `range16` with **64** fractions, 58
  obligations and a table fraction padding to it; so `R = 6`, the `range16` tree setting it
  alone, a 16-leaf product tree being 4 deep. Layers `L1 … L7` are 160, 80, 40, 20, 10, 6 and 4
  wide, and `L8 … L{n+7}` 4 each: `inner = 320 + 4n`. Relations 0–159 are list 0's producing
  gates, 160–531 its 372 enforcing gates, 532–611 list 1, 612–651 list 2, 652–671 list 3,
  672–681 list 4, 682–687 list 5, 688–691 list 6, and halving list `k` (`7 ≤ k ≤ n + 6`) holds
  `692 + 4(k − 7)` to `695 + 4(k − 7)`. The roots are relations `688 + 4n` to `691 + 4n`:
  752–755 at `n = 16`, 760–763 at `n = 18`. The recursion registry's alone (§23).

- **field_io.** Three trees: `read` and `write` with 16 leaves each — three frame words, the
  anchor, eight data words and the cell, and **three pads a side** — and `range16` with **128**
  fractions, 70 obligations and a table fraction padding to it; so `R = 7`, the `range16` tree
  setting it alone, a 16-leaf product tree being 4 deep. Layers `L1 … L8` are 288, 144, 72, 36,
  18, 10, 6 and 4 wide, and `L9 … L{n+8}` 4 each: `inner = 578 + 4n`. Relations 0–287 are list
  0's leaves, 288–311 its 24 enforcing gates, 312–455 list 1, 456–527 list 2, 528–563 list 3,
  564–581 list 4, 582–591 list 5, 592–597 list 6, 598–601 list 7, and halving list `k`
  (`8 ≤ k ≤ n + 7`) holds `602 + 4(k − 8)` to `605 + 4(k − 8)`. The roots are relations
  `598 + 4n` to `601 + 4n`: 670–673 at `n = 18`. The recursion registry's alone (§24).

- **fq_op.** Four trees: `read` and `write` with 32 leaves each — four frame words, the anchor
  and 13 field accesses, and **14 pads a side** — `timestamp` with 32 fractions (30 obligations,
  the table fraction and one pad) and `range16` with **64** (50, the table fraction and 13 pads);
  so `R = 6`, the `range16` tree setting it alone. Layers `L1 … L7` are 256, 128, 64, 32, 16, 8
  and 6 wide, and `L8 … L{n+7}` 6 each: `inner = 510 + 6n`. Relations 0–255 are list 0's
  leaves, 256–293 its 38 enforcing gates, 294–421 list 1, 422–485 list 2, 486–517 list 3,
  518–533 list 4, 534–541 list 5, 542–547 list 6, and halving list `k` (`7 ≤ k ≤ n + 6`) holds
  `548 + 6(k − 7)` to `553 + 6(k − 7)`. The roots are relations `542 + 6n` to `547 + 6n`:
  662–667 at `n = 20`. The recursion registry's alone (§25).

---

## 2. The memory frame every execution family carries

`memory::frame_artifact` and `frame_with_channels_artifact` build it; `memory.md` §2 is its
spec. It is the first part of every execution family's circuit, so its columns come first in
`M` and `W`.

### 2.1 The query table and the layout

The **seven** queries (`memory::{PC, RS1, RS2, LOAD, RAM, RD, DELEG}`, with
`FRAME_NAMES`, `FRAME_SPACE`, `FRAME_DELTA`) — the pc query and then
`execution-trace.md` §7's six roles in their frozen order:

| id | constant | `<q>` | `AS` | `Δ` | what it is |
| --- | --- | --- | --- | --- | --- |
| 0 | `PC` | `pc` | PC = 3 | 0 | reads the pc, writes the next pc |
| 1 | `RS1` | `rs1` | REG = 1 | 1 | first operand register; an ecall row's `a7` |
| 2 | `RS2` | `rs2` | REG | 2 | second operand register; an ecall row's `a0` |
| 3 | `LOAD` | `load` | RAM = 2 | 2 | a load's word |
| 4 | `RAM` | `ram` | RAM | 3 | a store's or an atomic's word |
| 5 | `RD` | `rd` | REG | 3 | the destination register; an ecall row's `a0` result |
| 6 | `DELEG` | `deleg` | **not a literal**: `FRAME_SPACE[6]` is 0 and the row's `deleg_space` column carries the tag | 3 | **S21**: a delegation request's mirror query, whose address is the frame base the request read from `a0` (`delegation.md` §5.1) |

**It was nine, and the two that went were `ARG1` and `ARG2`.** They were an ecall row's `a1` and
`a2` at `Δ = 2`, which only `read` (63) and `write` (64) ever passed; those calls are retired
and their numbers burned, so both roles became unreachable and were removed rather than left as
columns nothing can make nonzero (`ecall-abi.md` §4, `memory.md` §2.1). **Every remaining query
kept its id**, `DELEG`'s 6 included: the two that went were the last two of slot 2, nothing
above them is addressed by id, and a family's columns are addressed by *slot* anyway.
`trace::Row::present` is a `u8` with one bit per role, so it now has two spare bits; a seventh
role is still a schema change (`execution-trace.md` §7). `RAM` is no longer an ecall transfer's
word either — there are no transfer cycles — and it is a store's or an atomic's alone.

`DELEG`'s address space is the delegation family's, which is why a request's mirror tuple can
only be answered by an invocation of that family and by nothing in RAM or a register (§12.4).

**Which delegation family is a property of the row, not of the table, since S23.** One `deleg`
query serves every registered type — six in the base format's `ADD_SUB_LUI_AUIPC` and ten in
the recursion format's (§3.11); a second would need a seventh role — so its `AS` term
is not a literal on the mask but one more `M` column, `deleg_space` at `M[1 + 5w]`, which the
family pins to its type selectors with a degree-1 gate (`delegation.md` §5.1). A leaf may read
no `W` column, which is why the tag cannot ride the selectors directly.
`FRAME_SPACE[DELEG]` is therefore **0**, a value no real tag takes, so a reader that compares it
against an event's space matches nothing and reaches a loud panic rather than a silent skip;
`memory::frame_query_takes` is the routing rule, and a frame holding `deleg` carries the extra
column while one without it does not.

A family holds the subset `memory::frame_queries(family)`. **Slot** `s` is a query's position
in that list, and every column is addressed by slot, never by query id. With `w` the family's
query count:

| address | name | Rust | descriptive name | holds |
| --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the row's cycle `c`, counted from 1; its writes are at `4c + Δ` |
| `M[1 + 5s]` | `<q>_mask` | `memory::frame(s, FIELD_MASK)` | `<q>` present | 1 exactly on a live row that makes query `<q>` |
| `M[2 + 5s]` | `<q>_addr` | `frame(s, FIELD_ADDR)` | `<q>` address | a register index, a RAM word's byte address, or 0 for the pc |
| `M[3 + 5s]` | `<q>_read_ts` | `frame(s, FIELD_READ_TS)` | `<q>` previous-write time | the timestamp of the write this query reads |
| `M[4 + 5s]` | `<q>_read_value` | `frame(s, FIELD_READ_VALUE)` | `<q>` value read | |
| `M[5 + 5s]` | `<q>_write_value` | `frame(s, FIELD_WRITE_VALUE)` | `<q>` value written | written at `4·cycle + Δ_q` |
| `M[1 + 5w]` | `deleg_space` | `memory::deleg_space(w)` | requested delegation type | that type's address-space tag on a request row, 0 elsewhere; **only on a frame holding `deleg`** |
| `W[s]` | `<q>_gap_hi` | `memory::gap_hi(s)` | `<q>` gap, high chunk | `gap >> 19`, with `gap = 4·cycle + Δ_q − read_ts − 1` |
| `W[w]` | `rd_inv` | `memory::rd_inv(w)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 where `rd_addr = 0` |
| `W[w + 1]` | `rd_is_zero` | `memory::rd_is_zero(w)` | rd-is-x0 flag | 1 exactly on a live `rd` query at address 0 |
| `W[w + 2]` | `rd_selected` | `memory::rd_selected(w)` | Result before the x0 rule | what the instruction computes for `rd`, `x0` writes included, as a family's fill writes it (`fill::add_sub`, §3.3; `fill::jump_branch_slt`, §4.3); S14's `trace::build_frame_witness` writes `rd`'s write value where `rd_addr ≠ 0` and 0 elsewhere, and the frame's gates leave it free where `rd_is_zero = 1` |

Every family has an `rd` query, so every frame has the three x0 columns.

### 2.2 Each execution family's frame

| family | queries, in slot order | `w` | `M` | frame `W` | leaves a side | frame gates | gap obligations | circuit | frame fixture (`n = 22`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 `ADD_SUB_LUI_AUIPC` | pc rs1 rs2 rd **deleg** | 5 | 27 | 8 | 8 | 11 | 10 | §3 | `memory_frame_alu.bin` |
| 1 `JUMP_BRANCH_SLT` | pc rs1 rs2 rd | 4 | 21 | 7 | 4 | 10 | 8 | §4 | `memory_frame_reg.bin` |
| 2 `SHIFT_BITWISE` | pc rs1 rs2 rd | 4 | 21 | 7 | 4 | 10 | 8 | §5 | `memory_frame_reg.bin` |
| 3 `MUL_DIV` | pc rs1 rs2 rd | 4 | 21 | 7 | 4 | 10 | 8 | §6 | `memory_frame_reg.bin` |
| 4 `MEM_WORD` | pc rs1 rs2 load ram rd | 6 | 31 | 9 | 8 | 13 | 12 | §7 | `memory_frame_mem.bin` |
| 5 `MEM_SUBWORD` | pc rs1 rs2 load ram rd | 6 | 31 | 9 | 8 | 13 | 12 | §8 | `memory_frame_mem.bin` |
| 6 `ATOMICS` | pc rs1 rs2 ram rd | 5 | 26 | 8 | 8 | 11 | 10 | §9 | `memory_frame_atomics.bin` |

The frame gates are `w` mask booleanity gates, one write-back per read-only query the frame
holds — `memory::FRAME_READ_ONLY` is `rs1`, `rs2` and `load`, so it is 3 for the two memory
families and 2 for every other — and the four x0 gates. **`deleg` is not read-only** and carries
no write-back: a mirror query reads the zero tuple an invocation wrote at timestamp 0 and writes
a value of its own, which is what makes the pairing 1:1 (`delegation.md` §5.3).
`ADD_SUB_LUI_AUIPC` is the only family that holds it. **The three four-query families are the
only ones whose leaves a side are exactly their queries**; the two memory families pay two pads
a side, and `ADD_SUB_LUI_AUIPC` and `ATOMICS` three (`memory.md` §2.3).

The same layout by index. `M[a..b]` is half-open, and a query's five columns are always in the
order mask, addr, read_ts, read_value, write_value:

| columns | ALU (0) | REG (1, 2, 3) | MEM (4, 5) | ATOMICS (6) |
| --- | --- | --- | --- | --- |
| `cycle` | `M[0]` | `M[0]` | `M[0]` | `M[0]` |
| `pc_*` | `M[1..6]` | `M[1..6]` | `M[1..6]` | `M[1..6]` |
| `rs1_*` | `M[6..11]` | `M[6..11]` | `M[6..11]` | `M[6..11]` |
| `rs2_*` | `M[11..16]` | `M[11..16]` | `M[11..16]` | `M[11..16]` |
| `load_*` | — | — | `M[16..21]` | — |
| `ram_*` | — | — | `M[21..26]` | `M[16..21]` |
| `rd_*` | `M[16..21]` | `M[16..21]` | `M[26..31]` | `M[21..26]` |
| `deleg_*` | `M[21..26]` | — | — | — |
| `deleg_space` | `M[26]` | — | — | — |
| `<q>_gap_hi` | `W[0..5]` | `W[0..4]` | `W[0..6]` | `W[0..5]` |
| `rd_inv`, `rd_is_zero`, `rd_selected` | `W[5]`, `W[6]`, `W[7]` | `W[4]`, `W[5]`, `W[6]` | `W[6]`, `W[7]`, `W[8]` | `W[5]`, `W[6]`, `W[7]` |
| the family's own `W` columns start at | `W[8]` | `W[7]` | `W[9]` | `W[8]` |

`ADD_SUB_LUI_AUIPC` and `ATOMICS` now share a frame *shape* — five queries, so the same column
positions — and not a frame: slots 3 and 4 are `rd` then `deleg` in the ALU family and `ram`
then `rd` in the A extension, so the two differ in every address space, `Δ` and column name
past slot 2, and only the ALU family carries `deleg_space`, its 27th `M` column.
`memory_frame_alu.bin` and `memory_frame_atomics.bin` are different bytes.

### 2.3 The frame's gates and obligations

For the query `<q>` at slot `s`, with `m = <q>_mask`:

| name | kind | named form | code | what it holds |
| --- | --- | --- | --- | --- |
| `read_<q>`, `write_<q>` | leaves | §0.6 | `leaf(&tuple(..))` in `frame_body` | the query's read and write tuples, or 1 where it is absent |
| `read_pad_<i>`, `write_pad_<i>` | leaves, `Linear` | `1` | `frame_body` | the product's identity, padding each side to a power of two |
| `<q>_mask_boolean` | enforcing, degree 2 | `0 = m − m·m` | private `memory::booleanity` | the mask is 0 or 1 |
| `<q>_writes_back` | enforcing, degree 1 | `0 = <q>_write_value − <q>_read_value` | private `write_back` | a read-only query leaves its register or word unchanged |
| `rd_is_zero_inverse` | enforcing, degree 2 | `0 = rd_is_zero − rd_mask + rd_addr·rd_inv` | private `x0_gates`, which since S17 takes it from `gadgets::is_zero(&[(1, rd_addr)], rd_inv, rd_is_zero, rd_mask)[0]`, bytes unchanged | with the next gate: `rd_is_zero` is `rd_mask` at address 0 and 0 elsewhere |
| `rd_is_zero_at_nonzero` | enforcing, degree 2 | `0 = rd_addr·rd_is_zero` | `x0_gates`, from `is_zero(..)[1]` | the flag is 0 at a nonzero address |
| `rd_is_zero_boolean` | enforcing, degree 2 | `0 = rd_is_zero − rd_is_zero·rd_is_zero` | `x0_gates` | the flag is 0 or 1 |
| `rd_write_masked` | enforcing, degree 2 | `0 = rd_write_value − rd_selected + rd_is_zero·rd_selected` | `x0_gates` | the rd write is the result, or 0 into `x0` |
| `gap_hi_<q>` | `TIMESTAMP` obligation, selector `m` | `<q>_gap_hi < 2^19` | private `gap_lookups` | the gap's high chunk |
| `gap_lo_<q>` | `TIMESTAMP` obligation, selector `m` | `4·cycle − <q>_read_ts − 2^19·<q>_gap_hi + (Δ_q − 1) < 2^19` | `gap_lookups` | the low chunk; with the high one, `read_ts < 4·cycle + Δ_q` |

---

## 3. `ADD_SUB_LUI_AUIPC` — family 0

### 3.1 Header

`family_circuit(0, n)` is `add_sub::artifact(n)` with `add_sub::channels()`, built by
`memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` (`QUERIES` and the `SLOT_*`
constants are private to `add_sub.rs`). Normative spec: `shard-proof.md` §8. Fill:
`prover::family_fill(0)`, the private `fill::add_sub`.

**69 committed columns (27 `M`, 35 `W`, 7 `S`)** and two virtual tables. Gate list 0 writes 68
leaves and holds 63 enforcing gates. 15 lookups on three channels, 8 outputs. At `n = 20`, the
height S16 proves, there are 25 gate lists, the top is `L25`, and the circuit has 298 inner
columns and 361 relations; at `n = 22`, the committed fixture's height, 27 lists, `L27`, 314
inner columns and 377 relations. `artifact` panics unless the frame is `QUERIES` and the channels
carry exactly 10, 4 and 1 obligations.

**The frame is what sets those numbers, and it narrowed when the POSIX layer went.** `read`
(63) and `write` (64) are retired and their numbers burned (`ecall-abi.md` §4), so
the `arg1` and `arg2` queries — an ecall row's `a1` and `a2`, which only those two calls ever
passed — became unreachable, and the query table dropped from nine entries to seven
(`memory.md` §2.1, §2.1 here). This family lost a third query with them: its `ram` query was the
ecall **transfer row's** alone, no instruction routed here touches memory, and an ecall is now
exactly one cycle. So `frame_queries(0)` went from eight queries to **five** —
pc `rs1` `rs2` `rd` `deleg` — and with them went 15 `M` columns, three `*_gap_hi` witness
columns, three mask booleanity gates, the two write-backs `arg1` and `arg2` carried (`ram` is
not read-only and carried none) and the three `arg1_mask_rule`, `arg2_mask_rule` and
`ram_mask_rule` gates, each of which said `mask = 0` about a query the family already could not
make. Immediately before the change the circuit was
85 committed columns (42/36/7), 100 leaves, 65 enforcing gates, 21 lookups, 26 gate lists, 368
inner columns and 433 relations at `n = 20`; three of those figures had already moved past what
this page recorded at S23, S26's fourth delegation type (`MOD_MUL`) having added one `W`
column, three enforcing gates and three relations. **S26c then added two more types**,
`SHA256_COMP`'s and `EC_ADD`'s, whose request selectors sit at `W[26]` and `W[27]`: two `W`
columns, six enforcing gates and six relations, which moved `wrap` and every `W` column after it
up by two and every relation from `ecall_is_exit` on up by six. This entry is read from the
current artifact throughout: the committed `add_sub.bin`, SHA-256 `a6113128…6cae38c7`, at
`n = 22`.

**Two consequences are worth naming, because each undoes something S21 bought.** Five queries no
longer fill an eight-leaf product tree, so each side pays **three** literal-1 pad leaves where
eight paid none — the shape `ATOMICS` has had since S19 (§9.4). And ten gap obligations with
the table fraction is eleven leaves, which fits a 16-leaf tree, so the timestamp tree stopped
setting the depth: the circuit is **five** row-wise lists deep where S21 made it six, and its
layer widths are `MEM_WORD`'s exactly (§1.3, §7.7).

**What did not move**: the frozen rows of `docs/spec/execution-trace.md`, the `deleg` mirror and
everything S21 and S23 built on it, and the family's meaning. `EXIT` is still the only ecall
that halts, and the family still refuses every ecall number but `EXIT`'s and the six delegation
types this form knows (gates 93, 96, 99, 102, 105, 108 and 109). `artifact` also panics on every
refusal of the assembly, among them `n < 19` (the 19-bit timestamp table needs 19 variables) and
`n > 30` (`MAX_TRACE_VARS`); `family_circuit` returns `None` for both rather than calling it.

### 3.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::add_sub_lui_auipc`; the system
kind is split by the code the decoded table puts in `imm`
(`constants::extra_mask::system_code`).

| row kind | bit (`decoded_mask`) | `decoded_imm` | queries present | `rd_selected` | `wrap` | `next_pc` | provable at S16 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `add` | 3 (8) | 0 | pc rs1 rs2 rd | `rs1 + rs2 mod 2^32` | the carry | the fall-through | yes |
| `sub` | 4 (16) | 0 | pc rs1 rs2 rd | `rs1 − rs2 mod 2^32` | the borrow, `rs1 < rs2` | the fall-through | yes |
| `addi` | 1 (2) | the immediate, sign-extended, as a `u32` | pc rs1 rd | `rs1 + imm mod 2^32` | the carry | the fall-through | yes |
| `auipc` | 2 (4) | the shifted upper immediate, as a `u32` | pc rd | `pc + imm mod 2^32` | the carry | the fall-through | yes |
| `lui` | 5 (32) | the value loaded | pc rd | `imm` | 0; on this row only `wrap_boolean` constrains it, the sum and difference gates vanishing | the fall-through | yes |
| system: fence | 0 (1) | `FENCE` = 2 | pc | 0 | 0; as on a lui row, only `wrap_boolean` constrains it | the fall-through | yes, `is_fence = 1` |
| system: ecall | 0 (1) | `ECALL` = 0 | pc; rs1 = `x17`, reading 93; rs2 = `x10`; rd = `x10` | `a0` as read | 0; as on a lui row, only `wrap_boolean` constrains it | `HALT_PC` = 1 | `EXIT` only, `is_ecall = 1`, every `is_deleg_t = 0` |
| system: a **delegation request** (S21; one row kind per type since S23) | 0 (1) | `ECALL` = 0 | pc; rs1 = `x17`, reading the type's number — `0x507`, `0x500`, `0x502`, `0x504`, `0x508` or `0x506`; rs2 = `x10`, the frame base; rd = `x10`; **deleg**, at that base | 0 | 0; as above | the fall-through | yes, `is_ecall = 1` **and** exactly one `is_deleg_t = 1` |
| system: ebreak | 0 (1) | `EBREAK` = 1 | — | — | — | — | never: no row satisfies `system_split` with the two code gates |
| padding | none; all 0 | 0 | none | 0 | 0 | 0 | every row past the shard's last cycle |

A compressed instruction (`c.add`, `c.li`, …) is one of these kinds at its own length: its
table row's `next_pc` is `pc + 2`.

**There is no transfer-cycle row kind any more.** An ecall's buffer traffic used to reach RAM
through extra cycles carrying a RAM query apiece, and this family's frame carried the `ram`
query for them and nothing else; the two calls that made them are retired, so the row kind, the
query and the `ram_mask_rule` that forbade the row all went together (`ecall-abi.md` §4,
`public-values.md` §1). An ecall is one cycle.

A delegation request is the family's second provable ecall kind and the only row kind it has
gained since S16. It is an ordinary ecall row with one type selector set, one extra query, one
extra memory column and three zeroings; what makes it *an invocation of that type* is nothing
here — it is the mirror query's tuple meeting an invocation's in the one global multiset
(§12.4 and its counterparts in §13, §14, §18, §19 and §20, `delegation.md` §5.3). **Which type
is a property of the row, not of the frame**: the selector says which, and `deleg_space_rule`
(§3.5, gate 127) copies that type's address-space tag into the row's `deleg_space` cell, which
is what the mirror's leaf reads. The six types are one row kind here and six families
elsewhere; this family never sees a delegation frame, a permutation or a delegation shard.

### 3.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §3.4 and §3.6.

**Memory-argument columns, `M[0..27]`** — filled by `trace::build_memory_columns`; committed in
`PublicInputs::memory_commitments`, absorbed at G8 before the memory challenges.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the cycle `c` | leaves `write_*` (all 5); obligations `gap_lo_*` (all 5) |
| `M[1]` | `pc_mask` | `frame(0, FIELD_MASK)` | Row is live | 1 | leaves `read_pc`, `write_pc`; `pc_mask_boolean`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `deleg_mask_rule`; selector of `gap_hi_pc`, `gap_lo_pc`, the four `RANGE16` obligations and `decode_row` |
| `M[2]` | `pc_addr` | `frame(0, FIELD_ADDR)` | PC address | 0 | leaves `read_pc`, `write_pc` |
| `M[3]` | `pc_read_ts` | `frame(0, FIELD_READ_TS)` | Previous pc write | `4(c − 1)` | leaf `read_pc`; `gap_lo_pc` |
| `M[4]` | `pc_read_value` | `frame(0, FIELD_READ_VALUE)` | Current pc | the instruction's pc | leaf `read_pc`; `add_addi_auipc`; `decode_row` position 0 |
| `M[5]` | `pc_write_value` | `frame(0, FIELD_WRITE_VALUE)` | Next pc | the fall-through, or `HALT_PC` on the exit row | leaf `write_pc`; `next_pc_rule`; `next_pc_lo_range` |
| `M[6]` | `rs1_mask` | `frame(1, FIELD_MASK)` | rs1 present | 1 on add, sub, addi and every ecall row | leaves `read_rs1`, `write_rs1`; `rs1_mask_boolean`, `rs1_mask_rule`, `rs1_addr_rule`, `rs1_value_masked`; selector of `gap_hi_rs1`, `gap_lo_rs1` |
| `M[7]` | `rs1_addr` | `frame(1, FIELD_ADDR)` | rs1 register | the decoded `rs1`, or 17 (`a7`) on an ecall row | leaves `read_rs1`, `write_rs1`; `rs1_addr_rule` |
| `M[8]` | `rs1_read_ts` | `frame(1, FIELD_READ_TS)` | rs1 previous write | | leaf `read_rs1`; `gap_lo_rs1` |
| `M[9]` | `rs1_read_value` | `frame(1, FIELD_READ_VALUE)` | rs1 value | the `a7` an ecall row reads | leaf `read_rs1`; `rs1_writes_back`, `deleg_9_number`, `deleg_10_number`, `deleg_11_number`, `deleg_15_number`, `deleg_16_number`, `deleg_17_number`, `ecall_is_exit`, `rs1_value_masked`, `add_addi_auipc`, `sub` |
| `M[10]` | `rs1_write_value` | `frame(1, FIELD_WRITE_VALUE)` | rs1 written back | `rs1_read_value` | leaf `write_rs1`; `rs1_writes_back` |
| `M[11]` | `rs2_mask` | `frame(2, FIELD_MASK)` | rs2 present | 1 on add, sub and every ecall row | leaves `read_rs2`, `write_rs2`; `rs2_mask_boolean`, `rs2_mask_rule`, `rs2_addr_rule`, `rs2_value_masked`; selector of `gap_hi_rs2`, `gap_lo_rs2` |
| `M[12]` | `rs2_addr` | `frame(2, FIELD_ADDR)` | rs2 register | the decoded `rs2`, or 10 (`a0`) on an ecall row | leaves `read_rs2`, `write_rs2`; `rs2_addr_rule` |
| `M[13]` | `rs2_read_ts` | `frame(2, FIELD_READ_TS)` | rs2 previous write | | leaf `read_rs2`; `gap_lo_rs2` |
| `M[14]` | `rs2_read_value` | `frame(2, FIELD_READ_VALUE)` | rs2 value | the frame base on a request row | leaf `read_rs2`; `rs2_writes_back`, `rs2_value_masked`, `add_addi_auipc`, `sub`, `deleg_addr_rule` |
| `M[15]` | `rs2_write_value` | `frame(2, FIELD_WRITE_VALUE)` | rs2 written back | `rs2_read_value` | leaf `write_rs2`; `rs2_writes_back` |
| `M[16]` | `rd_mask` | `frame(3, FIELD_MASK)` | rd present | 1 on every kind but the fence | leaves `read_rd`, `write_rd`; `rd_mask_boolean`, `rd_is_zero_inverse`, `rd_mask_rule`, `rd_addr_rule`; selector of `gap_hi_rd`, `gap_lo_rd` |
| `M[17]` | `rd_addr` | `frame(3, FIELD_ADDR)` | rd register | the decoded `rd`, or 10 (`a0`) on an ecall row | leaves `read_rd`, `write_rd`; `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_addr_rule` |
| `M[18]` | `rd_read_ts` | `frame(3, FIELD_READ_TS)` | rd previous write | | leaf `read_rd`; `gap_lo_rd` |
| `M[19]` | `rd_read_value` | `frame(3, FIELD_READ_VALUE)` | rd old value | | leaf `read_rd`; `exit_status` |
| `M[20]` | `rd_write_value` | `frame(3, FIELD_WRITE_VALUE)` | rd new value | `rd_selected`, or 0 into `x0` | leaf `write_rd`; `rd_write_masked` |
| `M[21]` | `deleg_mask` | `frame(4, FIELD_MASK)` | Mirror query present | 1 on a delegation request, 0 on every other row | leaves `read_deleg`, `write_deleg`; `deleg_mask_boolean`, `deleg_mask_rule`, `deleg_writes_no_register`, `deleg_read_ts_zero`, `deleg_read_value_zero`, `deleg_addr_rule`; selector of `gap_hi_deleg`, `gap_lo_deleg` |
| `M[22]` | `deleg_addr` | `frame(4, FIELD_ADDR)` | Frame base handed over | the `a0` the row read, its invocation's frame pointer | leaves `read_deleg`, `write_deleg`; `deleg_addr_rule` |
| `M[23]` | `deleg_read_ts` | `frame(4, FIELD_READ_TS)` | Answer-tuple timestamp | 0, the stamp no cycle can make | leaf `read_deleg`; `deleg_read_ts_zero`, `gap_lo_deleg` |
| `M[24]` | `deleg_read_value` | `frame(4, FIELD_READ_VALUE)` | Answer-tuple value | 0 | leaf `read_deleg`; `deleg_read_value_zero` |
| `M[25]` | `deleg_write_value` | `frame(4, FIELD_WRITE_VALUE)` | Consumed-anchor value | **free**; 0 in an honest fill | leaf `write_deleg` **and nothing else**: no gate, no obligation, no table (§3.10) |
| `M[26]` | `deleg_space` | `memory::deleg_space(5)` | Requested delegation type | that type's `constants::address_space` tag — 4, 5, 6, 7, 8 or 9 — on a request row, 0 on every other | leaves `read_deleg`, `write_deleg`; `deleg_space_rule` |

The frame's slots in `add_sub.rs` are `SLOT_PC = 0`, `SLOT_RS1 = 1`, `SLOT_RS2 = 2`,
`SLOT_RD = 3` and `SLOT_DELEG = 4`, so `frame(3, ..)` is `frame(SLOT_RD, ..)` there. **Slot is
not query id**: `rd` is id 5 and `deleg` id 6 in `memory::FRAME_NAMES`, and neither equals its
slot in a frame this narrow — the id is what fixes the column's address space and its `Δ`, the
slot is what fixes its position (§2.1). `deleg_space` is not in that grid: it sits past the last
query's five fields at `M[1 + 5w]`, and a frame without the `deleg` query does not carry it at
all (§2.2).

**Every column of this frame is one some row of the family makes.** Until the POSIX layer went,
fifteen `M` columns and three gap chunks — the `arg1`, `arg2` and `ram` groups — were held to 0
on every row by three `mask = 0` gates, committed and opened by every shard, and carried
nothing; they were the I/O-binding stage's, and what that stage did with them was delete them
(§26 observation 2).

**Why the type rides a memory column, and why one query serves all six.** The mirror's leaf
has to name the requested type — the tag is its `AS` term — and a leaf may read no `W` column,
because `W` is committed after the memory challenges (`memory.md` §8, `check_memory`'s
provenance rule). The type selectors are `W` columns, so the tag crosses into the leaf through
`deleg_space`, which `deleg_space_rule` pins to them; with one delegation family the tag *was*
a literal on the mask, and with six it cannot be. And one `deleg` query serves every type
rather than one query apiece because a second mirror query would need a seventh
`trace::Role` (`execution-trace.md` §7). `delegation.md` §5.1 is that rule, and §10.1 records
what S21 wrote instead and why it was not implementable.

**Witness columns, `W[0..35]`** — `W[0..8]` filled by `trace::build_frame_witness`, `W[7..32]`
by `fill::add_sub` (which overwrites `rd_selected`), `W[32..35]` by
`trace::build_multiplicities` inside `prover::shard_columns`; committed in
`ShardProof::witness_commitments`, absorbed at S3 before `g` and `β`. The selectors are
`add_sub::is_delegation(i)` and the seven columns after them `add_sub::wrap(types)` and its
kin, each a function of how many delegation types the circuit knows; `add_sub::WRAP`,
`RD_HI`, `PC_WRAP`, `NEXT_PC_HI` and `MULTIPLICITIES` are those functions at
`constants::delegation::BASE_TYPES` = 6, this form's addresses (§3.11 is the other form).

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0]` | `pc_gap_hi` | `memory::gap_hi(0)` | pc gap, high chunk | 0: a pc read's gap is always 3 | `gap_hi_pc`, `gap_lo_pc` |
| `W[1]` | `rs1_gap_hi` | `gap_hi(1)` | rs1 gap, high chunk | `gap >> 19` | `gap_hi_rs1`, `gap_lo_rs1` |
| `W[2]` | `rs2_gap_hi` | `gap_hi(2)` | rs2 gap, high chunk | | `gap_hi_rs2`, `gap_lo_rs2` |
| `W[3]` | `rd_gap_hi` | `gap_hi(3)` | rd gap, high chunk | | `gap_hi_rd`, `gap_lo_rd` |
| `W[4]` | `deleg_gap_hi` | `gap_hi(4)` | Mirror-query gap, high chunk | `(4c + 2) >> 19` on a delegation row, 0 elsewhere | `gap_hi_deleg`, `gap_lo_deleg` |
| `W[5]` | `rd_inv` | `memory::rd_inv(5)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[6]` | `rd_is_zero` | `memory::rd_is_zero(5)` | rd is `x0` | | `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_is_zero_boolean`, `rd_write_masked` |
| `W[7]` | `rd_selected` | `memory::rd_selected(5)`; `sel` in `add_sub.rs` | Result | the kind's result (§3.2), `rd = x0` included: `fill::add_sub` overwrites the 0 that S14's builder writes there | `rd_write_masked`, `add_addi_auipc`, `sub`, `lui`, `exit_status`, `deleg_writes_no_register`; `rd_lo_range` |
| `W[8]` | `decoded_next_pc` | `add_sub::DECODED[0]` | Decoded fall-through | the table row's `next_pc` | `next_pc_rule`; `decode_row` position 1 |
| `W[9]` | `decoded_rs1` | `add_sub::DECODED[1]` | Decoded rs1 | | `rs1_addr_rule`; `decode_row` position 2 |
| `W[10]` | `decoded_rs2` | `add_sub::DECODED[2]` | Decoded rs2 | | `rs2_addr_rule`; `decode_row` position 3 |
| `W[11]` | `decoded_rd` | `add_sub::DECODED[3]` | Decoded rd | | `rd_addr_rule`; `decode_row` position 4 |
| `W[12]` | `decoded_imm` | `add_sub::DECODED[4]` | Decoded immediate, or system code | | `ecall_code`, `fence_code`, `add_addi_auipc`, `lui`; `decode_row` position 5 |
| `W[13]` | `decoded_mask` | `add_sub::DECODED[5]` | Decoded kind mask | `1 << bit` | `decoded_mask_bits`; `decode_row` position 6 |
| `W[14]` | `kind_system` | `add_sub::KINDS[0]`; `KIND_SYSTEM` in `add_sub.rs` (index `add_sub_lui_auipc::SYSTEM`) | System row | | `kind_system_boolean`, `decoded_mask_bits`, `system_split` |
| `W[15]` | `kind_addi` | `add_sub::KINDS[1]`; `KIND_ADDI` in `add_sub.rs` (index `add_sub_lui_auipc::ADDI`) | addi row | | `kind_addi_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rd_mask_rule`, `add_addi_auipc` |
| `W[16]` | `kind_auipc` | `add_sub::KINDS[2]`; `KIND_AUIPC` in `add_sub.rs` (index `add_sub_lui_auipc::AUIPC`) | auipc row | | `kind_auipc_boolean`, `decoded_mask_bits`, `rd_mask_rule`, `add_addi_auipc` |
| `W[17]` | `kind_add` | `add_sub::KINDS[3]`; `KIND_ADD` in `add_sub.rs` (index `add_sub_lui_auipc::ADD`) | add row | | `kind_add_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `add_addi_auipc` |
| `W[18]` | `kind_sub` | `add_sub::KINDS[4]`; `KIND_SUB` in `add_sub.rs` (index `add_sub_lui_auipc::SUB`) | sub row | | `kind_sub_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `sub` |
| `W[19]` | `kind_lui` | `add_sub::KINDS[5]`; `KIND_LUI` in `add_sub.rs` (index `add_sub_lui_auipc::LUI`) | lui row | | `kind_lui_boolean`, `decoded_mask_bits`, `rd_mask_rule`, `lui` |
| `W[20]` | `is_ecall` | `add_sub::IS_ECALL` | Ecall row: the exit, or a delegation | 1 on a system row with code `ECALL` | `is_ecall_boolean`, `system_split`, `ecall_code`, `ecall_is_exit`, `deleg_9_is_an_ecall`, `deleg_10_is_an_ecall`, `deleg_11_is_an_ecall`, `deleg_15_is_an_ecall`, `deleg_16_is_an_ecall`, `deleg_17_is_an_ecall`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `rs1_addr_rule`, `rs2_addr_rule`, `rd_addr_rule`, `exit_status`, `next_pc_rule` |
| `W[21]` | `is_fence` | `add_sub::IS_FENCE` | Fence row | 1 on a system row with code `FENCE` | `is_fence_boolean`, `system_split`, `fence_code` |
| `W[22]` | `is_deleg_9` | `add_sub::IS_DELEGATION[0]`; `add_sub::IS_KECCAK`, S21's name kept | `KECCAK_F` request row | 1 on an ecall row whose `a7` is `0x507` (`0x501` until S26d retired it) | `is_deleg_9_boolean`, `deleg_9_is_an_ecall`, `deleg_9_number`, `ecall_is_exit`, `deleg_mask_rule`, `exit_status`, `deleg_space_rule`, `next_pc_rule` |
| `W[23]` | `is_deleg_10` | `add_sub::IS_DELEGATION[1]` | `POSEIDON2` request row (S23) | 1 on an ecall row whose `a7` is `0x500` | `is_deleg_10_boolean`, `deleg_10_is_an_ecall`, `deleg_10_number`, `ecall_is_exit`, `deleg_mask_rule`, `exit_status`, `deleg_space_rule`, `next_pc_rule` |
| `W[24]` | `is_deleg_11` | `add_sub::IS_DELEGATION[2]` | `FR_ARITH` request row (S23) | 1 on an ecall row whose `a7` is `0x502` | `is_deleg_11_boolean`, `deleg_11_is_an_ecall`, `deleg_11_number`, `ecall_is_exit`, `deleg_mask_rule`, `exit_status`, `deleg_space_rule`, `next_pc_rule` |
| `W[25]` | `is_deleg_15` | `add_sub::IS_DELEGATION[3]` | `MOD_MUL` request row (S26) | 1 on an ecall row whose `a7` is `0x504` | `is_deleg_15_boolean`, `deleg_15_is_an_ecall`, `deleg_15_number`, `ecall_is_exit`, `deleg_mask_rule`, `exit_status`, `deleg_space_rule`, `next_pc_rule` |
| `W[26]` | `is_deleg_16` | `add_sub::IS_DELEGATION[4]` | `SHA256_COMP` request row (S26c) | 1 on an ecall row whose `a7` is `0x508` (`0x505` until S26e retired it) | `is_deleg_16_boolean`, `deleg_16_is_an_ecall`, `deleg_16_number`, `ecall_is_exit`, `deleg_mask_rule`, `exit_status`, `deleg_space_rule`, `next_pc_rule` |
| `W[27]` | `is_deleg_17` | `add_sub::IS_DELEGATION[5]` | `EC_ADD` request row (S26c) | 1 on an ecall row whose `a7` is `0x506` | `is_deleg_17_boolean`, `deleg_17_is_an_ecall`, `deleg_17_number`, `ecall_is_exit`, `deleg_mask_rule`, `exit_status`, `deleg_space_rule`, `next_pc_rule` |
| `W[28]` | `wrap` | `add_sub::WRAP` | Carry or borrow | | `add_addi_auipc`, `sub`, `wrap_boolean` |
| `W[29]` | `rd_hi` | `add_sub::RD_HI` | Result, high halfword | `rd_selected >> 16` | `rd_hi_range`, `rd_lo_range` |
| `W[30]` | `pc_wrap` | `add_sub::PC_WRAP` | Next-pc overflow | 0 | `pc_wrap_boolean`, `next_pc_rule` |
| `W[31]` | `next_pc_hi` | `add_sub::NEXT_PC_HI` | Next pc, high halfword | `pc_write_value >> 16` | `next_pc_hi_range`, `next_pc_lo_range` |
| `W[32]` | `mult_timestamp` | `add_sub::MULTIPLICITIES[0]` | Timestamp-table count | per table row `t`: the gated gap chunks (`mask·chunk`) equal to `t`, credited to rows below `2^19` | leaf `timestamp_table_num` |
| `W[33]` | `mult_range16` | `add_sub::MULTIPLICITIES[1]` | 16-bit-table count | per table row `t`: the gated halfwords (`pc_mask·halfword`) equal to `t`, credited to rows below `2^16` | leaf `range16_table_num` |
| `W[34]` | `mult_decoder` | `add_sub::MULTIPLICITIES[2]` | Decoder-table count | per table row `t`: the live cycles at pc `2t`; and every padding row's switched-off tuple (`MINUS_ONE` in all seven positions) on the table's lowest non-live row, which is row 0, since pc 0 lies below `RAM_ORIGIN` and holds no instruction | leaf `decoder_table_num` |

A switched-off obligation's gated tuple is 0 (`s·e` at `s = 0`), so row 0 of `mult_timestamp`
and `mult_range16` counts every switched-off obligation: all 10 timestamp and all 4 `RANGE16`
obligations of each padding row, and in `mult_timestamp` also the two `deleg` chunks of every
row that is not a delegation request and the two chunks of any `rs1`, `rs2` or `rd` query the
row does not make. The `RANGE16` obligations are selected by `pc_mask`, so none is off on a live
row. Row 0 also counts every live chunk whose value is 0, such as `pc_gap_hi` on every live row.

**Setup columns, `S[0..7]`** — the family's decoded table, `program::lookup_tuple(0)` order,
filled by `program::FamilyTable::column_poly(j)`; committed in program identity
(`program::setup_commitments`) and carried as `VerifyingKey::setup_commitments` for the family.
Each is read only by `decoder_table_den`, at the `β` power in the last column.

| address | name | Rust | descriptive name | table field | weight |
| --- | --- | --- | --- | --- | --- |
| `S[0]` | `table_pc` | `add_sub::channels()[2].table[0]` | Table pc | `RowField::Pc` | 1 |
| `S[1]` | `table_next_pc` | `channels()[2].table[1]` | Table fall-through | `RowField::NextPc` | `β` |
| `S[2]` | `table_rs1` | `channels()[2].table[2]` | Table rs1 | `RowField::Rs1` | `β²` |
| `S[3]` | `table_rs2` | `channels()[2].table[3]` | Table rs2 | `RowField::Rs2` | `β³` |
| `S[4]` | `table_rd` | `channels()[2].table[4]` | Table rd | `RowField::Rd` | `β⁴` |
| `S[5]` | `table_imm` | `channels()[2].table[5]` | Table immediate | `RowField::Imm` | `β⁵` |
| `S[6]` | `table_extra_mask` | `channels()[2].table[6]` | Table kind mask | `RowField::ExtraMask` | `β⁶` |

`add_sub::TABLE_WIDTH` is 7.

**Virtual tables** — never committed, never opened; `gkr_verify::verify` evaluates their
closed forms.

| address | name | Rust | descriptive name | value at row `y` | read by |
| --- | --- | --- | --- | --- | --- |
| `V[range19]` | `range19` | `VirtualKind::Range19`, wire tag 2 | 19-bit range table | `y mod 2^19` | `timestamp_table_den` |
| `V[range16]` | `range16` | `VirtualKind::Range16`, wire tag 3 | 16-bit range table | `y mod 2^16` | `range16_table_den` |

### 3.4 Gate list 0: the 68 leaves

A leaf's relation number equals its `L1` offset, 0 to 67.

**The memory product trees.** The read side is `L1[0..8]` and the write side `L1[8..16]`, each
leaf per §0.6. Five queries fill eight leaves a side, so each side carries **three** pads — the
shape `ATOMICS` has (§9.4). This family paid one pad a side at S16's seven queries and none at
S21's eight; the POSIX layer's deletion took three queries away and put three pads back.

| `L1` | node | mask | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `read_pc` | `M[1]` | 3 | `M[2]` | `M[3]` | `M[4]` |
| 1 | `read_rs1` | `M[6]` | 1 | `M[7]` | `M[8]` | `M[9]` |
| 2 | `read_rs2` | `M[11]` | 1 | `M[12]` | `M[13]` | `M[14]` |
| 3 | `read_rd` | `M[16]` | 1 | `M[17]` | `M[18]` | `M[19]` |
| 4 | `read_deleg` | `M[21]` | **`M[26]`** | `M[22]` | `M[23]` | `M[24]` |
| 5, 6, 7 | `read_pad_0`, `read_pad_1`, `read_pad_2` | — | — | — | — | the literal 1 |
| 8 | `write_pc` | `M[1]` | 3 | `M[2]` | `4·M[0] + 0` | `M[5]` |
| 9 | `write_rs1` | `M[6]` | 1 | `M[7]` | `4·M[0] + 1` | `M[10]` |
| 10 | `write_rs2` | `M[11]` | 1 | `M[12]` | `4·M[0] + 2` | `M[15]` |
| 11 | `write_rd` | `M[16]` | 1 | `M[17]` | `4·M[0] + 3` | `M[20]` |
| 12 | `write_deleg` | `M[21]` | **`M[26]`** | `M[22]` | `4·M[0] + 3` | `M[25]` |
| 13, 14, 15 | `write_pad_0`, `write_pad_1`, `write_pad_2` | — | — | — | — | the literal 1 |

**The `deleg` pair is the only one whose `AS` is a column and not a literal** (S23). Every
other leaf takes its space from `memory::FRAME_SPACE`, a compile-time constant of the query, so
the term is `(tag, mask)`; the mirror's is `(1, deleg_space, mask)`, the product
`deleg_space · deleg_mask`, because one query serves every delegation type and which one is a
property of the row (§2.2, `delegation.md` §5.1). `deleg_space` holds
`address_space::DELEGATION_KECCAK_F` = 4, `DELEGATION_POSEIDON2` = 5, `DELEGATION_FR_ARITH` = 6,
`DELEGATION_MOD_MUL` = 7, `DELEGATION_SHA256_COMP` = 8 or `DELEGATION_EC_ADD` = 9, and
`deleg_space_rule` is what ties it to the row's type selector.
A row requesting nothing has `deleg_space` 0 and `deleg_mask` 0 alike, so the leaf is the
literal 1 there whichever way it is read.

Four gates below pin what this pair may be — `deleg_space_rule`, `deleg_read_ts_zero`,
`deleg_read_value_zero` and `deleg_addr_rule` — and together they say a request of type `t`
reads the tuple `T(AS_t, rs2_read_value, 0, 0)` and writes
`T(AS_t, rs2_read_value, 4·cycle + 3, deleg_write_value)`. Only an invocation of §12, §13, §14,
§18, §19 or §20 writes a timestamp-0 tuple in its own space, and only a request of that type
reads one, which is what makes the pairing 1:1 (`delegation.md` §5.3). The tags are pairwise
distinct — the same `const` assertion in `add_sub.rs` that holds the ecall numbers apart holds
the tags apart — so a request of one type cannot be answered by an invocation of another.

Two of them in full:

```text
L{1}[0]  read_pc
  positional  1 + γ_M·M[1] − M[1] + 3·M[1] + α_addr·M[2]·M[1] + α_ts·M[3]·M[1] + α_val·M[4]·M[1]
  named       pc_mask·T(PC, pc_addr, pc_read_ts, pc_read_value) + 1 − pc_mask

L{1}[12]  write_deleg
  positional  1 + γ_M·M[21] − M[21] + α_ts·M[21] ×3 + M[26]·M[21] + α_addr·M[22]·M[21]
                + α_ts·M[0]·M[21] ×4 + α_val·M[25]·M[21]
  named       deleg_mask·T(deleg_space, deleg_addr, 4·cycle + 3, deleg_write_value)
                + 1 − deleg_mask
```

**The `timestamp` fraction tree**, `L1[16..48]`: 16 fractions, the table's then 10 gap
obligations then 5 pads. Fraction `i` is `(L1[16 + 2i], L1[17 + 2i])`, named `<node>_num` and
`<node>_den`. Eleven leaves fit a 16-leaf tree with room to spare, which is why this circuit is
five row-wise lists deep and not six (§1.3, §26 observation 20).

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 16, 17 | `timestamp_table` | `−mult_timestamp` | `V[range19] + g` |
| 1 | 18, 19 | `gap_hi_pc` | 1 | `g + pc_mask·pc_gap_hi` |
| 2 | 20, 21 | `gap_lo_pc` | 1 | `g − pc_mask + 4·pc_mask·cycle − pc_mask·pc_read_ts − 2^19·pc_mask·pc_gap_hi` |
| 3 | 22, 23 | `gap_hi_rs1` | 1 | `g + rs1_mask·rs1_gap_hi` |
| 4 | 24, 25 | `gap_lo_rs1` | 1 | `g + 4·rs1_mask·cycle − rs1_mask·rs1_read_ts − 2^19·rs1_mask·rs1_gap_hi` |
| 5 | 26, 27 | `gap_hi_rs2` | 1 | `g + rs2_mask·rs2_gap_hi` |
| 6 | 28, 29 | `gap_lo_rs2` | 1 | `g + rs2_mask + 4·rs2_mask·cycle − rs2_mask·rs2_read_ts − 2^19·rs2_mask·rs2_gap_hi` |
| 7 | 30, 31 | `gap_hi_rd` | 1 | `g + rd_mask·rd_gap_hi` |
| 8 | 32, 33 | `gap_lo_rd` | 1 | `g + 2·rd_mask + 4·rd_mask·cycle − rd_mask·rd_read_ts − 2^19·rd_mask·rd_gap_hi` |
| 9 | 34, 35 | `gap_hi_deleg` | 1 | `g + deleg_mask·deleg_gap_hi` |
| 10 | 36, 37 | `gap_lo_deleg` | 1 | `g + 2·deleg_mask + 4·deleg_mask·cycle − deleg_mask·deleg_read_ts − 2^19·deleg_mask·deleg_gap_hi` |
| 11–15 | 38, 39 … 46, 47 | `timestamp_pad_0` … `timestamp_pad_4` | 0 | 1 |

The linear term on a `gap_lo` denominator's mask is `(Δ_q − 1)·m`: `−1` for pc, none for rs1,
`+1` for rs2, `+2` for rd and deleg. **`Δ` is the query's, not the slot's** — `rd` is id 5 and
`deleg` id 6 in `memory::FRAME_DELTA`, and both write at `4·cycle + 3` — so dropping `arg1`,
`arg2` and `ram` from the frame moved every column of the `rd` and `deleg` groups down and
changed no constant in either.
In positional form fraction 2's denominator is
`g − M[1] + 4·M[1]·M[0] − M[1]·M[3] − 2^19·M[1]·W[0]`.

**The `deleg` gap pair is discharged against a timestamp the invocation never wrote.** Its
`read_ts` is held to 0 by `deleg_read_ts_zero`, so `gap_lo_deleg` is `4·cycle + 2` on a
delegation row — a real value below `2^19` only for the first 131,071 cycles, which is why
`deleg_gap_hi` is a committed chunk like every other and not an assumed zero.

**The `range16` fraction tree**, `L1[48..64]`: 8 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 48, 49 | `range16_table` | `−mult_range16` | `V[range16] + g` |
| 1 | 50, 51 | `rd_hi_range` | 1 | `g + pc_mask·rd_hi` |
| 2 | 52, 53 | `rd_lo_range` | 1 | `g + pc_mask·rd_selected − 2^16·pc_mask·rd_hi` |
| 3 | 54, 55 | `next_pc_hi_range` | 1 | `g + pc_mask·next_pc_hi` |
| 4 | 56, 57 | `next_pc_lo_range` | 1 | `g + pc_mask·pc_write_value − 2^16·pc_mask·next_pc_hi` |
| 5 | 58, 59 | `range16_pad_0` | 0 | 1 |
| 6 | 60, 61 | `range16_pad_1` | 0 | 1 |
| 7 | 62, 63 | `range16_pad_2` | 0 | 1 |

**The `decoder` fraction tree**, `L1[64..68]`: 2 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 64, 65 | `decoder_table` | `−mult_decoder` | `table_pc + β·table_next_pc + β²·table_rs1 + β³·table_rs2 + β⁴·table_rd + β⁵·table_imm + β⁶·table_extra_mask + g` |
| 1 | 66, 67 | `decode_row` | 1 | `g_dec + (1 + β + β² + β³ + β⁴ + β⁵ + β⁶)·pc_mask + pc_mask·pc_read_value + β·pc_mask·decoded_next_pc + β²·pc_mask·decoded_rs1 + β³·pc_mask·decoded_rs2 + β⁴·pc_mask·decoded_rd + β⁵·pc_mask·decoded_imm + β⁶·pc_mask·decoded_mask` |

```text
L{1}[67]  decode_row_den
  positional  g_dec + M[1] + β·M[1] + β²·M[1] + β³·M[1] + β⁴·M[1] + β⁵·M[1] + β⁶·M[1]
              + M[1]·M[4] + β·M[1]·W[8] + β²·M[1]·W[9] + β³·M[1]·W[10]
              + β⁴·M[1]·W[11] + β⁵·M[1]·W[12] + β⁶·M[1]·W[13]
  reads as    g + Σ_j β^j·(pc_mask·(v_j + 1) − 1), v = (pc_read_value, decoded_next_pc, …,
              decoded_mask):
              the claimed row at pc_mask = 1, and the table's MINUS_ONE padding row at 0
```

### 3.5 Gate list 0: the 63 enforcing gates

Relations 68–130, in list order. Each block gives the relation number, the name, what the gate
is for, its shape and degree, the constructor, the stored positional form, and the named form,
factored where that is easier to read. Every factoring re-expands to the stored terms.

**A. The frame's gates (68–78)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
68–72   <q>_mask_boolean — each query's presence flag is a bit          Quadratic, degree 2
        code  memory::booleanity(frame(s, FIELD_MASK)), in frame_body

  68 pc_mask_boolean     0 = M[1]  − M[1]·M[1]      0 = pc_mask    − pc_mask²
  69 rs1_mask_boolean    0 = M[6]  − M[6]·M[6]      0 = rs1_mask   − rs1_mask²
  70 rs2_mask_boolean    0 = M[11] − M[11]·M[11]    0 = rs2_mask   − rs2_mask²
  71 rd_mask_boolean     0 = M[16] − M[16]·M[16]    0 = rd_mask    − rd_mask²
  72 deleg_mask_boolean  0 = M[21] − M[21]·M[21]    0 = deleg_mask − deleg_mask²

  reads as  a leaf is 1 or its tuple only at a mask of 0 or 1; a mask of −1 on a pc query
            flips both leaves' signs and reads as a REG query (memory.md §2.4). Every mask
            is also a lookup selector, which validate requires to be boolean.

────────────────────────────────────────────────────────────────────────────────────────────
73, 74  <q>_writes_back — a read-only register is left unchanged        Linear, degree 1
        code  memory::write_back(s), in frame_body

  73 rs1_writes_back     0 = M[10] − M[9]     0 = rs1_write_value − rs1_read_value
  74 rs2_writes_back     0 = M[15] − M[14]    0 = rs2_write_value − rs2_read_value

  reads as  a query that only reads writes back what it read, so reading x0 cannot put 5 in it.
            Two, not four: memory::FRAME_READ_ONLY is rs1, rs2 and load, and this frame holds
            no load — and the two ecall-argument queries that carried the other two gates went
            with the calls that used them (ecall-abi.md §4). `deleg` is NOT read-only and has
            no such gate: it reads the answer tuple an invocation wrote and writes a tuple of
            its own, which is what makes the pairing 1:1 (delegation.md §5.3). Gates 124–127
            pin what it may read instead.

────────────────────────────────────────────────────────────────────────────────────────────
75      rd_is_zero_inverse — the x0 flag, with gate 76                  Quadratic, degree 2
        code  memory::x0_gates(3, 5)[0]

  positional  0 = W[6] − M[16] + M[17]·W[5]
  named       0 = rd_addr·rd_inv + rd_is_zero − rd_mask

────────────────────────────────────────────────────────────────────────────────────────────
76      rd_is_zero_at_nonzero — no x0 flag at a real register           Quadratic, degree 2
        code  x0_gates(3, 5)[1]

  positional  0 = M[17]·W[6]
  named       0 = rd_addr·rd_is_zero

  reads as (75 with 76)  at rd_addr ≠ 0: rd_is_zero = 0 and rd_addr·rd_inv = rd_mask, so
                         rd_inv = 1/rd_addr on a live rd query (rd_mask = 1) and 0 where
                         rd_mask = 0.
                         at rd_addr = 0: rd_is_zero = rd_mask.
                         So the flag is 1 exactly on a live rd query at x0.

────────────────────────────────────────────────────────────────────────────────────────────
77      rd_is_zero_boolean                                              Quadratic, degree 2
        code  x0_gates(3, 5)[2]

  positional  0 = W[6] − W[6]·W[6]
  named       0 = rd_is_zero − rd_is_zero²

────────────────────────────────────────────────────────────────────────────────────────────
78      rd_write_masked — a write into x0 writes 0                      Quadratic, degree 2
        code  x0_gates(3, 5)[3]

  positional  0 = M[20] − W[7] + W[6]·W[7]
  named       0 = rd_write_value − (1 − rd_is_zero)·rd_selected

  reads as  the rd write is the computed result, except into x0, where it is 0. With the
            write-backs and x0's initial 0, every read of x0 returns 0.
```

**B. What the row is (79–109)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
79–84   kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2
        code  add_sub::booleanity(KINDS[k])

  79 kind_system_boolean   0 = W[14] − W[14]·W[14]    0 = kind_system − kind_system²
  80 kind_addi_boolean     0 = W[15] − W[15]·W[15]    0 = kind_addi   − kind_addi²
  81 kind_auipc_boolean    0 = W[16] − W[16]·W[16]    0 = kind_auipc  − kind_auipc²
  82 kind_add_boolean      0 = W[17] − W[17]·W[17]    0 = kind_add    − kind_add²
  83 kind_sub_boolean      0 = W[18] − W[18]·W[18]    0 = kind_sub    − kind_sub²
  84 kind_lui_boolean      0 = W[19] − W[19]·W[19]    0 = kind_lui    − kind_lui²

────────────────────────────────────────────────────────────────────────────────────────────
85      decoded_mask_bits — the packed mask is its six bits             Linear, degree 1
        code  add_sub::artifact, `bits`

  positional  0 = W[14] + 2·W[15] + 4·W[16] + 8·W[17] + 16·W[18] + 32·W[19] − W[13]
  named       0 = kind_system + 2·kind_addi + 4·kind_auipc + 8·kind_add + 16·kind_sub
                  + 32·kind_lui − decoded_mask

  reads as  the bits are the mask the decoder lookup binds. One-hotness is not here: on a
            live row an all-zero mask satisfies all 63 gates, and only the decoder table,
            whose masks are single bits, refuses it (lookup.md §10). Two bits that each ask
            for an rd write (any two of addi, auipc, add, sub, lui, or the system bit read as
            is_ecall beside one of them) are refused by 112 with 71, since rd_mask comes out
            2. The system bit read as is_fence beside any one other bit passes every gate,
            and only the decoder table refuses it. On a padding row the decoder lookup is
            off, so no table row binds the bits and only the gates above constrain them; the
            honest fill writes 0.

────────────────────────────────────────────────────────────────────────────────────────────
86      is_ecall_boolean      0 = W[20] − W[20]·W[20]      0 = is_ecall − is_ecall²
87      is_fence_boolean      0 = W[21] − W[21]·W[21]      0 = is_fence − is_fence²
        Quadratic, degree 2; code  add_sub::booleanity

────────────────────────────────────────────────────────────────────────────────────────────
88      system_split — a system row is exactly one of ecall and fence   Linear, degree 1
        code  add_sub::artifact

  positional  0 = W[20] + W[21] − W[14]
  named       0 = is_ecall + is_fence − kind_system

────────────────────────────────────────────────────────────────────────────────────────────
89      ecall_code — an ecall row's code is ECALL                       Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = W[20]·W[12]
  named       0 = is_ecall·decoded_imm

  reads as  is_ecall = 1 needs code 0; this reads "the code is ECALL" only because
            system_code::ECALL is 0, which a const assertion in add_sub.rs pins.

────────────────────────────────────────────────────────────────────────────────────────────
90      fence_code — a fence row's code is FENCE                        Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = −2·W[21] + W[21]·W[12]
  named       0 = is_fence·(decoded_imm − 2)

  reads as (88, 89, 90)  a system row with code 1, EBREAK, can set neither flag, and
                         system_split then fails: no ebreak row is provable.

────────────────────────────────────────────────────────────────────────────────────────────
91–108  three gates per delegation type, in constants::delegation::TYPES order
                                                                        Quadratic, degree 2
        code  add_sub::artifact, build's loop over DELEGATIONS[..BASE_TYPES]  S23, S26, S26c

  91  is_deleg_9_boolean    0 = W[22] − W[22]·W[22]    0 = is_deleg_9  − is_deleg_9²
  92  deleg_9_is_an_ecall   0 = W[22] − W[22]·W[20]    0 = is_deleg_9·(1 − is_ecall)
  93  deleg_9_number        0 = −1287·W[22] + W[22]·M[9]
                                                       0 = is_deleg_9·(rs1_read_value − 0x507)
  94  is_deleg_10_boolean   0 = W[23] − W[23]·W[23]    0 = is_deleg_10 − is_deleg_10²
  95  deleg_10_is_an_ecall  0 = W[23] − W[23]·W[20]    0 = is_deleg_10·(1 − is_ecall)
  96  deleg_10_number       0 = −1280·W[23] + W[23]·M[9]
                                                       0 = is_deleg_10·(rs1_read_value − 0x500)
  97  is_deleg_11_boolean   0 = W[24] − W[24]·W[24]    0 = is_deleg_11 − is_deleg_11²
  98  deleg_11_is_an_ecall  0 = W[24] − W[24]·W[20]    0 = is_deleg_11·(1 − is_ecall)
  99  deleg_11_number       0 = −1282·W[24] + W[24]·M[9]
                                                       0 = is_deleg_11·(rs1_read_value − 0x502)
  100 is_deleg_15_boolean   0 = W[25] − W[25]·W[25]    0 = is_deleg_15 − is_deleg_15²
  101 deleg_15_is_an_ecall  0 = W[25] − W[25]·W[20]    0 = is_deleg_15·(1 − is_ecall)
  102 deleg_15_number       0 = −1284·W[25] + W[25]·M[9]
                                                       0 = is_deleg_15·(rs1_read_value − 0x504)
  103 is_deleg_16_boolean   0 = W[26] − W[26]·W[26]    0 = is_deleg_16 − is_deleg_16²
  104 deleg_16_is_an_ecall  0 = W[26] − W[26]·W[20]    0 = is_deleg_16·(1 − is_ecall)
  105 deleg_16_number       0 = −1288·W[26] + W[26]·M[9]
                                                       0 = is_deleg_16·(rs1_read_value − 0x508)
  106 is_deleg_17_boolean   0 = W[27] − W[27]·W[27]    0 = is_deleg_17 − is_deleg_17²
  107 deleg_17_is_an_ecall  0 = W[27] − W[27]·W[20]    0 = is_deleg_17·(1 − is_ecall)
  108 deleg_17_number       0 = −1286·W[27] + W[27]·M[9]
                                                       0 = is_deleg_17·(rs1_read_value − 0x506)

  reads as  each is_deleg_t = 1 forces is_ecall = 1, so a delegation request is a system row
            with code ECALL and carries the whole ecall frame. Each flag is free on every
            other row, where its booleanity gate alone holds it to 0 or 1 — and 113 then
            makes a stray 1 ask for a deleg query, 127 makes it name that type's address
            space, the number gate makes it ask a7 for that type's number, and 109 and 122
            turn the exit gates off; the honest fill writes 0 in all six.

            The six numbers are ecall::PRECOMPILE_KECCAK_F, PRECOMPILE_POSEIDON2,
            PRECOMPILE_FR_ARITH, PRECOMPILE_MOD_MUL, PRECOMPILE_SHA256_COMP and
            PRECOMPILE_EC_ADD, read straight from the first BASE_TYPES = 6 rows of
            constants::delegation::TYPES, which is also where the family ids in the names
            come from: no gate here spells a number of its own, and neither does 109. S21 had
            one flag and four gates for the one delegation family; since S23 it is three
            gates per type, the fourth having become 109's sum over types, and S26's MOD_MUL
            and S26c's SHA256_COMP and EC_ADD cost exactly those three apiece. The keccak
            number is 0x507 since S26d retired 0x501, and SHA256_COMP's 0x508 since S26e
            retired 0x505; each move changed one literal here, in 93 and in 105.

────────────────────────────────────────────────────────────────────────────────────────────
109     ecall_is_exit — every ecall that is not a delegation is EXIT    Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = −93·W[20] + 93·W[22] + 93·W[23] + 93·W[24] + 93·W[25] + 93·W[26] + 93·W[27]
                  + W[20]·M[9] − W[22]·M[9] − W[23]·M[9] − W[24]·M[9] − W[25]·M[9]
                  − W[26]·M[9] − W[27]·M[9]
  named       0 = (is_ecall − is_deleg_9 − is_deleg_10 − is_deleg_11 − is_deleg_15
                   − is_deleg_16 − is_deleg_17) · (rs1_read_value − 93)

  reads as  an ecall row's rs1 query reads a7 (gate 114), and a7 is 93 unless this row is a
            delegation of some type. This is S16's `is_ecall·(rs1_read_value − 93)` with
            every delegation row subtracted out, one linear term and one product per type.

  reads as (91–109)  **an ecall row is an exit or a delegation request of exactly one
                     type.** Each is_deleg_t is a free boolean and is_exit is written out
                     as is_ecall − Σ_t is_deleg_t, so a row setting two type flags at once
                     would need a7 to be two distinct numbers, and a row setting one beside
                     the exit would need a7 to be 93 as well. The partition therefore holds
                     because the ecall numbers are **pairwise distinct** and each is in its
                     ABI range (delegation.md §2, §3) — a `const` assertion in add_sub.rs
                     over every pair of registry rows, not a test, because a violation
                     there is a mis-numbered ABI and should not compile. So the factor is 0
                     or 1 on every row and never −1 or 2, which is what the three amended
                     gates 109, 122 and 130 need of it.
                     **read (63) and write (64) reach none of this**: they are retired and
                     their numbers burned (ecall-abi.md §4), so an image issuing one asks
                     a7 for a number no selector names and 109 refuses the row.
```

**C. Which queries a row makes, and where (110–118)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
110     rs1_mask_rule — rs1 is read exactly by add, sub, addi, ecall    Quadratic, degree 2
        code  add_sub::mask_rule(frame(1, FIELD_MASK), [KIND_ADD, KIND_SUB, KIND_ADDI, IS_ECALL])

  positional  0 = M[6] − M[1]·W[17] − M[1]·W[18] − M[1]·W[15] − M[1]·W[20]
  named       0 = rs1_mask − pc_mask·(kind_add + kind_sub + kind_addi + is_ecall)

────────────────────────────────────────────────────────────────────────────────────────────
111     rs2_mask_rule — rs2 is read exactly by add, sub, ecall          Quadratic, degree 2
        code  mask_rule(frame(2, FIELD_MASK), [KIND_ADD, KIND_SUB, IS_ECALL])

  positional  0 = M[11] − M[1]·W[17] − M[1]·W[18] − M[1]·W[20]
  named       0 = rs2_mask − pc_mask·(kind_add + kind_sub + is_ecall)

────────────────────────────────────────────────────────────────────────────────────────────
112     rd_mask_rule — rd is written by every kind but the fence        Quadratic, degree 2
        code  mask_rule(frame(3, FIELD_MASK),
                        [KIND_ADD, KIND_SUB, KIND_ADDI, KIND_AUIPC, KIND_LUI, IS_ECALL])

  positional  0 = M[16] − M[1]·W[17] − M[1]·W[18] − M[1]·W[15] − M[1]·W[16] − M[1]·W[19]
                  − M[1]·W[20]
  named       0 = rd_mask − pc_mask·(kind_add + kind_sub + kind_addi + kind_auipc
                                     + kind_lui + is_ecall)

  reads as (110, 111, 112)  on a live row the bits are one-hot, so each sum is 0 or 1 and the
                            mask is the kind's use of the query. A delegation row is an ecall
                            row, so it makes all three: a7 at slot 1, a0 at slot 2, a0 at
                            slot 3. On a padding row pc_mask = 0 and every mask is 0,
                            whatever the bits hold.
                            **There is no fourth, fifth or sixth rule here any more.** Until
                            the POSIX layer went, three degree-1 gates said arg1_mask = 0,
                            arg2_mask = 0 and ram_mask = 0 — each refusing a query the frame
                            carried and no kind could make. The queries are gone, so the
                            gates refuse nothing representable and went with them
                            (ecall-abi.md §4, §26 observation 2).

────────────────────────────────────────────────────────────────────────────────────────────
113     deleg_mask_rule — the mirror query is a delegation row's alone  Quadratic, degree 2
        code  mask_rule(frame(4, FIELD_MASK), &IS_DELEGATION)

  positional  0 = M[21] − M[1]·W[22] − M[1]·W[23] − M[1]·W[24] − M[1]·W[25] − M[1]·W[26]
                  − M[1]·W[27]
  named       0 = deleg_mask − pc_mask·(is_deleg_9 + is_deleg_10 + is_deleg_11 + is_deleg_15
                                         + is_deleg_16 + is_deleg_17)

  reads as  exactly the delegation rows make the mirror query, whatever their type, and
            every delegation row makes it. A row that set a type flag without making the
            query, or made the query without any flag, fails here — and since the mirror
            query is the request's half of the anchor, a request with no mirror query cannot
            balance against its invocation (delegation.md §5.3). The sum is 0 or 1 on every
            row that passes 91–109, so this is the ordinary mask rule of 110–112 with the
            six type flags as its `uses` list; it is what 127 pairs with, one saying the
            query is made and the other which type it names.

────────────────────────────────────────────────────────────────────────────────────────────
114     rs1_addr_rule — rs1's register is the decoded one, or a7        Quadratic, degree 2
        code  add_sub::addr_rule(1, DECODED_RS1, 17)

  positional  0 = M[6]·M[7] − M[6]·W[9] − 17·M[6]·W[20]
  named       0 = rs1_mask·(rs1_addr − decoded_rs1 − 17·is_ecall)

────────────────────────────────────────────────────────────────────────────────────────────
115     rs2_addr_rule — rs2's register is the decoded one, or a0        Quadratic, degree 2
        code  addr_rule(2, DECODED_RS2, 10)

  positional  0 = M[11]·M[12] − M[11]·W[10] − 10·M[11]·W[20]
  named       0 = rs2_mask·(rs2_addr − decoded_rs2 − 10·is_ecall)

────────────────────────────────────────────────────────────────────────────────────────────
116     rd_addr_rule — rd's register is the decoded one, or a0          Quadratic, degree 2
        code  addr_rule(3, DECODED_RD, 10)

  positional  0 = M[16]·M[17] − M[16]·W[11] − 10·M[16]·W[20]
  named       0 = rd_mask·(rd_addr − decoded_rd − 10·is_ecall)

  reads as (114–116)  a present query's register is the table's; a system row's decoded
                      registers are 0, so on an ecall row — exit or delegation of any type
                      alike — the constants name a7 and a0. The three gates key on is_ecall
                      and on no type flag, which is why a delegation row needs no address
                      rule of its own and why adding a type adds none: it is an ecall row and
                      takes the ecall frame.

────────────────────────────────────────────────────────────────────────────────────────────
117     rs1_value_masked — an absent rs1 reads 0                        Quadratic, degree 2
        code  add_sub::value_masked(1)

  positional  0 = M[9] − M[6]·M[9]
  named       0 = (1 − rs1_mask)·rs1_read_value

────────────────────────────────────────────────────────────────────────────────────────────
118     rs2_value_masked — an absent rs2 reads 0                        Quadratic, degree 2
        code  value_masked(2)

  positional  0 = M[14] − M[11]·M[14]
  named       0 = (1 − rs2_mask)·rs2_read_value

  reads as (117, 118)  the sum gate can add both operands on every kind: an addi row's
                       absent rs2, and an auipc row's absent rs1 and rs2, add 0.
```

**D. What the row computes (119–130)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
119     add_addi_auipc — the three sums, one gate                       Quadratic, degree 2
        code  add_sub::artifact, the `sum` loop over [KIND_ADD, KIND_ADDI, KIND_AUIPC]

  positional  0 = W[17]·M[9] + W[17]·M[14] + W[17]·W[12] − W[17]·W[7] − 2^32·W[17]·W[28]
                + W[15]·M[9] + W[15]·M[14] + W[15]·W[12] − W[15]·W[7] − 2^32·W[15]·W[28]
                + W[16]·M[9] + W[16]·M[14] + W[16]·W[12] − W[16]·W[7] − 2^32·W[16]·W[28]
                + W[16]·M[4]
  named, factored
    0 =   kind_add   · ( rs1_read_value + rs2_read_value + decoded_imm − rd_selected − 2^32·wrap )
        + kind_addi  · ( rs1_read_value + rs2_read_value + decoded_imm − rd_selected − 2^32·wrap )
        + kind_auipc · ( rs1_read_value + rs2_read_value + decoded_imm − rd_selected − 2^32·wrap
                         + pc_read_value )

  reads as  one kind at a time:
              add    rs1 + rs2 = sel + 2^32·wrap      its imm is 0, bound by the decoder table
              addi   rs1 + imm = sel + 2^32·wrap      its rs2 is absent and reads 0
              auipc  pc + imm  = sel + 2^32·wrap      its rs1 and rs2 are absent and read 0
            With sel range-checked below 2^32 and wrap a bit, sel is the RISC-V sum and wrap
            its carry: both addends are below 2^32, so the sum is below 2^33.

────────────────────────────────────────────────────────────────────────────────────────────
120     sub — the difference                                            Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = W[18]·M[9] − W[18]·M[14] − W[18]·W[7] + 2^32·W[18]·W[28]
  named       0 = kind_sub·(rs1_read_value − rs2_read_value − rd_selected + 2^32·wrap)

  reads as  rs1 − rs2 = sel − 2^32·wrap: wrap is the borrow.

────────────────────────────────────────────────────────────────────────────────────────────
121     lui — the loaded value                                          Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = W[19]·W[12] − W[19]·W[7]
  named       0 = kind_lui·(decoded_imm − rd_selected)

────────────────────────────────────────────────────────────────────────────────────────────
122     exit_status — the exit row writes a0 back                       Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = W[20]·M[19] − W[20]·W[7] − W[22]·M[19] + W[22]·W[7]
                  − W[23]·M[19] + W[23]·W[7] − W[24]·M[19] + W[24]·W[7]
                  − W[25]·M[19] + W[25]·W[7] − W[26]·M[19] + W[26]·W[7]
                  − W[27]·M[19] + W[27]·W[7]
  named       0 = (is_ecall − is_deleg_9 − is_deleg_10 − is_deleg_11 − is_deleg_15
                   − is_deleg_16 − is_deleg_17) · (rd_read_value − rd_selected)

  reads as  the exit row's result is a0 as read, and its rd query is x10, so x10's final
            value is the exit status verify_shard's step 10 compares with v_10. A delegation
            row of any type is subtracted out here and answered by 123 instead: it writes 0
            into a0, not a0 back (delegation.md §2). Same shape as 109's amendment, same
            reason, and a new type costs it two more products and no degree.

────────────────────────────────────────────────────────────────────────────────────────────
123     deleg_writes_no_register — a delegation answers 0               Quadratic, degree 2
        code  add_sub::artifact                                                         S21

  positional  0 = M[21]·W[7]
  named       0 = deleg_mask·rd_selected

  reads as  on a delegation row rd_selected is 0, so with 78 the rd query writes 0 into a0 —
            the frozen answer of every delegation call on an executor that has the circuit
            (delegation.md §2). This is the first of the three request-side zeroings; 124 and
            125 are the other two. All three key on deleg_mask and not on a type flag, so
            they are one gate apiece however many types there are.

────────────────────────────────────────────────────────────────────────────────────────────
124     deleg_read_ts_zero — the mirror query reads the answer tuple    Quadratic, degree 2
        code  add_sub::artifact                                                         S21

  positional  0 = M[21]·M[23]
  named       0 = deleg_mask·deleg_read_ts

────────────────────────────────────────────────────────────────────────────────────────────
125     deleg_read_value_zero                                           Quadratic, degree 2
        code  add_sub::artifact                                                         S21

  positional  0 = M[21]·M[24]
  named       0 = deleg_mask·deleg_read_value

  reads as (124, 125)  the tuple the request reads is T(deleg_space, deleg_addr, 0, 0)
                       exactly, and 127 is what fixes deleg_space. Only an invocation writes
                       a timestamp-0 tuple in its own space, and it writes one per row, so
                       the read pairs with an invocation of the type it named and with
                       nothing else.
                       Timestamp 0 is the stamp no ordinary cycle can produce (cycles are
                       numbered from 1), which is what lets the pair be recognised without a
                       tag (delegation.md §5.2, §5.3).

────────────────────────────────────────────────────────────────────────────────────────────
126     deleg_addr_rule — the mirror is at the frame base handed over   Quadratic, degree 2
        code  add_sub::artifact                                                         S21

  positional  0 = M[21]·M[22] − M[21]·M[14]
  named       0 = deleg_mask·(deleg_addr − rs2_read_value)

  reads as  the anchor's address is the a0 the request passed — the same a0 the rs2 query
            read at slot 2 and gate 115 pinned to register 10. So the invocation that answers
            this request permutes the frame at this pointer and no other (delegation.md §5.1).

────────────────────────────────────────────────────────────────────────────────────────────
127     deleg_space_rule — the mirror's leaf names the requested type   Linear, degree 1
        code  add_sub::artifact                                                         S23

  positional  0 = M[26] − 4·W[22] − 5·W[23] − 6·W[24] − 7·W[25] − 8·W[26] − 9·W[27]
  named       0 = deleg_space − (4·is_deleg_9 + 5·is_deleg_10 + 6·is_deleg_11
                                 + 7·is_deleg_15 + 8·is_deleg_16 + 9·is_deleg_17)

  reads as  the literals are address_space::DELEGATION_KECCAK_F, DELEGATION_POSEIDON2,
            DELEGATION_FR_ARITH, DELEGATION_MOD_MUL, DELEGATION_SHA256_COMP and
            DELEGATION_EC_ADD, read through constants::delegation::TYPES; the gate spells no
            tag of its own. It is what
            carries the type into the mirror's two leaves (§3.4), which may not read the W
            selectors themselves: a leaf reading a W column is refused by check_memory, W
            being committed after the memory challenges (memory.md §8, delegation.md §5.1,
            §10.1). Ungated and degree 1, so it holds on every row of the shard — on a row
            requesting nothing it forces deleg_space = 0, because each is_deleg_t is 0 unless
            is_ecall is 1 and is_ecall is 0 on a padding row. With 113 it is the whole of
            "which delegation, if any, this row asks for".

────────────────────────────────────────────────────────────────────────────────────────────
128     wrap_boolean          0 = W[28] − W[28]·W[28]      0 = wrap − wrap²
129     pc_wrap_boolean       0 = W[30] − W[30]·W[30]      0 = pc_wrap − pc_wrap²
        Quadratic, degree 2; code  add_sub::booleanity

────────────────────────────────────────────────────────────────────────────────────────────
130     next_pc_rule — the fall-through, or HALT_PC on the exit row     Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = M[5] + 2^32·W[30] − W[8] − W[20] + W[22] + W[23] + W[24] + W[25] + W[26]
                  + W[27] + W[20]·W[8] − W[22]·W[8] − W[23]·W[8] − W[24]·W[8] − W[25]·W[8]
                  − W[26]·W[8] − W[27]·W[8]
  named       0 = pc_write_value + 2^32·pc_wrap
                  − (1 − is_ecall + is_deleg_9 + is_deleg_10 + is_deleg_11 + is_deleg_15
                     + is_deleg_16 + is_deleg_17)·decoded_next_pc
                  − HALT_PC·(is_ecall − is_deleg_9 − is_deleg_10 − is_deleg_11 − is_deleg_15
                             − is_deleg_16 − is_deleg_17)
                                                                      (HALT_PC = 1)

  reads as  next_pc + 2^32·pc_wrap is decoded_next_pc on every row but the exit row, and 1
            (HALT_PC) there. **A delegation row falls through, whatever its type**: its two
            terms put it back on the decoded_next_pc branch, because a delegation call
            returns to pc + 4 and the program goes on (delegation.md §2); a new type costs
            one linear term and one product and no degree. On a live row decoded_next_pc
            is the table's fall-through, bound by decode_row; on a padding row nothing else
            binds decoded_next_pc, so it and next_pc are free together (the honest fill
            writes 0 in both). next_pc is range-checked below 2^32 on a live row and the
            fall-through is below 2^31, so pc_wrap is 0 on every live row.
```

Of the 63 gates, **5 are degree 1**: the two write-backs, `decoded_mask_bits`, `system_split`
and S23's `deleg_space_rule`. It was 10 before the frame narrowed — four write-backs and the
three `mask = 0` rules for `arg1`, `arg2` and `ram` — so the deletion took **five degree-1 gates
and three degree-2 ones**, the three mask booleanity gates of the queries that went, and the
degree-2 count went from 55 to 52; S26c's two delegation types then added six degree-2 gates,
and it is 58. **Every gate S23, S26 and S26c added or amended is degree 2, and
`deleg_space_rule` is degree 1**: a registered delegation type costs three gates and a handful
of terms rather than a gate list, because a type flag multiplies nothing but `is_ecall`,
`pc_mask`, `rd_read_value`, `rd_selected`, `rs1_read_value` and `decoded_next_pc`, each of which
some gate already multiplies. All 63 have constant 0, so each is 0 on the all-zero row, and the
private `memory::assemble` records `zero_row_valid = true` (`build::zero_on_zero_row`). The
padding row itself is all zeros in every assembled artifact (`build::assemble`), whatever its
gates.

### 3.6 The 15 lookups

`CircuitArtifact::lookups`, in order. The frame's 10 come from the private
`memory::gap_lookups`; the rest from `add_sub::artifact` (`range16`, `low_half` and the inline
`decode_row`).

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `gap_hi_pc` | `TIMESTAMP` (0) | `M[1]` | `W[0]` | `pc_gap_hi` | `< 2^19` |
| 1 | `gap_lo_pc` | `TIMESTAMP` | `M[1]` | `4·M[0] − M[3] − 2^19·W[0] − 1` | `4·cycle − pc_read_ts − 2^19·pc_gap_hi − 1` | `< 2^19` |
| 2 | `gap_hi_rs1` | `TIMESTAMP` | `M[6]` | `W[1]` | `rs1_gap_hi` | `< 2^19` |
| 3 | `gap_lo_rs1` | `TIMESTAMP` | `M[6]` | `4·M[0] − M[8] − 2^19·W[1]` | `4·cycle − rs1_read_ts − 2^19·rs1_gap_hi` | `< 2^19` |
| 4 | `gap_hi_rs2` | `TIMESTAMP` | `M[11]` | `W[2]` | `rs2_gap_hi` | `< 2^19` |
| 5 | `gap_lo_rs2` | `TIMESTAMP` | `M[11]` | `4·M[0] − M[13] − 2^19·W[2] + 1` | `4·cycle − rs2_read_ts − 2^19·rs2_gap_hi + 1` | `< 2^19` |
| 6 | `gap_hi_rd` | `TIMESTAMP` | `M[16]` | `W[3]` | `rd_gap_hi` | `< 2^19` |
| 7 | `gap_lo_rd` | `TIMESTAMP` | `M[16]` | `4·M[0] − M[18] − 2^19·W[3] + 2` | `4·cycle − rd_read_ts − 2^19·rd_gap_hi + 2` | `< 2^19` |
| 8 | `gap_hi_deleg` | `TIMESTAMP` | `M[21]` | `W[4]` | `deleg_gap_hi` | `< 2^19` |
| 9 | `gap_lo_deleg` | `TIMESTAMP` | `M[21]` | `4·M[0] − M[23] − 2^19·W[4] + 2` | `4·cycle − deleg_read_ts − 2^19·deleg_gap_hi + 2` | `< 2^19` |
| 10 | `rd_hi_range` | `RANGE16` (1) | `M[1]` | `W[29]` | `rd_hi` | `< 2^16` |
| 11 | `rd_lo_range` | `RANGE16` | `M[1]` | `W[7] − 2^16·W[29]` | `rd_selected − 2^16·rd_hi` | `< 2^16` |
| 12 | `next_pc_hi_range` | `RANGE16` | `M[1]` | `W[31]` | `next_pc_hi` | `< 2^16` |
| 13 | `next_pc_lo_range` | `RANGE16` | `M[1]` | `M[5] − 2^16·W[31]` | `pc_write_value − 2^16·next_pc_hi` | `< 2^16` |
| 14 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[8], W[9], W[10], W[11], W[12], W[13])` | `(pc_read_value, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_imm, decoded_mask)` | a row of `S[0..7]` |

Read in pairs: `gap_hi_<q>` and `gap_lo_<q>` together say
`gap = 4·cycle + Δ_q − <q>_read_ts − 1 = lo + 2^19·hi` lies in `[0, 2^38)`, so the read strictly
precedes its own write. `rd_hi_range` and `rd_lo_range` bound `rd_selected` below `2^32`, and
the `next_pc` pair bounds the next pc the same way (`memory.md` §7's range convention).
**Lookups 8 and 9 are S21's**, and the `deleg` query is bounded exactly as the four before
it: the pair is what makes the mirror query's read obey the clock like any other, even though
the timestamp it reads is the literal 0 (§3.5, gate 124). **The six obligations the POSIX
layer's deletion took were the `arg1`, `arg2` and `ram` pairs**, each bounding a gap on a query
no row could make; nothing else moved, and neither S23, S26 nor S26c added a lookup or moved one — a
delegation type is a selector, a tag and three gates, and none of the three is a key of any
channel.

The channels, `add_sub::channels()`, in output order:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[32]` | **10** | **16** |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[33]` | 4 | 8 |
| 6, 7 | `DECODER` | 3 | `S[0..7]` | `W[34]` | 1 | 2 |

**The timestamp tree's padding is where the three lost queries gave a gate list back.** Ten
obligations and one table fraction is eleven leaves, which fits a 16-leaf tree with five pads;
at sixteen obligations it was seventeen leaves, one past 16, and the tree padded to 32 (§26
observation 20). So this circuit is five row-wise lists deep where S21 made it six, and no tree
of it sets a depth the frame does not.

`GENERIC` (2) is not used here. S17's jump/branch/slt family is the first to look it up. S17
put the packed table's three commitments in every verifying key, whatever its families, and
folded them into the SRS digest, which the global transcript absorbs before any challenge;
program identity does not bind them. This family's shard opening does not list them, its
circuit reading no generic channel (§4.3, §4.6, `shard-proof.md` §8.5,
`jump-branch-slt.md` §6).

### 3.7 Inner layers `L2`–`L5`: the row-wise reduction

Every column here is a per-row value, never committed. `a·b` is a `Product`, `a + b` a
fraction-node pair (§0.6), `copy` a `Linear` copy of each column. A fraction node `<node>` is
two columns named `<node>_num` and `<node>_den` (relations `define_<node>_num` and
`define_<node>_den`), as in §3.4; a product node is one column named `<node>`. There are four
row-wise reduction lists, and the layer widths are `MEM_WORD`'s (§7.7).

**`L2`, gate list 1, 34 columns, relations 131–164.**

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 131 | `read_2_0` | `read_pc · read_rs1` |
| 1 | 132 | `read_2_1` | `read_rs2 · read_rd` |
| 2 | 133 | `read_2_2` | `read_deleg · read_pad_0` |
| 3 | 134 | `read_2_3` | `read_pad_1 · read_pad_2` |
| 4–7 | 135–138 | `write_2_0` … `write_2_3` | the same over the write side |
| 8, 9 | 139, 140 | `timestamp_2_0` | `timestamp_table + gap_hi_pc` |
| 10, 11 | 141, 142 | `timestamp_2_1` | `gap_lo_pc + gap_hi_rs1` |
| 12, 13 | 143, 144 | `timestamp_2_2` | `gap_lo_rs1 + gap_hi_rs2` |
| 14, 15 | 145, 146 | `timestamp_2_3` | `gap_lo_rs2 + gap_hi_rd` |
| 16, 17 | 147, 148 | `timestamp_2_4` | `gap_lo_rd + gap_hi_deleg` |
| 18, 19 | 149, 150 | `timestamp_2_5` | `gap_lo_deleg + timestamp_pad_0` |
| 20, 21 | 151, 152 | `timestamp_2_6` | `timestamp_pad_1 + timestamp_pad_2` |
| 22, 23 | 153, 154 | `timestamp_2_7` | `timestamp_pad_3 + timestamp_pad_4` |
| 24, 25 | 155, 156 | `range16_2_0` | `range16_table + rd_hi_range` |
| 26, 27 | 157, 158 | `range16_2_1` | `rd_lo_range + next_pc_hi_range` |
| 28, 29 | 159, 160 | `range16_2_2` | `next_pc_lo_range + range16_pad_0` |
| 30, 31 | 161, 162 | `range16_2_3` | `range16_pad_1 + range16_pad_2` |
| 32, 33 | 163, 164 | `decoder_2_0` | `decoder_table + decode_row` |

Positionally, `timestamp_2_0` is `L{2}[8] = L{1}[16]·L{1}[19] + L{1}[18]·L{1}[17]` and
`L{2}[9] = L{1}[17]·L{1}[19]`: `−mult/(T + g) + 1/(E_gap_hi_pc + g)`, the node `lookup.md` §6
puts first on purpose. `read_2_2` and `read_2_3` are the nodes the frame's narrowing changed:
they multiplied two real leaves when the frame was eight queries and now carry the pads.

**`L3`, gate list 2, 18 columns, relations 165–182.**

| `L3` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 165 | `read_3_0` | `read_2_0 · read_2_1` |
| 1 | 166 | `read_3_1` | `read_2_2 · read_2_3` |
| 2, 3 | 167, 168 | `write_3_0`, `write_3_1` | the same over the write side |
| 4, 5 | 169, 170 | `timestamp_3_0` | `timestamp_2_0 + timestamp_2_1` |
| 6, 7 | 171, 172 | `timestamp_3_1` | `timestamp_2_2 + timestamp_2_3` |
| 8, 9 | 173, 174 | `timestamp_3_2` | `timestamp_2_4 + timestamp_2_5` |
| 10, 11 | 175, 176 | `timestamp_3_3` | `timestamp_2_6 + timestamp_2_7` |
| 12, 13 | 177, 178 | `range16_3_0` | `range16_2_0 + range16_2_1` |
| 14, 15 | 179, 180 | `range16_3_1` | `range16_2_2 + range16_2_3` |
| 16, 17 | 181, 182 | `decoder_3_0` | copy of `decoder_2_0` |

**`L4`, gate list 3, 10 columns, relations 183–192.**

| `L4` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 183 | `read_4_0` | `read_3_0 · read_3_1` |
| 1 | 184 | `write_4_0` | `write_3_0 · write_3_1` |
| 2, 3 | 185, 186 | `timestamp_4_0` | `timestamp_3_0 + timestamp_3_1` |
| 4, 5 | 187, 188 | `timestamp_4_1` | `timestamp_3_2 + timestamp_3_3` |
| 6, 7 | 189, 190 | `range16_4_0` | `range16_3_0 + range16_3_1` |
| 8, 9 | 191, 192 | `decoder_4_0` | copy of `decoder_3_0` |

**`L5`, gate list 4, 8 columns, relations 193–200** — the row-wise top: one value per row per
tree.

| `L5` | relations | node | formula | value at row `y` |
| --- | --- | --- | --- | --- |
| 0 | 193 | `read_5_0` | copy of `read_4_0` | the product of row `y`'s 8 read leaves |
| 1 | 194 | `write_5_0` | copy of `write_4_0` | the product of row `y`'s 8 write leaves |
| 2, 3 | 195, 196 | `timestamp_5_0` | `timestamp_4_0 + timestamp_4_1` | the sum of row `y`'s 16 timestamp fractions |
| 4, 5 | 197, 198 | `range16_5_0` | copy of `range16_4_0` | the sum of row `y`'s 8 range16 fractions |
| 6, 7 | 199, 200 | `decoder_5_0` | copy of `decoder_4_0` | the sum of row `y`'s 2 decoder fractions |

`checker::memory_roots` recomputes the two roots from `L5[0]` and `L5[1]`, the layer the first
halving list reads.

### 3.8 The halving layers and the outputs

Gate list `k`, for `5 ≤ k ≤ n + 4`, halves layer `k` into layer `k + 1`, which has
`n + 4 − k` variables. Its eight gates, relation `r = 201 + 8(k − 5)`:

| `L{k+1}` | relation | node | shape | formula |
| --- | --- | --- | --- | --- |
| 0 | `r` | `read_{k+1}_0` | `TreeProduct { L{k}[0] }` | `L{k}[0](y,0) · L{k}[0](y,1)` |
| 1 | `r + 1` | `write_{k+1}_0` | `TreeProduct { L{k}[1] }` | `L{k}[1](y,0) · L{k}[1](y,1)` |
| 2 | `r + 2` | `timestamp_{k+1}_0_num` | `TreeCross { L{k}[2], L{k}[3] }` | `L{k}[2](y,0)·L{k}[3](y,1) + L{k}[2](y,1)·L{k}[3](y,0)` |
| 3 | `r + 3` | `timestamp_{k+1}_0_den` | `TreeProduct { L{k}[3] }` | `L{k}[3](y,0) · L{k}[3](y,1)` |
| 4 | `r + 4` | `range16_{k+1}_0_num` | `TreeCross { L{k}[4], L{k}[5] }` | `L{k}[4](y,0)·L{k}[5](y,1) + L{k}[4](y,1)·L{k}[5](y,0)` |
| 5 | `r + 5` | `range16_{k+1}_0_den` | `TreeProduct { L{k}[5] }` | `L{k}[5](y,0) · L{k}[5](y,1)` |
| 6 | `r + 6` | `decoder_{k+1}_0_num` | `TreeCross { L{k}[6], L{k}[7] }` | `L{k}[6](y,0)·L{k}[7](y,1) + L{k}[6](y,1)·L{k}[7](y,0)` |
| 7 | `r + 7` | `decoder_{k+1}_0_den` | `TreeProduct { L{k}[7] }` | `L{k}[7](y,0) · L{k}[7](y,1)` |

In the last list, `k = n + 4`, the eight nodes are named `read_root`, `write_root`,
`timestamp_num_root`, `timestamp_den_root`, `range16_num_root`, `range16_den_root`,
`decoder_num_root` and `decoder_den_root`. At `n = 20` the halving lists are 5 to 24, `L6` has
19 variables and `L25` none. At `n = 22` they are 5 to 26, and the top is `L27`.

**The outputs**, in output-map order. All eight are absorbed as one `GKR_OUTPUTS` message
(`gkr.md` §5.2, O1) before any challenge of the backward pass (the top has no variables, so O2
draws no point), and travel in `ShardProof::outputs`.

| # | address, `n = 20` | node | value | what `verify_shard` does with it |
| --- | --- | --- | --- | --- |
| 0 | `L{25}[0]` | `read_root` | the product of every read leaf of the shard | step 10: must equal `PublicInputs::memory_roots[p][0]`, `p` being the position of `(0, shard_index)` in `verifier_core::statement_shards`, after `INIT_TEARDOWN`'s shard and every `ZERO_WINDOWS` shard (`shard-proof.md` §1.2); a factor of `reconciles` |
| 1 | `L{25}[1]` | `write_root` | the product of every write leaf | step 10: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |
| 2 | `L{25}[2]` | `timestamp_num_root` | the numerator of the channel's summed fraction `Σ num/den` over every leaf of every row, written over the product of all its denominators | step 9, `channel_holds`: must be 0; otherwise `Lookup { channel: 0 }` |
| 3 | `L{25}[3]` | `timestamp_den_root` | that product of denominators | step 9: must be nonzero; otherwise `Lookup { channel: 0 }` |
| 4 | `L{25}[4]` | `range16_num_root` | as output 2, for `RANGE16` | step 9: must be 0; otherwise `Lookup { channel: 1 }` |
| 5 | `L{25}[5]` | `range16_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 1 }` |
| 6 | `L{25}[6]` | `decoder_num_root` | as output 2, for `DECODER` | step 9: must be 0; otherwise `Lookup { channel: 3 }` |
| 7 | `L{25}[7]` | `decoder_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 3 }` |

`reconciles` holds when `∏ read roots · R_b = ∏ write roots · W_b` and `∏ read roots · R_b ≠ 0`,
the products running over every shard of the statement, with the boundary factors `(W_b, R_b)`
of `memory.md` §4.2. **Since S21 that product also runs over the delegation shards**, whose two
roots enter it exactly as a CPU shard's do (§12.7): an invocation's frame reads and writes are
ordinary RAM tuples, and its anchor pair cancels against a request's.

### 3.9 Witness rows

The table shows ten of the seventeen `honest_rows` in `crates/checker/tests/add_sub.rs`. The
other seven are `add, not carrying`, `sub, not borrowing`, `addi from x0, as c.li` (a 4-byte
`addi`, despite its name), `auipc, not carrying`, `sub to x0, borrowing`, `nop`
(`addi x0, x0, 0`) and `c.add, two bytes` (an `add` whose fall-through is `0x10012`); §3.10
probes all seventeen. Each row is built from Rust's own `u32` arithmetic, and
`every_row_kind_satisfies_every_gate_and_every_bound` holds it to every gate and range
obligation in CI.

A row is checked alone, so three things differ from a real shard. **Every read timestamp is
synthetic**: each register query reads a write made 8 timestamps before its own and the pc
query the previous cycle's, which fixes every gap at 7, or 3 for the pc, and leaves every
`<q>_gap_hi` 0. The multiplicities, which count over a whole shard (§0.3), are left 0. And the
test sets the `S` columns on each live row to that row's own table entry, where a shard indexes
them by pc, not by cycle; the table below omits them. Every live row shown has cycle 9, pc
`0x10010` and a 4-byte instruction, and `P` is 0 in every cell.

`A` add, carrying: `x7 = x5 + x6`, `0xffffefff + 0x12345678`. `B` sub, borrowing:
`x29 = x6 − x5`. `C` addi of −1, carrying: `x5 = x5 − 1`. `D` auipc, carrying:
`x31 = pc + 0xfffff000`. `E` lui: `x6 = 0x12345000`. `F` add into `x0`, carrying. `G` fence.
`H` exit 42. **`I` keccak delegation request** (S21): `a7 = 0x507`, `a0 = 0x10400`, the frame
base it hands over, and `a0` written back 0. `P` padding. A `POSEIDON2`, `FR_ARITH`, `MOD_MUL`,
`SHA256_COMP` or `EC_ADD` request is the same row with `a7` `0x500`, `0x502`, `0x504`, `0x508`
or `0x506`, its own selector at `W[23]`, `W[24]`, `W[25]`, `W[26]` or `W[27]` and its own tag
5, 6, 7, 8 or 9 at `M[26]`; the suite carries one of the six, the gates being one loop over
the registry.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `I` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[2]` `pc_addr` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `M[3]` `pc_read_ts` | 32 | 32 | 32 | 32 | 32 | 32 | 32 | 32 | 32 | 0 |
| `M[4]` `pc_read_value` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | 0 |
| `M[5]` `pc_write_value` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | 1 | `0x10014` | 0 |
| `M[6]` `rs1_mask` | 1 | 1 | 1 | 0 | 0 | 1 | 0 | 1 | 1 | 0 |
| `M[7]` `rs1_addr` | 5 | 6 | 5 | 0 | 0 | 5 | 0 | 17 | 17 | 0 |
| `M[8]` `rs1_read_ts` | 29 | 29 | 29 | 0 | 0 | 29 | 0 | 29 | 29 | 0 |
| `M[9]`, `M[10]` `rs1_read_value`, `rs1_write_value` | `0xffffefff` | `0x12345678` | `0xfffff000` | 0 | 0 | `0xffffefff` | 0 | 93 | `0x507` | 0 |
| `M[11]` `rs2_mask` | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 1 | 1 | 0 |
| `M[12]` `rs2_addr` | 6 | 5 | 0 | 0 | 0 | 6 | 0 | 10 | 10 | 0 |
| `M[13]` `rs2_read_ts` | 30 | 30 | 0 | 0 | 0 | 30 | 0 | 30 | 30 | 0 |
| `M[14]`, `M[15]` `rs2_read_value`, `rs2_write_value` | `0x12345678` | `0xffffefff` | 0 | 0 | 0 | `0x12345678` | 0 | 42 | `0x10400` | 0 |
| `M[16]` `rd_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 0 |
| `M[17]` `rd_addr` | 7 | 29 | 5 | 31 | 6 | 0 | 0 | 10 | 10 | 0 |
| `M[18]` `rd_read_ts` | 31 | 31 | 31 | 31 | 31 | 31 | 0 | 31 | 31 | 0 |
| `M[19]` `rd_read_value` | 3 | 1 | `0xfffff000` | 0 | 0 | 0 | 0 | 42 | 7 | 0 |
| `M[20]` `rd_write_value` | `0x12344677` | `0x12346679` | `0xffffefff` | `0xf010` | `0x12345000` | 0 | 0 | 42 | 0 | 0 |
| `M[21]` `deleg_mask` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| `M[22]` `deleg_addr` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | `0x10400` | 0 |
| `M[23]`, `M[24]`, `M[25]` `deleg_read_ts`, `deleg_read_value`, `deleg_write_value` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `M[26]` `deleg_space` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4 | 0 |
| `W[0..5]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[5]` `rd_inv` | `7⁻¹` | `29⁻¹` | `5⁻¹` | `31⁻¹` | `6⁻¹` | 0 | 0 | `10⁻¹` | `10⁻¹` | 0 |
| `W[6]` `rd_is_zero` | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `W[7]` `rd_selected` | `0x12344677` | `0x12346679` | `0xffffefff` | `0xf010` | `0x12345000` | `0x12344677` | 0 | 42 | 0 | 0 |
| `W[8]` `decoded_next_pc` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | 0 |
| `W[9]` `decoded_rs1` | 5 | 6 | 5 | 0 | 0 | 5 | 0 | 0 | 0 | 0 |
| `W[10]` `decoded_rs2` | 6 | 5 | 0 | 0 | 0 | 6 | 0 | 0 | 0 | 0 |
| `W[11]` `decoded_rd` | 7 | 29 | 5 | 31 | 6 | 0 | 0 | 0 | 0 | 0 |
| `W[12]` `decoded_imm` | 0 | 0 | `0xffffffff` | `0xfffff000` | `0x12345000` | 0 | 2 | 0 | 0 | 0 |
| `W[13]` `decoded_mask` | 8 | 16 | 2 | 4 | 32 | 8 | 1 | 1 | 1 | 0 |
| `W[14..20]` the kind bit set | `add` | `sub` | `addi` | `auipc` | `lui` | `add` | `system` | `system` | `system` | none |
| `W[20]` `is_ecall` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 |
| `W[21]` `is_fence` | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `W[22]` `is_deleg_9` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| `W[23..28]` `is_deleg_10`, `is_deleg_11`, `is_deleg_15`, `is_deleg_16`, `is_deleg_17` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[28]` `wrap` | 1 | 1 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 |
| `W[29]` `rd_hi` | `0x1234` | `0x1234` | `0xffff` | 0 | `0x1234` | `0x1234` | 0 | 0 | 0 | 0 |
| `W[30]` `pc_wrap` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[31]` `next_pc_hi` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 0 |

`F` computes the same sum as `A` and writes 0: `rd_selected` still holds the result, and
`rd_write_masked` masks it. `H`'s decoded fall-through is `0x10014` while its next pc is 1.
**`I` and `H` are the same instruction word** — a `SYSTEM` row with code `ECALL` — and every
column that differs between them follows from one cell, the `a7` the `rs1` query reads: `0x507`
instead of 93 sets `is_deleg_9`, which makes the `deleg` query present (`deleg_mask_rule`),
names address space 4 in `deleg_space` (`deleg_space_rule`), makes the answer 0
(`deleg_writes_no_register`) and makes the next pc the fall-through (`next_pc_rule`), and which
turns `ecall_is_exit` and `exit_status` off. That is the whole of the delegation row kind, and
the type is the whole of what one delegation row differs from another by.

### 3.10 What fixes each cell

All seventeen `honest_rows`, probed one cell at a time: a cell is listed below when adding 5 to
it alone breaks no gate and no range obligation, evaluated row-locally (as `violated_relations`
and `violated_lookups` evaluate a row). Adding 5 never probes a boolean column, whose
booleanity gate refuses 5, so each boolean column was also flipped between 0 and 1; that finds
two more cells, marked (flip). A cell listed is fixed, if at all, by something that is not
row-local: the **memory argument**, when the cell is in a leaf whose mask is 1; the **decoder
table**, when it is in `decode_row`'s tuple on a live row; or nothing. The multiplicities
`W[32..35]` appear on every row and are not a row's property at all.

A read timestamp is a case apart. Its gap obligations hold it only in
`[4·cycle + Δ_q − 2^38, 4·cycle + Δ_q)`, which the timestamp of any earlier write satisfies, so
the memory argument alone fixes it. `+5` happens to stay inside a register's synthetic gap of 7,
so `M[8]`, `M[13]` and `M[18]` show up on every row; the pc's gap is 3, so `M[3]` shows up on
padding alone, but on a live row a rise of 1 to 3 passes too, and so does a fall to any earlier
timestamp once `pc_gap_hi` is re-chosen (a fall of less than `2^19 − 3` passes with it unchanged).

| cell | fixed, on the rows that use it, by | rows where less fixes it, or nothing |
| --- | --- | --- |
| `M[0]` `cycle` | the memory argument (every write leaf's timestamp), with the gap obligations bounding it below | padding: nothing |
| `M[1]` `pc_mask` (flip) | its booleanity gate, the mask rules through the row's other masks, and the memory argument | fence: the memory argument alone (1 → 0 breaks no gate, since the row has no other query for a mask rule to tie to it, and it switches every lookup off); padding: 0 → 1 is refused by `gap_lo_pc`, whose gap becomes −1 |
| `M[2]` `pc_addr` | the memory argument alone: no gate holds it to 0, but a pc chain at any other address has no initial and no final tuple, and cannot balance (`memory.md` §4.2's counting) | padding: nothing |
| `M[4]` `pc_read_value` | the memory argument and the decoder table; on an auipc row, also `add_addi_auipc` | padding: nothing |
| `M[3]`, `M[8]`, `M[13]`, `M[18]` read timestamps | the memory argument alone; the gap obligations only hold each below its own write | rows without that query, padding included: nothing |
| `M[7]` `rs1_addr` | `rs1_addr_rule` | auipc, lui, fence, padding: nothing |
| `M[12]` `rs2_addr` | `rs2_addr_rule` | addi (nop included), auipc, lui, fence, padding: nothing |
| `M[17]` `rd_addr` | `rd_addr_rule` | fence, padding: nothing |
| `M[19]` `rd_read_value` | the memory argument; on the exit row, also `exit_status` | fence, **the delegation row**, padding: nothing — `exit_status` is off there, and 123 reads `rd_selected` rather than what `a0` held |
| `M[22]` `deleg_addr` | `deleg_addr_rule`, and the memory argument | every row but the delegation row: nothing, the mask being 0 |
| `M[23]` `deleg_read_ts` | `deleg_read_ts_zero`, with `gap_lo_deleg` | every row but the delegation row: nothing |
| `M[24]` `deleg_read_value` | `deleg_read_value_zero` | every row but the delegation row: nothing |
| `M[25]` `deleg_write_value` | the memory argument alone, **on every row including the delegation row**: no gate reads it | every row: no gate |
| `W[0]` `pc_gap_hi` | its gap obligations | padding: nothing |
| `W[1]`, `W[2]`, `W[3]`, `W[4]` gap chunks | their gap obligations | rows without that query: nothing |
| `W[5]` `rd_inv` | `rd_is_zero_inverse`, where `rd_addr ≠ 0` | rows writing `x0` (nop included), fence, padding: nothing |
| `W[8]` `decoded_next_pc` | `next_pc_rule` and the decoder table | the exit row: the decoder table alone, since `next_pc_rule` cancels it there — **but not the delegation row**, which falls through, so `next_pc_rule` ties it there like any ordinary row; padding: `next_pc_rule` alone, which only ties it to `pc_write_value` and `pc_wrap` |
| `W[9]` `decoded_rs1` | `rs1_addr_rule` and the decoder table | auipc, lui and fence rows: the decoder table alone; padding: nothing |
| `W[10]` `decoded_rs2` | `rs2_addr_rule` and the decoder table | addi, auipc, lui and fence rows: the decoder table alone; padding: nothing |
| `W[11]` `decoded_rd` | `rd_addr_rule` and the decoder table | fence rows: the decoder table alone; padding: nothing |
| `W[12]` `decoded_imm` | the gate its kind reads it in, and the decoder table | sub rows: the decoder table alone; padding: nothing |
| `W[28]` `wrap` (flip) | `add_addi_auipc` or `sub` | lui, fence, exit, **the delegation row** and padding: `wrap_boolean` alone, since the two gates that read it are gated off there |
| `W[29]` `rd_hi`, `W[31]` `next_pc_hi` | their range obligations | padding: nothing |

**Three rows left this table when the frame narrowed**, and each was there for the same reason:
the `arg1`, `arg2` and `ram` columns and their three gap chunks were fixed by nothing on any
row, and the `arg1` and `arg2` write-back pairs were fixed only by a gate that a pair moved
together keeps. They were the registry's largest block of cells nothing constrained, and they
are gone rather than constrained (§26 observation 2).

On a padding row every mask is 0 and every lookup is switched off, so no cell there reaches a
memory event or a table. The gates still hold `pc_write_value + 2^32·pc_wrap = decoded_next_pc`
and `rd_write_value = rd_selected` there; the honest fill writes 0 everywhere. A fence row,
whose `rd_mask` is 0, leaves the pair `rd_selected`, `rd_write_value` free but for its range
obligations: `rd_write_masked` holds the two equal (the row's `rd_is_zero` is 0),
`rd_hi_range` and `rd_lo_range` keep `rd_selected` below `2^32`, and nothing else reads either.

**`deleg_space` is the one frame column no row leaves free.** `deleg_space_rule` is ungated and
degree 1, so it is not in the table above at all: adding 5 breaks it on the padding row exactly
as on the delegation row, and no other gate, obligation or table is needed to fix the cell. That
is what a type tag has to be — the mirror's leaf reads it on every row, and a leaf is not gated
by anything a row chooses.

**`deleg_write_value` is free on every row, and that is the design** (§26 observation 19). It is
one half of the anchor's answer pair, and its other half is §12's `anchor_value`: nothing fixes
either locally, and the two must be equal or the multiset does not balance. A prover that writes
7 on both sides proves the same statement; a prover that writes 7 on one is refused as
`MemoryArgument`, which is `delegation.md` §5.2's whole argument.

### 3.11 The recursion format's form

`constraints::recursion_circuit(0, n)` is `add_sub::recursion_artifact(n)` with
`add_sub::recursion_channels()`: the private `build` that `add_sub::artifact` runs, over all ten
rows of `constants::delegation::TYPES` where the base form takes the first
`constants::delegation::BASE_TYPES = 6`. Normative spec: `recursion.md` §1.2 and §1.4. A
statement is in the recursion format exactly when its `VmConfig` holds `FIELD_WINDOWS`
(`VmConfig::is_recursion`), and `VmConfig::circuit` then takes every circuit from
`recursion_circuit`, which returns every other family of §1.1 byte for byte as `family_circuit`
does (`crates/constraints/tests/recursion.rs`, `the_registries_differ_in_add_sub_alone`).
`family_circuit(0, n)` is unchanged: **the base form keeps its gate and its bytes**, and the
committed `add_sub.bin` is still it. Fill: the same private `fill::add_sub`, which writes ten
request selectors when `config.is_recursion()` and six otherwise, and refuses a recursion request
in a base-format statement by name.

**What this subsection was read from.** `checker dump` of `recursion_circuit(0, 20)`'s bytes
against `checker dump` of `family_circuit(0, 20)`'s, diffed line by line once the moved `W`
indices and relation numbers are mapped across. Nothing differs that is not named below. The
base positions are the committed artifact's (`add_sub.bin`, SHA-256 `a6113128…6cae38c7`), whose
six request selectors sit at `W[22..28]`: `is_deleg_9`, `_10`, `_11`, `_15`, `_16` and `_17`, the
last two S26c's `SHA256_COMP` and `EC_ADD`. Its gate numbers are that artifact's too.

**The counts.** Four `W` columns and twelve enforcing gates are added, and one gate is replaced.
Nothing else changes:

| | base, `family_circuit(0, n)` | recursion, `recursion_circuit(0, n)` |
| --- | --- | --- |
| delegation types known | 6 | **10** |
| `M` / `W` / `S` / virtual | 27 / 35 / 7 / 2 | 27 / **39** / 7 / 2 |
| committed, layer 0's width | 69 | **73** |
| gate list 0: leaves, enforcing (d1/d2) | 68, 63 (5/58) | 68, **75 (5/70)** |
| lookups (ts/r16/gen/dec) | 15 (10/4/0/1) | 15 (10/4/0/1) |
| gate lists, top, inner at `n = 20` | 25 (5 + 20), `L25`, 298 | 25 (5 + 20), `L25`, 298 |
| relations at `n = 20` / `n = 22` | 361 / 377 | **373 / 389** |
| outputs | 8 | 8 |
| bytes at `n = 20` / `n = 22` | 70,974 / 72,064 | **77,987 / 79,077** |

The halving lists are the same in both, so the differences do not depend on the height:
**12 relations and 7,013 bytes**. Both registries return `Some` for `19 ≤ n ≤ 30`, because the
channels and so their floors are the same. The recursion form is not committed as bytes.
`crates/constraints/tests/vectors/recursion.txt` pins its shape line and digest at `n = 20`, the
height the recursion programs run the family at. `cargo run -p kat-gen -- recursion` writes
that line:

```text
ADD_SUB_LUI_AUIPC 20 27 39 25 298 373 8 77987 0531ed89f637e857499cc7a38dd0fea37030afbb2ca936c38cebbcfb62f32f74
#                 n  memory witness layers inner relations outputs bytes sha256
```

**The row kinds it adds** (§3.2). There are four delegation request kinds, one per recursion type.
Each is a base request's row: the same instruction word, the same ecall frame, and the same
mirror query at the `a0` it read. Only the value it writes into `a0` differs:

| row kind | `a7`, the `rs1` read | selector | `deleg_space` | `rd_selected`, written to `x10` | `next_pc` |
| --- | --- | --- | --- | --- | --- |
| a base request (§3.2) | its type's number | one of `W[22..28]` | 4–9 | 0 | the fall-through |
| `FR_OP` request, family 19 | `0x509` | `W[28]` | 11 | `a0 + 16`: the frame is 4 words | the fall-through |
| `P2_FIELD` request, family 20 | `0x50A` | `W[29]` | 12 | `a0 + 20`: 5 words | the fall-through |
| `FIELD_IO` request, family 21 | `0x50B` | `W[30]` | 13 | `a0 + 12`: 3 words | the fall-through |
| `FQ_OP` request, family 22 | `0x50C` | `W[31]` | 14 | `a0 + 16`: 4 words | the fall-through |

`a0` is the frame base, `rs2_read_value`. The tags skip 10, which is `address_space::FIELD`: the
field memory's space, not an anchor's (`recursion.md` §2.1). **In the base form such a row cannot
be proved**, exactly as a retired `read` cannot. No base selector names its number, so the base
`ecall_is_exit` requires `a7` to be 93 and refuses the row. The fill refuses it before that, by
name.

**Witness columns.** Every column of §3.3 not listed here keeps its base address: all 27 `M`,
`W[0..28]` and all 7 `S`. Four are added. `fill::add_sub` fills them:

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[28]` | `is_deleg_19` | `add_sub::is_delegation(6)` | `FR_OP` request row | 1 on an ecall row whose `a7` is `0x509` | `is_deleg_19_boolean`, `deleg_19_is_an_ecall`, `deleg_19_number`, `ecall_is_exit`, `deleg_mask_rule`, `exit_status`, `deleg_a0_rule`, `deleg_space_rule`, `next_pc_rule` |
| `W[29]` | `is_deleg_20` | `is_delegation(7)` | `P2_FIELD` request row | 1 on an ecall row whose `a7` is `0x50A` | the same nine, `_20`'s three among them |
| `W[30]` | `is_deleg_21` | `is_delegation(8)` | `FIELD_IO` request row | 1 on an ecall row whose `a7` is `0x50B` | the same nine, `_21`'s three among them |
| `W[31]` | `is_deleg_22` | `is_delegation(9)` | `FQ_OP` request row | 1 on an ecall row whose `a7` is `0x50C` | the same nine, `_22`'s three among them |

The seven columns after them move up by four. Their meaning, fill and readers are §3.3's. The
multiplicities are counted by `trace::build_multiplicities` over `recursion_channels()`:

| address | name | Rust | base address |
| --- | --- | --- | --- |
| `W[32]` | `wrap` | `add_sub::wrap(10)` | `W[28]` |
| `W[33]` | `rd_hi` | `rd_hi(10)` | `W[29]` |
| `W[34]` | `pc_wrap` | `pc_wrap(10)` | `W[30]` |
| `W[35]` | `next_pc_hi` | `next_pc_hi(10)` | `W[31]` |
| `W[36]` | `mult_timestamp` | `multiplicities(10)[0]`, `recursion_channels()[0].multiplicity` | `W[32]` |
| `W[37]` | `mult_range16` | `multiplicities(10)[1]` | `W[33]` |
| `W[38]` | `mult_decoder` | `multiplicities(10)[2]` | `W[34]` |

The `10` is `constants::delegation::TYPES.len()`, which is what `fill::add_sub` passes;
`add_sub.rs`'s own `TYPES` is private. **`add_sub::WRAP`, `RD_HI`, `PC_WRAP`, `NEXT_PC_HI` and
`MULTIPLICITIES` are the base form's addresses**, each the function above at `BASE_TYPES`, and
`IS_DELEGATION` holds the six base selectors only. None of them names a column of this form past
`W[27]`.

Some unmoved columns change readers. `deleg_a0_rule` replaces `deleg_writes_no_register` as a
reader of `W[7] rd_selected`. It is a new reader of `M[14] rs2_read_value` and of each base
selector, `W[22..28]`. `M[21] deleg_mask` loses `deleg_writes_no_register` and gains no reader.
`M[26] deleg_space` takes four more values, 11 to 14.

**Gate list 0's leaves** (§3.4). The same 68, in the same order, with the same named forms. Seven
positional forms move with the columns they read:

| `L1` | node | positional |
| --- | --- | --- |
| 16 | `timestamp_table_num` | `−W[36]` |
| 48 | `range16_table_num` | `−W[37]` |
| 51 | `rd_hi_range_den` | `g + M[1]·W[33]` |
| 53 | `rd_lo_range_den` | `g + M[1]·W[7] − 2^16·M[1]·W[33]` |
| 55 | `next_pc_hi_range_den` | `g + M[1]·W[35]` |
| 57 | `next_pc_lo_range_den` | `g + M[1]·M[5] − 2^16·M[1]·W[35]` |
| 64 | `decoder_table_num` | `−W[38]` |

No leaf reads a new column. The selectors are `W` columns, and the mirror's two leaves take the
type from `deleg_space`, as §3.4 describes, now over ten tags.

**Gate list 0's enforcing gates.** Relations 68–142 hold 75 gates, where the base form holds 63
at 68–130. Twelve are inserted after the base types' eighteen, which moves every later gate up
by 12:

| base relation | recursion relation | gate | what changed |
| --- | --- | --- | --- |
| 68–108 | 68–108 | the frame's 11, `kind_system_boolean` through `fence_code`, and the six base types' three apiece | nothing |
| — | **109–120** | `is_deleg_t_boolean`, `deleg_t_is_an_ecall`, `deleg_t_number` for `t` = 19, 20, 21, 22 | added |
| 109 | 121 | `ecall_is_exit` | four more types |
| 110–112 | 122–124 | `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule` | nothing |
| 113 | 125 | `deleg_mask_rule` | four more types |
| 114–118 | 126–130 | `rs1_addr_rule`, `rs2_addr_rule`, `rd_addr_rule`, `rs1_value_masked`, `rs2_value_masked` | nothing |
| 119, 120 | 131, 132 | `add_addi_auipc`, `sub` | `wrap` read at `W[32]` |
| 121 | 133 | `lui` | nothing |
| 122 | 134 | `exit_status` | four more types |
| 123 `deleg_writes_no_register` | **135 `deleg_a0_rule`** | what a request writes into `a0` | **replaced** |
| 124–126 | 136–138 | `deleg_read_ts_zero`, `deleg_read_value_zero`, `deleg_addr_rule` | nothing |
| 127 | 139 | `deleg_space_rule` | four more tags |
| 128, 129 | 140, 141 | `wrap_boolean`, `pc_wrap_boolean` | read at `W[32]` and `W[34]` |
| 130 | 142 | `next_pc_rule` | four more types; `pc_wrap` read at `W[34]` |

All 13 added or replacing gates are `Quadratic` and degree 2, so the degree-1 count stays at 5.
Every one of the 75 has constant 0, `zero_row_valid` is still `true`, and the padding row is all
zeros over the 73 committed columns. In the blocks below,
`D = is_deleg_9 + is_deleg_10 + is_deleg_11 + is_deleg_15 + is_deleg_16 + is_deleg_17 +
is_deleg_19 + is_deleg_20 + is_deleg_21 + is_deleg_22`, the sum over `W[22..32]`.

```text
────────────────────────────────────────────────────────────────────────────────────────────
109–120 three gates per recursion type, continuing 91–108's loop over the registry
                                                                        Quadratic, degree 2
        code  add_sub::recursion_artifact: build's loop over DELEGATIONS[..10]   S-RECURSION

  109 is_deleg_19_boolean   0 = W[28] − W[28]·W[28]    0 = is_deleg_19 − is_deleg_19²
  110 deleg_19_is_an_ecall  0 = W[28] − W[28]·W[20]    0 = is_deleg_19·(1 − is_ecall)
  111 deleg_19_number       0 = −1289·W[28] + W[28]·M[9]
                                                       0 = is_deleg_19·(rs1_read_value − 0x509)
  112 is_deleg_20_boolean   0 = W[29] − W[29]·W[29]    0 = is_deleg_20 − is_deleg_20²
  113 deleg_20_is_an_ecall  0 = W[29] − W[29]·W[20]    0 = is_deleg_20·(1 − is_ecall)
  114 deleg_20_number       0 = −1290·W[29] + W[29]·M[9]
                                                       0 = is_deleg_20·(rs1_read_value − 0x50A)
  115 is_deleg_21_boolean   0 = W[30] − W[30]·W[30]    0 = is_deleg_21 − is_deleg_21²
  116 deleg_21_is_an_ecall  0 = W[30] − W[30]·W[20]    0 = is_deleg_21·(1 − is_ecall)
  117 deleg_21_number       0 = −1291·W[30] + W[30]·M[9]
                                                       0 = is_deleg_21·(rs1_read_value − 0x50B)
  118 is_deleg_22_boolean   0 = W[31] − W[31]·W[31]    0 = is_deleg_22 − is_deleg_22²
  119 deleg_22_is_an_ecall  0 = W[31] − W[31]·W[20]    0 = is_deleg_22·(1 − is_ecall)
  120 deleg_22_number       0 = −1292·W[31] + W[31]·M[9]
                                                       0 = is_deleg_22·(rs1_read_value − 0x50C)

  reads as  the base types' three gates, over four more numbers: ecall::PRECOMPILE_FR_OP,
            PRECOMPILE_P2_FIELD, PRECOMPILE_FIELD_IO and PRECOMPILE_FQ_OP, read through
            constants::delegation::TYPES. The const assertion in add_sub.rs that makes the
            number gates a partition runs over the whole registry, not over its base prefix.
            So the ten numbers are pairwise distinct, and an ecall row is either an exit or a
            request of exactly one of ten types.

────────────────────────────────────────────────────────────────────────────────────────────
121     ecall_is_exit — every ecall that is not a delegation is EXIT    Quadratic, degree 2

  positional  0 = −93·W[20] + 93·W[22] + 93·W[23] + 93·W[24] + 93·W[25] + 93·W[26]
                  + 93·W[27] + 93·W[28] + 93·W[29] + 93·W[30] + 93·W[31]
                  + W[20]·M[9] − W[22]·M[9] − W[23]·M[9] − W[24]·M[9] − W[25]·M[9]
                  − W[26]·M[9] − W[27]·M[9] − W[28]·M[9] − W[29]·M[9] − W[30]·M[9]
                  − W[31]·M[9]
  named       0 = (is_ecall − D)·(rs1_read_value − 93)

────────────────────────────────────────────────────────────────────────────────────────────
125     deleg_mask_rule — the mirror query is a delegation row's alone  Quadratic, degree 2

  positional  0 = M[21] − M[1]·W[22] − M[1]·W[23] − M[1]·W[24] − M[1]·W[25] − M[1]·W[26]
                  − M[1]·W[27] − M[1]·W[28] − M[1]·W[29] − M[1]·W[30] − M[1]·W[31]
  named       0 = deleg_mask − pc_mask·D

────────────────────────────────────────────────────────────────────────────────────────────
134     exit_status — the exit row writes a0 back                       Quadratic, degree 2

  positional  0 = W[20]·M[19] − W[20]·W[7] − W[22]·M[19] + W[22]·W[7] − W[23]·M[19]
                  + W[23]·W[7] − W[24]·M[19] + W[24]·W[7] − W[25]·M[19] + W[25]·W[7]
                  − W[26]·M[19] + W[26]·W[7] − W[27]·M[19] + W[27]·W[7] − W[28]·M[19]
                  + W[28]·W[7] − W[29]·M[19] + W[29]·W[7] − W[30]·M[19] + W[30]·W[7]
                  − W[31]·M[19] + W[31]·W[7]
  named       0 = (is_ecall − D)·(rd_read_value − rd_selected)

────────────────────────────────────────────────────────────────────────────────────────────
139     deleg_space_rule — the mirror's leaf names the requested type   Linear, degree 1

  positional  0 = M[26] − 4·W[22] − 5·W[23] − 6·W[24] − 7·W[25] − 8·W[26] − 9·W[27]
                  − 11·W[28] − 12·W[29] − 13·W[30] − 14·W[31]
  named       0 = deleg_space − (4·is_deleg_9 + 5·is_deleg_10 + 6·is_deleg_11 + 7·is_deleg_15
                                 + 8·is_deleg_16 + 9·is_deleg_17 + 11·is_deleg_19
                                 + 12·is_deleg_20 + 13·is_deleg_21 + 14·is_deleg_22)

  reads as  11 to 14 are address_space::DELEGATION_FR_OP, DELEGATION_P2_FIELD,
            DELEGATION_FIELD_IO and DELEGATION_FQ_OP, read through the registry. 10 is
            address_space::FIELD and names no type.

────────────────────────────────────────────────────────────────────────────────────────────
142     next_pc_rule — the fall-through, or HALT_PC on the exit row     Quadratic, degree 2

  positional  0 = M[5] + 2^32·W[34] − W[8] − W[20] + W[22] + W[23] + W[24] + W[25] + W[26]
                  + W[27] + W[28] + W[29] + W[30] + W[31] + W[20]·W[8] − W[22]·W[8]
                  − W[23]·W[8] − W[24]·W[8] − W[25]·W[8] − W[26]·W[8] − W[27]·W[8]
                  − W[28]·W[8] − W[29]·W[8] − W[30]·W[8] − W[31]·W[8]
  named       0 = pc_write_value + 2^32·pc_wrap − (1 − is_ecall + D)·decoded_next_pc
                  − HALT_PC·(is_ecall − D)                                     (HALT_PC = 1)

  reads as (121, 125, 134, 139, 142)  §3.5's readings with D summing ten selectors: a
                     recursion request is not an exit, asks a7 for its own number, makes the
                     mirror query in its own space, writes no exit status and falls through.
                     Each type adds a linear term and a product to 121 and to 142, a product
                     to 125, two products to 134 and a linear term to 139.

────────────────────────────────────────────────────────────────────────────────────────────
131, 132, 140, 141   the four gates that read wrap or pc_wrap, which moved

  131 add_addi_auipc   0 = W[17]·M[9] + W[17]·M[14] + W[17]·W[12] − W[17]·W[7] − 2^32·W[17]·W[32]
                         + W[15]·M[9] + W[15]·M[14] + W[15]·W[12] − W[15]·W[7] − 2^32·W[15]·W[32]
                         + W[16]·M[9] + W[16]·M[14] + W[16]·W[12] − W[16]·W[7] − 2^32·W[16]·W[32]
                         + W[16]·M[4]
  132 sub              0 = W[18]·M[9] − W[18]·M[14] − W[18]·W[7] + 2^32·W[18]·W[32]
  140 wrap_boolean     0 = W[32] − W[32]·W[32]
  141 pc_wrap_boolean  0 = W[34] − W[34]·W[34]

  Their named forms are §3.5's.

────────────────────────────────────────────────────────────────────────────────────────────
135     deleg_a0_rule — a request writes a0 what its type answers       Quadratic, degree 2
        code  add_sub's build, its types != BASE_TYPES arm,
              in deleg_writes_no_register's place                               S-RECURSION

  positional  0 = −16·W[28] − 20·W[29] − 12·W[30] − 16·W[31]
                  + W[22]·W[7] + W[23]·W[7] + W[24]·W[7] + W[25]·W[7] + W[26]·W[7] + W[27]·W[7]
                  + W[28]·W[7] − W[28]·M[14] + W[29]·W[7] − W[29]·M[14]
                  + W[30]·W[7] − W[30]·M[14] + W[31]·W[7] − W[31]·M[14]
  named, factored
    0 =   (is_deleg_9 + is_deleg_10 + is_deleg_11 + is_deleg_15 + is_deleg_16 + is_deleg_17)
              · rd_selected
        + is_deleg_19 · (rd_selected − rs2_read_value − 16)
        + is_deleg_20 · (rd_selected − rs2_read_value − 20)
        + is_deleg_21 · (rd_selected − rs2_read_value − 12)
        + is_deleg_22 · (rd_selected − rs2_read_value − 16)
    which is recursion.md §1.4's
      Σ_t is_deleg_t·rd_selected − Σ_{t ≥ BASE_TYPES} is_deleg_t·(rs2_read_value + 4·words_t)

  replaces    base 123 deleg_writes_no_register   0 = M[21]·W[7]   0 = deleg_mask·rd_selected

  reads as  one type at a time:
              a base request    rd_selected = 0             the base answer
              FR_OP             rd_selected = a0 + 16
              P2_FIELD          rd_selected = a0 + 20
              FIELD_IO          rd_selected = a0 + 12
              FQ_OP             rd_selected = a0 + 16
            where a0 is rs2_read_value. On a row requesting nothing every term is 0. Each
            literal is 4·words from the type's registry row (fr_op::FRAME_WORDS 4, p2_field's
            5, field_io's 3, fq_op's 4), read through constants::delegation::TYPES. The gate is
            constants::delegation::a0_after and spells no length of its own.
```

**What the rule fixes.** On a recursion request row, the gates around it fix everything but
the value. `rs2_addr_rule` (127) makes the `rs2` query read `x10`, so `rs2_read_value` is the
`a0` the program passed. `deleg_addr_rule` (138) puts the mirror query at that address, and with
it the invocation that answers the query. `rd_addr_rule` (128) makes the `rd` query `x10` as
well, where `rd_is_zero` is 0, so `rd_write_masked` (78) writes `rd_selected` itself. So the row
writes, at `4·cycle + 3`, **`x10 ← a0 + 4·words_t`, the first byte past the frame its invocation
read**. In a tape of consecutive frames, that is the next frame's base. The sum is formed over
`Fr` with no carry column, and `rd_hi_range` and `rd_lo_range` still bound `rd_selected` below
`2^32` on every live row, so it is an exact integer sum. A frame ending at `2^32` or above has
no provable request. That costs nothing, because the caller's frame lies in RAM
(`constants::delegation::a0_after`).

**Why the replay needs it: the replay reads the advance and checks almost nothing else.**
`guest_sdk::recursion::replay` walks a tape's body (`recursion.md` §7) as
`a0 = ecall1(number, a0)`, call after call. Each request's frame base is the `a0` the previous
request left. The next run's header is read where the previous run's `a0` ended. The function
checks each run's number, and checks once that the body's last call ended exactly at its end.
`import` passes one fixed frame and reads nothing back. So the circuit is the only thing that
fixes where a call leaves `a0`. The SDK says as much: "the add/sub family's `a0` rule is what
holds a recursion request to it (§1.4), and nothing here reads it." If the write were free, the
prover would choose each call's frame. It could skip an `EQ` frame, which is one of the tape's
assertions, repeat a frame, or run one from anywhere in RAM, and still end at the body's end.
The advance buys one RISC-V row per call instead of two or three, and a tape replayed as
straight-line `ecall`s at one cycle per call (`recursion.md` §1.4, §7). This gate is what makes
it sound for the guest to skip the check. It also serves the base zeroing's own reason
(`delegation.md` §5.2, gate 1): a request writes a value it did not choose.

**Why the base gate cannot stay beside it, and why the rule is per type.** On a recursion
request, `deleg_mask` is 1. `deleg_writes_no_register` would then require `rd_selected = 0` and
refuse every honest request, so the rule has to replace it. `deleg_mask` says only that *some*
type was requested, while the advance is a different length per type. So the gate keys on the
selectors. It is the first request-side gate that does: §3.5's three zeroings each key on the
mask, one gate however many types there are. For a base type it says exactly what the base gate
says:

- Where `pc_mask` is 0, `rs1_value_masked` (129) makes `a7` 0, and each number gate then holds
  its selector to 0. Every term vanishes, as the base gate's does with `deleg_mask` at 0.
- On a live row, `deleg_mask_rule` (125) makes `deleg_mask` the sum of the selectors, at most
  one of them 1.

So `Σ_{base t} is_deleg_t·rd_selected` equals `deleg_mask·rd_selected` on every row that
holds a base request or no request, and the two forms differ only on a recursion request.

**What it leaves alone.** The other two zeroings and `deleg_addr_rule` (136–138) are §3.5's,
gated on the mask. A recursion request's mirror reads `T(AS_t, a0, 0, 0)` and writes
`T(AS_t, a0, 4·cycle + 3, deleg_write_value)`, with `AS_t` from 11 to 14. So the anchor pairing
(`delegation.md` §5.3) is untouched: the `a0` write belongs to the `rd` query and never reaches
the anchor's space.

**The lookups and channels** (§3.6). The same 15 lookups, in the same order, on the same
channels and selectors, with the same named tuples. Four positional tuples move:

| # | name | tuple, positional |
| --- | --- | --- |
| 10 | `rd_hi_range` | `W[33]` |
| 11 | `rd_lo_range` | `W[7] − 2^16·W[33]` |
| 12 | `next_pc_hi_range` | `W[35]` |
| 13 | `next_pc_lo_range` | `M[5] − 2^16·W[35]` |

The channels' multiplicities are `W[36]`, `W[37]` and `W[38]`. Obligations stay at 10, 4 and 1,
fraction trees at 16, 8 and 2, and output positions at 2–7. A selector is not a key of any
channel, and neither is a frame length, so the four types add no obligation and no leaf.
`L1` stays 68 wide. The challenge slots read are §0.4's, unchanged.

**The inner layers and outputs** (§3.7, §3.8). The same columns, nodes, formulas and widths:
`L1 … L5` are 68, 34, 18, 10 and 8 wide, and `inner = 138 + 8n`. Each relation number is the
base number plus 12:

| layer | gate list | base relations | recursion relations |
| --- | --- | --- | --- |
| `L2` | 1 | 131–164 | 143–176 |
| `L3` | 2 | 165–182 | 177–194 |
| `L4` | 3 | 183–192 | 195–204 |
| `L5` | 4 | 193–200 | 205–212 |
| `L{k+1}`, halving list `k`, `5 ≤ k ≤ n + 4` | `k` | `201 + 8(k − 5)` to `208 + 8(k − 5)` | `213 + 8(k − 5)` to `220 + 8(k − 5)` |
| the roots | `n + 4` | `193 + 8n` to `200 + 8n` | `205 + 8n` to `212 + 8n`: 365–372 at `n = 20`, 381–388 at `n = 22` |

The eight outputs keep their names, their order and their `verify_shard` steps. They sit at
`L{25}[0..8]` at `n = 20`, as in the base form at that height.

**Witness rows** (§3.9). `crates/checker/tests/add_sub.rs`, in
`a_recursion_request_advances_a0_past_its_frame`, builds three recursion requests with the
suite's `honest`. Each is at cycle 9 and pc `0x10010` like every row there, with
`a0 = RAM_ORIGIN + 0x400 = 0x10400` and an old `a0` of 7, the same frame base and history as the
keccak request. The test holds each one to every gate and range obligation of the recursion
form. The recursion form accepts the keccak request too. Only these cells differ from it:

| column | keccak request | `FR_OP` | `P2_FIELD` | `FIELD_IO` |
| --- | --- | --- | --- | --- |
| `M[9]`, `M[10]` `rs1_read_value`, `rs1_write_value` | `0x507` | `0x509` | `0x50a` | `0x50b` |
| `M[20]` `rd_write_value`, `W[7]` `rd_selected` | 0 | `0x10410` | `0x10414` | `0x1040c` |
| `M[26]` `deleg_space` | 4 | 11 | 12 | 13 |
| `W[22]` `is_deleg_9` | 1 | 0 | 0 | 0 |
| `W[28]`, `W[29]`, `W[30]` | 0, 0, 0 | 1, 0, 0 | 0, 1, 0 | 0, 0, 1 |
| `W[33]` `rd_hi` | 0 | 1 | 1 | 1 |

The test's two controls move `rd_selected` and `rd_write_value` together. One sets them to 0,
the base answer, on each recursion request. The other sets them to `0x10410`, an advance of 16,
on the keccak request. Each time, `deleg_a0_rule` is the only gate that refuses. The test also
asserts that the base artifact still carries `deleg_writes_no_register` and no `deleg_a0_rule`.
`FQ_OP`'s arm is the gate's fourth term and is not among the three. Its coverage comes from
`crates/checker/tests/recursion.rs`, in `the_recursion_add_sub_holds_on_the_field_requests`.
That test fills this form at `n = 20` from `guests/field-ops`' own trace, which issues all four
field calls and a tape `replay`. It holds every live row and a padding row to every relation
and range obligation, with the 105 field requests among them.

**What fixes each cell** (§3.10). No probe like §3.10's has been run over this form; the cells
its rows fix differently are read off gate 135:

- On a recursion request, `deleg_a0_rule` fixes `rd_selected` and `rd_write_value` to the `a0`
  the row read plus the frame's length, where the base form fixes them to 0. The memory
  argument fixes `a0` itself, `rs2_read_value`.
- The request's selector is held as a base selector is: by its booleanity, its ecall gate, and
  its number gate against the `a7` the memory argument fixes.
- `deleg_space` is held by the ungated `deleg_space_rule`, now to 11–14.

---

## 4. `JUMP_BRANCH_SLT` — family 1

### 4.1 Header

`family_circuit(1, n)` is `jump_branch_slt::artifact(n)` with `jump_branch_slt::channels()`,
built by `memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` with S17's two
gadgets, `constraints::gadgets::{is_zero, comparison}` (`QUERIES`, the `SLOT_*` constants and
the per-kind constants `SLTI` … `JAL` are private to `jump_branch_slt.rs`). Normative spec:
`jump-branch-slt.md`. Fill: `prover::family_fill(1)`, the private `fill::jump_branch_slt`.

75 committed columns (21 `M`, 44 `W`, 10 `S`) and two virtual tables. Gate list 0 writes 84
leaves and holds 42 enforcing gates. 22 lookups on four channels, 10 outputs. At `n = 20`, the
height S17 proves, there are 25 gate lists, the top is `L25`, and the circuit has 372 inner
columns and 414 relations; a shard proof of it is 61,612 bytes (`crates/prover/tests/control.rs`).
`artifact` panics unless the frame is `QUERIES`, the channels carry exactly 8, 11, 2 and 1
obligations, and `lookup::check_copowers` finds `next_pc`'s direct range pair beside
`next_pc_even`, which halves it. It also panics on every refusal of the assembly, among them
`n < 19` (the 19-bit timestamp table needs 19 variables) and `n > 30` (`MAX_TRACE_VARS`);
`family_circuit` returns `None` for both rather than calling it.

### 4.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::jump_branch_slt`, bit `k` being
`W[13 + k]`. The decoded table's `imm` is the value the instruction uses, two's complement, and
a form's absent register is `x0` (`jump-branch-slt.md` §1). `sc` is
`kind_slti + kind_slt + kind_blt + kind_bge`.

| row kind | bit (`decoded_mask`) | `decoded_imm` | queries present | `cmp_rhs` | `sc` | `taken` | `rd_selected` | `next_pc` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `slti` | 0 (1) | the compare immediate, sign-extended, as a `u32` | pc rs1 rd | the immediate | 1 | 0 | `lt` | the fall-through |
| `sltiu` | 1 (2) | the same, which `sltiu` compares unsigned | pc rs1 rd | the immediate | 0 | 0 | `lt` | the fall-through |
| `slt` | 2 (4) | 0 | pc rs1 rs2 rd | `rs2` | 1 | 0 | `lt` | the fall-through |
| `sltu` | 3 (8) | 0 | pc rs1 rs2 rd | `rs2` | 0 | 0 | `lt` | the fall-through |
| `beq` | 4 (16) | the displacement | pc rs1 rs2 | `rs2` | 0 | `eq` | 0 | `pc + imm mod 2^32` where taken, else the fall-through |
| `bne` | 5 (32) | the displacement | pc rs1 rs2 | `rs2` | 0 | `1 − eq` | 0 | as `beq` |
| `blt` | 6 (64) | the displacement | pc rs1 rs2 | `rs2` | 1 | `lt` | 0 | as `beq` |
| `bge` | 7 (128) | the displacement | pc rs1 rs2 | `rs2` | 1 | `1 − lt` | 0 | as `beq` |
| `bltu` | 8 (256) | the displacement | pc rs1 rs2 | `rs2` | 0 | `lt` | 0 | as `beq` |
| `bgeu` | 9 (512) | the displacement | pc rs1 rs2 | `rs2` | 0 | `1 − lt` | 0 | as `beq` |
| `jalr` | 10 (1024) | the offset | pc rs1 rd | 0 | 0 | 0 | the fall-through, the link | `(rs1 + imm) mod 2^32`, bit 0 cleared |
| `jal` | 11 (2048) | the displacement | pc rd | 0 | 0 | 0 | the fall-through, the link | `pc + imm mod 2^32` |
| padding | none; all 0 | 0 | none | 0 | 0 | 0 | 0 | 0 |

Every kind is provable at S17. `pc_wrap` is the carry of the target sum on a row that takes a
target, and 0 on a fall-through; `jalr_drop` is bit 0 of `rs1 + imm` on a `jalr` row, and 0 on
every other in an honest fill. `rd = x0` is not a kind: the table's `rd` is 0, the frame's x0
rule writes 0, and `rd_selected` keeps the computed value. A compressed instruction (`c.jal`,
`c.beqz`, …) is one of these kinds at its own length: its table row's `next_pc`, which is also a
jump's link, is `pc + 2`. A live row at a pc holding no instruction of the family meets the
table's `MINUS_ONE` row, which its decoder tuple cannot equal (`jump-branch-slt.md` §5).

### 4.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §4.4 and §4.6.

**Memory-argument columns, `M[0..21]`** — §2's REG layout (`w = 4`), filled by
`trace::build_memory_columns`; committed in `PublicInputs::memory_commitments`, absorbed at G8
before the memory challenges.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the cycle `c` | leaves `write_*` (all 4); obligations `gap_lo_*` (all 4) |
| `M[1]` | `pc_mask` | `frame(0, FIELD_MASK)` | Row is live | 1 | leaves `read_pc`, `write_pc`; `pc_mask_boolean`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `eq_inverse` (as its `enable`); selector of `gap_hi_pc`, `gap_lo_pc`, the eleven `RANGE16` obligations, the two `GENERIC` lookups and `decode_row` |
| `M[2]` | `pc_addr` | `frame(0, FIELD_ADDR)` | PC address | 0 | leaves `read_pc`, `write_pc` |
| `M[3]` | `pc_read_ts` | `frame(0, FIELD_READ_TS)` | Previous pc write | `4(c − 1)` | leaf `read_pc`; `gap_lo_pc` |
| `M[4]` | `pc_read_value` | `frame(0, FIELD_READ_VALUE)` | Current pc | the instruction's pc | leaf `read_pc`; `next_pc_rule`; `decode_row` position 0 |
| `M[5]` | `pc_write_value` | `frame(0, FIELD_WRITE_VALUE)` | Next pc | the target, or the fall-through (§4.2) | leaf `write_pc`; `next_pc_rule`; `next_pc_lo_range`, `next_pc_even` |
| `M[6]` | `rs1_mask` | `frame(1, FIELD_MASK)` | rs1 present | 1 on every kind but `jal` | leaves `read_rs1`, `write_rs1`; `rs1_mask_boolean`, `rs1_mask_rule`, `rs1_addr_rule`, `rs1_value_masked`; selector of `gap_hi_rs1`, `gap_lo_rs1` |
| `M[7]` | `rs1_addr` | `frame(1, FIELD_ADDR)` | rs1 register | the decoded `rs1` | leaves `read_rs1`, `write_rs1`; `rs1_addr_rule` |
| `M[8]` | `rs1_read_ts` | `frame(1, FIELD_READ_TS)` | rs1 previous write | | leaf `read_rs1`; `gap_lo_rs1` |
| `M[9]` | `rs1_read_value` | `frame(1, FIELD_READ_VALUE)` | rs1 value; the comparison's left operand | 0 where absent | leaf `read_rs1`; `rs1_writes_back`, `rs1_value_masked`, `cmp_order`, `eq_inverse`, `eq_at_nonzero`, `next_pc_rule`; `cmp_lhs_lo_range` |
| `M[10]` | `rs1_write_value` | `frame(1, FIELD_WRITE_VALUE)` | rs1 written back | `rs1_read_value` | leaf `write_rs1`; `rs1_writes_back` |
| `M[11]` | `rs2_mask` | `frame(2, FIELD_MASK)` | rs2 present | 1 on `slt`, `sltu` and the six branches | leaves `read_rs2`, `write_rs2`; `rs2_mask_boolean`, `rs2_mask_rule`, `rs2_addr_rule`, `rs2_value_masked`; selector of `gap_hi_rs2`, `gap_lo_rs2` |
| `M[12]` | `rs2_addr` | `frame(2, FIELD_ADDR)` | rs2 register | the decoded `rs2` | leaves `read_rs2`, `write_rs2`; `rs2_addr_rule` |
| `M[13]` | `rs2_read_ts` | `frame(2, FIELD_READ_TS)` | rs2 previous write | | leaf `read_rs2`; `gap_lo_rs2` |
| `M[14]` | `rs2_read_value` | `frame(2, FIELD_READ_VALUE)` | rs2 value | 0 where absent | leaf `read_rs2`; `rs2_writes_back`, `rs2_value_masked`, `cmp_rhs_rule` |
| `M[15]` | `rs2_write_value` | `frame(2, FIELD_WRITE_VALUE)` | rs2 written back | `rs2_read_value` | leaf `write_rs2`; `rs2_writes_back` |
| `M[16]` | `rd_mask` | `frame(3, FIELD_MASK)` | rd present | 1 on the four `slt` kinds, `jalr` and `jal` | leaves `read_rd`, `write_rd`; `rd_mask_boolean`, `rd_is_zero_inverse`, `rd_mask_rule`, `rd_addr_rule`; selector of `gap_hi_rd`, `gap_lo_rd` |
| `M[17]` | `rd_addr` | `frame(3, FIELD_ADDR)` | rd register | the decoded `rd` | leaves `read_rd`, `write_rd`; `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_addr_rule` |
| `M[18]` | `rd_read_ts` | `frame(3, FIELD_READ_TS)` | rd previous write | | leaf `read_rd`; `gap_lo_rd` |
| `M[19]` | `rd_read_value` | `frame(3, FIELD_READ_VALUE)` | rd old value | | leaf `read_rd` |
| `M[20]` | `rd_write_value` | `frame(3, FIELD_WRITE_VALUE)` | rd new value | `rd_selected`, or 0 into `x0` | leaf `write_rd`; `rd_write_masked` |

The frame's slots in `jump_branch_slt.rs` are `SLOT_PC = 0` through `SLOT_RD = 3`, so
`frame(3, ..)` is `frame(SLOT_RD, ..)` there. Every query of this frame is used by some kind.

**Witness columns, `W[0..44]`** — `W[0..6]` filled by `trace::build_frame_witness`, `W[6..40]`
by `fill::jump_branch_slt` (`W[6]` in place of S14's), `W[40..44]` by
`trace::build_multiplicities` inside `prover::shard_columns`; committed in
`ShardProof::witness_commitments`, absorbed at S3 before `g` and `β`. The `KINDS[k]` rows name
the private constant beside each (`KINDS[kind::SLTI as usize]` is `SLTI`, with `kind` being
`constants::extra_mask::jump_branch_slt`).

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0]` | `pc_gap_hi` | `memory::gap_hi(0)` | pc gap, high chunk | 0: a pc read's gap is always 3 | `gap_hi_pc`, `gap_lo_pc` |
| `W[1]` | `rs1_gap_hi` | `gap_hi(1)` | rs1 gap, high chunk | `gap >> 19` | `gap_hi_rs1`, `gap_lo_rs1` |
| `W[2]` | `rs2_gap_hi` | `gap_hi(2)` | rs2 gap, high chunk | | `gap_hi_rs2`, `gap_lo_rs2` |
| `W[3]` | `rd_gap_hi` | `gap_hi(3)` | rd gap, high chunk | | `gap_hi_rd`, `gap_lo_rd` |
| `W[4]` | `rd_inv` | `memory::rd_inv(4)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[5]` | `rd_is_zero` | `memory::rd_is_zero(4)` | rd is `x0` | | `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_is_zero_boolean`, `rd_write_masked` |
| `W[6]` | `rd_selected` | `memory::rd_selected(4)`; `sel` in `jump_branch_slt.rs` | Result | the link on `jal` and `jalr`, `lt` on the `slt` kinds, 0 on a branch; `rd = x0` included: the fill overwrites the 0 S14's builder writes there | `rd_write_masked`, `rd_value_rule`; `rd_lo_range` |
| `W[7]` | `decoded_next_pc` | `jump_branch_slt::DECODED[0]`; `SEQ` in `jump_branch_slt.rs` | Decoded fall-through | the table row's `next_pc` | `next_pc_rule`, `rd_value_rule`; `decode_row` position 1 |
| `W[8]` | `decoded_rs1` | `DECODED[1]` | Decoded rs1 | | `rs1_addr_rule`; `decode_row` position 2 |
| `W[9]` | `decoded_rs2` | `DECODED[2]` | Decoded rs2 | | `rs2_addr_rule`; `decode_row` position 3 |
| `W[10]` | `decoded_rd` | `DECODED[3]` | Decoded rd | | `rd_addr_rule`; `decode_row` position 4 |
| `W[11]` | `decoded_imm` | `DECODED[4]`; `IMM` in `jump_branch_slt.rs` | Decoded immediate | | `cmp_rhs_rule`, `next_pc_rule`; `decode_row` position 5 |
| `W[12]` | `decoded_mask` | `DECODED[5]` | Decoded kind mask | `1 << bit` | `decoded_mask_bits`; `decode_row` position 6 |
| `W[13]` | `kind_slti` | `KINDS[0]`; `SLTI` | slti row | | `kind_slti_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rd_mask_rule`, `cmp_rhs_rule`, `cmp_order`, `rd_value_rule` |
| `W[14]` | `kind_sltiu` | `KINDS[1]`; `SLTIU` | sltiu row | | `kind_sltiu_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rd_mask_rule`, `cmp_rhs_rule`, `rd_value_rule` |
| `W[15]` | `kind_slt` | `KINDS[2]`; `SLT` | slt row | | `kind_slt_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `cmp_order`, `rd_value_rule` |
| `W[16]` | `kind_sltu` | `KINDS[3]`; `SLTU` | sltu row | | `kind_sltu_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `rd_value_rule` |
| `W[17]` | `kind_beq` | `KINDS[4]`; `BEQ` | beq row | | `kind_beq_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `taken_rule` |
| `W[18]` | `kind_bne` | `KINDS[5]`; `BNE` | bne row | | `kind_bne_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `taken_rule` |
| `W[19]` | `kind_blt` | `KINDS[6]`; `BLT` | blt row | | `kind_blt_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `cmp_order`, `taken_rule` |
| `W[20]` | `kind_bge` | `KINDS[7]`; `BGE` | bge row | | `kind_bge_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `cmp_order`, `taken_rule` |
| `W[21]` | `kind_bltu` | `KINDS[8]`; `BLTU` | bltu row | | `kind_bltu_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `taken_rule` |
| `W[22]` | `kind_bgeu` | `KINDS[9]`; `BGEU` | bgeu row | | `kind_bgeu_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `taken_rule` |
| `W[23]` | `kind_jalr` | `KINDS[10]`; `JALR` | jalr row | | `kind_jalr_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rd_mask_rule`, `next_pc_rule`, `rd_value_rule` |
| `W[24]` | `kind_jal` | `KINDS[11]`; `JAL` | jal row | | `kind_jal_boolean`, `decoded_mask_bits`, `rd_mask_rule`, `next_pc_rule`, `rd_value_rule` |
| `W[25]` | `cmp_rhs` | `jump_branch_slt::CMP_RHS` | Comparison's right operand | `rs2_read_value`, or the immediate on `slti` and `sltiu` | `cmp_rhs_rule`, `cmp_order`, `eq_inverse`, `eq_at_nonzero`; `cmp_rhs_lo_range` |
| `W[26]` | `rs1_hi` | `RS1_HI` | rs1, high halfword | `rs1_read_value >> 16` | `cmp_lhs_hi_range`, `cmp_lhs_lo_range`; `cmp_lhs_get_sign` position 0 |
| `W[27]` | `rs1_sign` | `RS1_SIGN` | rs1, sign bit | `rs1_read_value >> 31` | `cmp_order`; `cmp_lhs_get_sign` position 1 |
| `W[28]` | `cmp_rhs_hi` | `CMP_RHS_HI` | Right operand, high halfword | `cmp_rhs >> 16` | `cmp_rhs_hi_range`, `cmp_rhs_lo_range`; `cmp_rhs_get_sign` position 0 |
| `W[29]` | `cmp_rhs_sign` | `CMP_RHS_SIGN` | Right operand, sign bit | `cmp_rhs >> 31` | `cmp_order`; `cmp_rhs_get_sign` position 1 |
| `W[30]` | `lt` | `LT` | Less-than | `rs1 < cmp_rhs`, read signed where `sc = 1` | `cmp_order`, `cmp_lt_boolean`, `taken_rule`, `rd_value_rule` |
| `W[31]` | `cmp_gap` | `CMP_GAP` | Comparison gap | `(rs1 − cmp_rhs) mod 2^32` | `cmp_order`; `cmp_gap_lo_range` |
| `W[32]` | `cmp_gap_hi` | `CMP_GAP_HI` | Gap, high halfword | `cmp_gap >> 16` | `cmp_gap_hi_range`, `cmp_gap_lo_range` |
| `W[33]` | `eq` | `EQ` | Operands equal | 1 where `rs1_read_value = cmp_rhs`, a `jal` row included (both read 0) | `eq_inverse`, `eq_at_nonzero`, `taken_rule` |
| `W[34]` | `eq_inv` | `EQ_INV` | Inverse of the difference | `(rs1_read_value − cmp_rhs)⁻¹`, or 0 | `eq_inverse` |
| `W[35]` | `taken` | `TAKEN` | Branch taken | | `taken_rule`, `taken_boolean`, `next_pc_rule` |
| `W[36]` | `jalr_drop` | `JALR_DROP` | jalr's dropped bit | bit 0 of `rs1 + imm` on a `jalr` row; 0 elsewhere | `jalr_drop_boolean`, `next_pc_rule` |
| `W[37]` | `pc_wrap` | `PC_WRAP` | Next-pc wrap | the carry of the target sum; 0 on a fall-through | `pc_wrap_boolean`, `next_pc_rule` |
| `W[38]` | `next_pc_hi` | `NEXT_PC_HI` | Next pc, high halfword | `pc_write_value >> 16` | `next_pc_hi_range`, `next_pc_lo_range`, `next_pc_even` |
| `W[39]` | `rd_hi` | `RD_HI` | Result, high halfword | `rd_selected >> 16` | `rd_hi_range`, `rd_lo_range` |
| `W[40]` | `mult_timestamp` | `MULTIPLICITIES[0]` | Timestamp-table count | per table row `t`: the gated gap chunks (`mask·chunk`) equal to `t`, credited to rows below `2^19` | leaf `timestamp_table_num` |
| `W[41]` | `mult_range16` | `MULTIPLICITIES[1]` | 16-bit-table count | per table row `t`: the gated halfwords (`pc_mask·expression`) equal to `t`, credited to rows below `2^16` | leaf `range16_table_num` |
| `W[42]` | `mult_generic` | `MULTIPLICITIES[2]` | Generic-table count | per table row `t`: the gated sign tuples equal to row `t`; a live row's sign lookup lands on row `2^16 + 1 + hi`, `U16GetSign`'s row for its halfword `hi`, and a padding row's two on row 0, the `ZeroEntry` | leaf `generic_table_num` |
| `W[43]` | `mult_decoder` | `MULTIPLICITIES[3]` | Decoder-table count | per table row `t`: the live cycles at pc `2t`; and every padding row's switched-off tuple (`MINUS_ONE` in all seven positions) on the table's lowest non-live row, row 0 | leaf `decoder_table_num` |

A switched-off obligation's gated tuple is 0 (`s·e` at `s = 0`), so row 0 of `mult_timestamp`
and `mult_range16` counts every switched-off obligation: all 8 timestamp and all 11 `RANGE16`
obligations of each padding row, and in `mult_timestamp` also the two chunks of any query a live
row does not make — `rs1` on `jal`; `rs2` on `slti`, `sltiu`, `jal` and `jalr`; `rd` on a
branch. The `RANGE16` and `GENERIC` obligations are selected by `pc_mask`, so none is off on a
live row. Row 0 also counts every live chunk or halfword whose value is 0, such as `pc_gap_hi`
on every live row. The generic table's all-zero tuple repeats on every row past `2^17 + 32`,
and the count goes to the lowest, row 0.

**Setup columns, `S[0..10]`** — two tables. `S[0..7]` is the family's decoded table,
`program::lookup_tuple(1)` order, filled by `program::FamilyTable::column_poly(j)`; committed in
program identity (`program::setup_commitments`) and carried as `VerifyingKey::setup_commitments`
for the family. `S[7..10]` is the packed generic table (§0.3), filled by
`program::lookup_tables::generic_table(n)`. Its commitments are the same three points at every
even `n ≥ 18`: `program::lookup_tables::generic_commitments(srs)` computes them once, at `2^18`, and
every key carries them as `VerifyingKey::generic_table`, whatever its families. Identity does
not bind them; the key's SRS digest covers them after its `SrsVerifier`, and the global
transcript absorbs that digest before every challenge. A shard opens `S[7..10]` against them,
after identity's list, because `FamilyCircuit::reads_generic_table` holds for this circuit
(`shard-proof.md` §3, §5.1, §7; `jump-branch-slt.md` §6). Each is read only by its table's
denominator, at the `β` power in the last column.

| address | name | Rust | descriptive name | contents | read by | weight |
| --- | --- | --- | --- | --- | --- | --- |
| `S[0]` | `table_pc` | `jump_branch_slt::channels()[3].table[0]` | Table pc | `RowField::Pc` | `decoder_table_den` | 1 |
| `S[1]` | `table_next_pc` | `channels()[3].table[1]` | Table fall-through | `RowField::NextPc` | `decoder_table_den` | `β` |
| `S[2]` | `table_rs1` | `channels()[3].table[2]` | Table rs1 | `RowField::Rs1` | `decoder_table_den` | `β²` |
| `S[3]` | `table_rs2` | `channels()[3].table[3]` | Table rs2 | `RowField::Rs2` | `decoder_table_den` | `β³` |
| `S[4]` | `table_rd` | `channels()[3].table[4]` | Table rd | `RowField::Rd` | `decoder_table_den` | `β⁴` |
| `S[5]` | `table_imm` | `channels()[3].table[5]` | Table immediate | `RowField::Imm` | `decoder_table_den` | `β⁵` |
| `S[6]` | `table_extra_mask` | `channels()[3].table[6]` | Table kind mask | `RowField::ExtraMask` | `decoder_table_den` | `β⁶` |
| `S[7]` | `generic_key` | `jump_branch_slt::GENERIC_TABLE[0]`, `channels()[2].table[0]` | Generic key | 0, `AND_BASE + a + 1`, `SIGN_BASE + h + 1` or `SHIFT_BASE + s + 1` | `generic_table_den` | 1 |
| `S[8]` | `generic_value` | `GENERIC_TABLE[1]` | Generic value | 0, `b`, `h >> 15` or `2^s` | `generic_table_den` | `β` |
| `S[9]` | `generic_result` | `GENERIC_TABLE[2]` | Generic result | 0, `a & b`, 0 or `2^(31 − s)` | `generic_table_den` | `β²` |

`jump_branch_slt::TABLE_WIDTH` is 7 and `constants::generic_table::WIDTH` is 3.

**Virtual tables** — never committed, never opened; `gkr_verify::verify` evaluates their
closed forms.

| address | name | Rust | descriptive name | value at row `y` | read by |
| --- | --- | --- | --- | --- | --- |
| `V[range19]` | `range19` | `VirtualKind::Range19`, wire tag 2 | 19-bit range table | `y mod 2^19` | `timestamp_table_den` |
| `V[range16]` | `range16` | `VirtualKind::Range16`, wire tag 3 | 16-bit range table | `y mod 2^16` | `range16_table_den` |

### 4.4 Gate list 0: the 84 leaves

A leaf's relation number equals its `L1` offset, 0 to 83.

**The memory product trees.** The read side is `L1[0..4]` and the write side `L1[4..8]`, each
leaf per §0.6. Four queries fill each side, so neither has a pad.

| `L1` | node | mask | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `read_pc` | `M[1]` | 3 | `M[2]` | `M[3]` | `M[4]` |
| 1 | `read_rs1` | `M[6]` | 1 | `M[7]` | `M[8]` | `M[9]` |
| 2 | `read_rs2` | `M[11]` | 1 | `M[12]` | `M[13]` | `M[14]` |
| 3 | `read_rd` | `M[16]` | 1 | `M[17]` | `M[18]` | `M[19]` |
| 4 | `write_pc` | `M[1]` | 3 | `M[2]` | `4·M[0] + 0` | `M[5]` |
| 5 | `write_rs1` | `M[6]` | 1 | `M[7]` | `4·M[0] + 1` | `M[10]` |
| 6 | `write_rs2` | `M[11]` | 1 | `M[12]` | `4·M[0] + 2` | `M[15]` |
| 7 | `write_rd` | `M[16]` | 1 | `M[17]` | `4·M[0] + 3` | `M[20]` |

`L{1}[0]`, `read_pc`, is §3.4's, address for address. The rd write in full:

```text
L{1}[7]  write_rd
  positional  1 + γ_M·M[16] − M[16] + M[16] + α_ts·M[16] ×3 + α_addr·M[17]·M[16]
                + α_ts·M[0]·M[16] ×4 + α_val·M[20]·M[16]
  named       rd_mask·T(REG, rd_addr, 4·cycle + 3, rd_write_value) + 1 − rd_mask
```

**The `timestamp` fraction tree**, `L1[8..40]`: 16 fractions, the table's then 8 gap
obligations then 7 pads. Fraction `i` is `(L1[8 + 2i], L1[9 + 2i])`, named `<node>_num` and
`<node>_den`.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 8, 9 | `timestamp_table` | `−mult_timestamp` | `V[range19] + g` |
| 1 | 10, 11 | `gap_hi_pc` | 1 | `g + pc_mask·pc_gap_hi` |
| 2 | 12, 13 | `gap_lo_pc` | 1 | `g − pc_mask + 4·pc_mask·cycle − pc_mask·pc_read_ts − 2^19·pc_mask·pc_gap_hi` |
| 3 | 14, 15 | `gap_hi_rs1` | 1 | `g + rs1_mask·rs1_gap_hi` |
| 4 | 16, 17 | `gap_lo_rs1` | 1 | `g + 4·rs1_mask·cycle − rs1_mask·rs1_read_ts − 2^19·rs1_mask·rs1_gap_hi` |
| 5 | 18, 19 | `gap_hi_rs2` | 1 | `g + rs2_mask·rs2_gap_hi` |
| 6 | 20, 21 | `gap_lo_rs2` | 1 | `g + rs2_mask + 4·rs2_mask·cycle − rs2_mask·rs2_read_ts − 2^19·rs2_mask·rs2_gap_hi` |
| 7 | 22, 23 | `gap_hi_rd` | 1 | `g + rd_mask·rd_gap_hi` |
| 8 | 24, 25 | `gap_lo_rd` | 1 | `g + 2·rd_mask + 4·rd_mask·cycle − rd_mask·rd_read_ts − 2^19·rd_mask·rd_gap_hi` |
| 9–15 | 26–39 | `timestamp_pad_0` … `timestamp_pad_6` | 0 | 1 |

The `gap_lo` masks carry `(Δ_q − 1)·m` as in §3.4. In positional form fraction 8's denominator
is `g + 2·M[16] + 4·M[16]·M[0] − M[16]·M[18] − 2^19·M[16]·W[3]`.

**The `range16` fraction tree**, `L1[40..72]`: 16 fractions, the table's then 11 obligations then
4 pads.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 40, 41 | `range16_table` | `−mult_range16` | `V[range16] + g` |
| 1 | 42, 43 | `cmp_lhs_hi_range` | 1 | `g + pc_mask·rs1_hi` |
| 2 | 44, 45 | `cmp_lhs_lo_range` | 1 | `g + pc_mask·rs1_read_value − 2^16·pc_mask·rs1_hi` |
| 3 | 46, 47 | `cmp_rhs_hi_range` | 1 | `g + pc_mask·cmp_rhs_hi` |
| 4 | 48, 49 | `cmp_rhs_lo_range` | 1 | `g + pc_mask·cmp_rhs − 2^16·pc_mask·cmp_rhs_hi` |
| 5 | 50, 51 | `cmp_gap_hi_range` | 1 | `g + pc_mask·cmp_gap_hi` |
| 6 | 52, 53 | `cmp_gap_lo_range` | 1 | `g + pc_mask·cmp_gap − 2^16·pc_mask·cmp_gap_hi` |
| 7 | 54, 55 | `rd_hi_range` | 1 | `g + pc_mask·rd_hi` |
| 8 | 56, 57 | `rd_lo_range` | 1 | `g + pc_mask·rd_selected − 2^16·pc_mask·rd_hi` |
| 9 | 58, 59 | `next_pc_hi_range` | 1 | `g + pc_mask·next_pc_hi` |
| 10 | 60, 61 | `next_pc_lo_range` | 1 | `g + pc_mask·pc_write_value − 2^16·pc_mask·next_pc_hi` |
| 11 | 62, 63 | `next_pc_even` | 1 | `g + 2⁻¹·pc_mask·pc_write_value − 2^15·pc_mask·next_pc_hi` |
| 12–15 | 64–71 | `range16_pad_0` … `range16_pad_3` | 0 | 1 |

In positional form fraction 11's denominator is `g + 2⁻¹·M[1]·M[5] − 2^15·M[1]·W[38]`. `2⁻¹`
is `(p + 1)/2`, which the dump prints as
`0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000001`, and `−2^15` as `-32768`.

**The `generic` fraction tree**, `L1[72..80]`: 4 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 72, 73 | `generic_table` | `−mult_generic` | `generic_key + β·generic_value + β²·generic_result + g` |
| 1 | 74, 75 | `cmp_lhs_get_sign` | 1 | `g + 257·pc_mask + pc_mask·rs1_hi + β·pc_mask·rs1_sign` |
| 2 | 76, 77 | `cmp_rhs_get_sign` | 1 | `g + 257·pc_mask + pc_mask·cmp_rhs_hi + β·pc_mask·cmp_rhs_sign` |
| 3 | 78, 79 | `generic_pad_0` | 0 | 1 |

```text
L{1}[75]  cmp_lhs_get_sign_den
  positional  g + 257·M[1] + M[1]·W[26] + β·M[1]·W[27]
  reads as    g + pc_mask·(e_0 + 1) + β·pc_mask·e_1 + β²·pc_mask·e_2,
              e = (rs1_hi + SIGN_BASE, rs1_sign, 0), SIGN_BASE = 256:
              the key rs1_hi + 257 and the sign at pc_mask = 1, the ZeroEntry at 0;
              e_2 is the constant 0 and contributes no term
```

**The `decoder` fraction tree**, `L1[80..84]`: 2 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 80, 81 | `decoder_table` | `−mult_decoder` | `table_pc + β·table_next_pc + β²·table_rs1 + β³·table_rs2 + β⁴·table_rd + β⁵·table_imm + β⁶·table_extra_mask + g` |
| 1 | 82, 83 | `decode_row` | 1 | `g_dec + (1 + β + β² + β³ + β⁴ + β⁵ + β⁶)·pc_mask + pc_mask·pc_read_value + β·pc_mask·decoded_next_pc + β²·pc_mask·decoded_rs1 + β³·pc_mask·decoded_rs2 + β⁴·pc_mask·decoded_rd + β⁵·pc_mask·decoded_imm + β⁶·pc_mask·decoded_mask` |

`decode_row_den` is §3.4's with the decoded row at `W[7..13]`: positionally
`g_dec + M[1] + β·M[1] + … + β⁶·M[1] + M[1]·M[4] + β·M[1]·W[7] + β²·M[1]·W[8] + β³·M[1]·W[9]
+ β⁴·M[1]·W[10] + β⁵·M[1]·W[11] + β⁶·M[1]·W[12]`.

### 4.5 Gate list 0: the 42 enforcing gates

Relations 84–125, in list order, in §3.5's format. The family's 32 come from
`jump_branch_slt::artifact`, its private helpers `booleanity`, `mask_rule`, `addr_rule` and
`value_masked`, and the two gadgets.

**A. The frame's gates (84–93)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
84–87   <q>_mask_boolean — each query's presence flag is a bit          Quadratic, degree 2
        code  memory::booleanity(frame(s, FIELD_MASK)), in frame_body

  84 pc_mask_boolean     0 = M[1]  − M[1]·M[1]      0 = pc_mask  − pc_mask²
  85 rs1_mask_boolean    0 = M[6]  − M[6]·M[6]      0 = rs1_mask − rs1_mask²
  86 rs2_mask_boolean    0 = M[11] − M[11]·M[11]    0 = rs2_mask − rs2_mask²
  87 rd_mask_boolean     0 = M[16] − M[16]·M[16]    0 = rd_mask  − rd_mask²

────────────────────────────────────────────────────────────────────────────────────────────
88–89   <q>_writes_back — a read-only register is left unchanged        Linear, degree 1
        code  memory::write_back(s), in frame_body

  88 rs1_writes_back     0 = M[10] − M[9]     0 = rs1_write_value − rs1_read_value
  89 rs2_writes_back     0 = M[15] − M[14]    0 = rs2_write_value − rs2_read_value

────────────────────────────────────────────────────────────────────────────────────────────
90      rd_is_zero_inverse — the x0 flag, with gate 91                  Quadratic, degree 2
        code  memory::x0_gates(3, 4)[0]
              = gadgets::is_zero(&[(1, rd_addr)], rd_inv, rd_is_zero, rd_mask)[0]

  positional  0 = W[5] − M[16] + M[17]·W[4]
  named       0 = rd_addr·rd_inv + rd_is_zero − rd_mask

────────────────────────────────────────────────────────────────────────────────────────────
91      rd_is_zero_at_nonzero — no x0 flag at a real register           Quadratic, degree 2
        code  x0_gates(3, 4)[1] = is_zero(..)[1]

  positional  0 = M[17]·W[5]
  named       0 = rd_addr·rd_is_zero

────────────────────────────────────────────────────────────────────────────────────────────
92      rd_is_zero_boolean    0 = W[5] − W[5]·W[5]    0 = rd_is_zero − rd_is_zero²
        Quadratic, degree 2; code  x0_gates(3, 4)[2]

────────────────────────────────────────────────────────────────────────────────────────────
93      rd_write_masked — a write into x0 writes 0                      Quadratic, degree 2
        code  x0_gates(3, 4)[3]

  positional  0 = M[20] − W[6] + W[5]·W[6]
  named       0 = rd_write_value − (1 − rd_is_zero)·rd_selected

  reads as (90–93)  §3.5's 75–78 over the REG layout. S17 builds 90 and 91 through
                    gadgets::is_zero; the frame fixtures hold their bytes unchanged.
```

**B. What the row is (94–106)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
94–105  kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2
        code  jump_branch_slt's private booleanity(KINDS[k])

  94  kind_slti_boolean    0 = W[13] − W[13]·W[13]    0 = kind_slti  − kind_slti²
  95  kind_sltiu_boolean   0 = W[14] − W[14]·W[14]    0 = kind_sltiu − kind_sltiu²
  96  kind_slt_boolean     0 = W[15] − W[15]·W[15]    0 = kind_slt   − kind_slt²
  97  kind_sltu_boolean    0 = W[16] − W[16]·W[16]    0 = kind_sltu  − kind_sltu²
  98  kind_beq_boolean     0 = W[17] − W[17]·W[17]    0 = kind_beq   − kind_beq²
  99  kind_bne_boolean     0 = W[18] − W[18]·W[18]    0 = kind_bne   − kind_bne²
  100 kind_blt_boolean     0 = W[19] − W[19]·W[19]    0 = kind_blt   − kind_blt²
  101 kind_bge_boolean     0 = W[20] − W[20]·W[20]    0 = kind_bge   − kind_bge²
  102 kind_bltu_boolean    0 = W[21] − W[21]·W[21]    0 = kind_bltu  − kind_bltu²
  103 kind_bgeu_boolean    0 = W[22] − W[22]·W[22]    0 = kind_bgeu  − kind_bgeu²
  104 kind_jalr_boolean    0 = W[23] − W[23]·W[23]    0 = kind_jalr  − kind_jalr²
  105 kind_jal_boolean     0 = W[24] − W[24]·W[24]    0 = kind_jal   − kind_jal²

────────────────────────────────────────────────────────────────────────────────────────────
106     decoded_mask_bits — the packed mask is its twelve bits          Linear, degree 1
        code  jump_branch_slt::artifact, `bits`

  positional  0 = W[13] + 2·W[14] + 4·W[15] + 8·W[16] + 16·W[17] + 32·W[18] + 64·W[19]
                  + 128·W[20] + 256·W[21] + 512·W[22] + 1024·W[23] + 2048·W[24] − W[12]
  named       0 = Σ_k 2^k·kind_k − decoded_mask,  k in extra_mask::jump_branch_slt order

  reads as  the bits are the mask the decoder lookup binds. One-hotness is not here: a live
            row with an all-zero mask, its queries and values what the rules below then
            demand, breaks no gate, and only the decoder table, whose masks are single bits,
            refuses it (crates/checker/tests/jump_branch_slt.rs,
            an_all_zero_mask_is_refused_by_the_decoder_domain_alone). Two bits that both ask
            for rs1 — any pair without jal — are refused on a live row by 107 with 85: the
            rule demands rs1_mask = 2, which booleanity refuses. On a padding row the
            decoder lookup is off: one kind bit with its packed mask breaks no gate there,
            beside taken = 1 for bne, bge and bgeu (§4.10). The honest fill writes 0.
```

**C. Which queries a row makes, and where (107–114)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
107     rs1_mask_rule — rs1 is read by every kind but jal               Quadratic, degree 2
        code  mask_rule(frame(1, FIELD_MASK),
                        [SLTI, SLTIU, SLT, SLTU, BEQ, BNE, BLT, BGE, BLTU, BGEU, JALR])

  positional  0 = M[6] − M[1]·W[13] − M[1]·W[14] − M[1]·W[15] − M[1]·W[16] − M[1]·W[17]
                  − M[1]·W[18] − M[1]·W[19] − M[1]·W[20] − M[1]·W[21] − M[1]·W[22]
                  − M[1]·W[23]
  named       0 = rs1_mask − pc_mask·(kind_slti + kind_sltiu + kind_slt + kind_sltu
                                      + kind_beq + kind_bne + kind_blt + kind_bge
                                      + kind_bltu + kind_bgeu + kind_jalr)

────────────────────────────────────────────────────────────────────────────────────────────
108     rs2_mask_rule — rs2 is read by slt, sltu and the six branches   Quadratic, degree 2
        code  mask_rule(frame(2, FIELD_MASK), [SLT, SLTU, BEQ, BNE, BLT, BGE, BLTU, BGEU])

  positional  0 = M[11] − M[1]·W[15] − M[1]·W[16] − M[1]·W[17] − M[1]·W[18] − M[1]·W[19]
                  − M[1]·W[20] − M[1]·W[21] − M[1]·W[22]
  named       0 = rs2_mask − pc_mask·(kind_slt + kind_sltu + kind_beq + kind_bne
                                      + kind_blt + kind_bge + kind_bltu + kind_bgeu)

────────────────────────────────────────────────────────────────────────────────────────────
109     rd_mask_rule — rd is written by the four slt kinds and the jumps
                                                                        Quadratic, degree 2
        code  mask_rule(frame(3, FIELD_MASK), [SLTI, SLTIU, SLT, SLTU, JALR, JAL])

  positional  0 = M[16] − M[1]·W[13] − M[1]·W[14] − M[1]·W[15] − M[1]·W[16] − M[1]·W[23]
                  − M[1]·W[24]
  named       0 = rd_mask − pc_mask·(kind_slti + kind_sltiu + kind_slt + kind_sltu
                                     + kind_jalr + kind_jal)

  reads as (107–109)  on a live row the bits are one-hot, so each sum is 0 or 1 and the mask
                      is the kind's use of the query (execution-trace.md §4); a branch has no
                      rd query. On a padding row pc_mask = 0 and every mask is 0, whatever
                      the bits hold: S14's control C8, which the row suite refuses by 109
                      alone on a padding row that claims jal to rewrite x10.

────────────────────────────────────────────────────────────────────────────────────────────
110     rs1_addr_rule — rs1's register is the decoded one               Quadratic, degree 2
        code  addr_rule(1, DECODED_RS1)

  positional  0 = M[6]·M[7] − M[6]·W[8]
  named       0 = rs1_mask·(rs1_addr − decoded_rs1)

────────────────────────────────────────────────────────────────────────────────────────────
111     rs2_addr_rule — rs2's register is the decoded one               Quadratic, degree 2
        code  addr_rule(2, DECODED_RS2)

  positional  0 = M[11]·M[12] − M[11]·W[9]
  named       0 = rs2_mask·(rs2_addr − decoded_rs2)

────────────────────────────────────────────────────────────────────────────────────────────
112     rd_addr_rule — rd's register is the decoded one                 Quadratic, degree 2
        code  addr_rule(3, DECODED_RD)

  positional  0 = M[16]·M[17] − M[16]·W[10]
  named       0 = rd_mask·(rd_addr − decoded_rd)

  reads as (110–112)  a present query's register is the table's; unlike §3.5's, no constant
                      term, since the family has no ecall row. rd = x0 needs no bit: the
                      table's rd is 0, 112 makes the write's address 0, and 90–93 write 0
                      whatever rd_selected is.

────────────────────────────────────────────────────────────────────────────────────────────
113     rs1_value_masked — an absent rs1 reads 0                        Quadratic, degree 2
        code  value_masked(1)

  positional  0 = M[9] − M[6]·M[9]
  named       0 = (1 − rs1_mask)·rs1_read_value

────────────────────────────────────────────────────────────────────────────────────────────
114     rs2_value_masked — an absent rs2 reads 0                        Quadratic, degree 2
        code  value_masked(2)

  positional  0 = M[14] − M[11]·M[14]
  named       0 = (1 − rs2_mask)·rs2_read_value

  reads as (113, 114)  the comparison runs on every live row: a jal row compares 0 with 0, a
                       jalr row rs1 with 0, and an slti row's rs2 adds nothing to cmp_rhs.
```

**D. The comparison and equality (115–119)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
115     cmp_rhs_rule — the comparison's right operand                   Quadratic, degree 2
        code  jump_branch_slt::artifact

  positional  0 = W[25] − M[14] − W[13]·W[11] − W[14]·W[11]
  named       0 = cmp_rhs − rs2_read_value − (kind_slti + kind_sltiu)·decoded_imm

  reads as  cmp_rhs is rs2 on every kind but slti and sltiu, and the immediate there (whose
            rs2 reads 0 by 114). A branch's imm, its displacement, never reaches it.

────────────────────────────────────────────────────────────────────────────────────────────
116     cmp_order — signed or unsigned ordering, one equation           Quadratic, degree 2
        code  gadgets::comparison_equation(&the_comparison(), 32), via gadgets::comparison;
              the_comparison() is private: prefix "cmp", selector pc_mask,
              signed [SLTI, SLT, BLT, BGE], lhs rs1_read_value, rhs cmp_rhs

  positional  0 = M[9] − W[25] + 2^32·W[30] − W[31]
                  − 2^32·W[13]·W[27] + 2^32·W[13]·W[29]
                  − 2^32·W[15]·W[27] + 2^32·W[15]·W[29]
                  − 2^32·W[19]·W[27] + 2^32·W[19]·W[29]
                  − 2^32·W[20]·W[27] + 2^32·W[20]·W[29]
  named, factored
    0 = rs1_read_value − cmp_rhs − 2^32·sc·(rs1_sign − cmp_rhs_sign) + 2^32·lt − cmp_gap,
    sc = kind_slti + kind_slt + kind_blt + kind_bge

  reads as  cmp_gap = D + 2^32·lt, with D = rs1 − cmp_rhs read in two's complement where
            sc = 1. With both operands and cmp_gap below 2^32 (their range pairs), each sign
            its operand's bit 31 (the generic table) and lt a bit (117), exactly one
            (lt, cmp_gap) holds: lt is the ordering sc selects, and cmp_gap is
            (rs1 − cmp_rhs) mod 2^32 whatever sc is (jump-branch-slt.md §3.2). The gate is
            ungated; on a padding row, where the range pairs are off, it leaves lt and
            cmp_gap free together (§4.10). The dump prints 2^32 as 0x…0100000000 and −2^32
            as 0x30644e72…f0000001.

────────────────────────────────────────────────────────────────────────────────────────────
117     cmp_lt_boolean        0 = W[30] − W[30]·W[30]      0 = lt − lt²
        Quadratic, degree 2; code  gadgets::comparison

────────────────────────────────────────────────────────────────────────────────────────────
118     eq_inverse — equality, with gate 119                            Quadratic, degree 2
        code  gadgets::is_zero(&[(1, rs1_read_value), (−1, cmp_rhs)], eq_inv, eq, pc_mask)[0]

  positional  0 = W[33] − M[1] + M[9]·W[34] − W[25]·W[34]
  named       0 = (rs1_read_value − cmp_rhs)·eq_inv + eq − pc_mask

────────────────────────────────────────────────────────────────────────────────────────────
119     eq_at_nonzero — no equality flag where the operands differ     Quadratic, degree 2
        code  is_zero(..)[1]

  positional  0 = M[9]·W[33] − W[25]·W[33]
  named       0 = (rs1_read_value − cmp_rhs)·eq

  reads as (118 with 119)  at rs1 ≠ cmp_rhs: eq = 0 and eq_inv = pc_mask/(rs1 − cmp_rhs).
                           at rs1 = cmp_rhs: eq = pc_mask.
                           So eq is 1 exactly on a live row whose operands are equal — every
                           jal row among them — and 0 on every padding row, with no
                           booleanity gate of its own (jump-branch-slt.md §3.1).
```

**E. What the row decides and writes (120–125)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
120     taken_rule — the branch decision                                Quadratic, degree 2
        code  jump_branch_slt::artifact

  positional  0 = W[35] − W[18] − W[20] − W[22] − W[17]·W[33] + W[18]·W[33]
                  − W[19]·W[30] − W[21]·W[30] + W[20]·W[30] + W[22]·W[30]
  named, factored
    0 = taken − (kind_bne + kind_bge + kind_bgeu)
              − (kind_beq − kind_bne)·eq
              − (kind_blt + kind_bltu − kind_bge − kind_bgeu)·lt

  reads as  one kind at a time: taken = eq on beq, 1 − eq on bne, lt on blt and bltu,
            1 − lt on bge and bgeu, and 0 on every other kind (jump-branch-slt.md §1's
            weight triples).

────────────────────────────────────────────────────────────────────────────────────────────
121     taken_boolean         0 = W[35] − W[35]·W[35]      0 = taken − taken²
122     jalr_drop_boolean     0 = W[36] − W[36]·W[36]      0 = jalr_drop − jalr_drop²
123     pc_wrap_boolean       0 = W[37] − W[37]·W[37]      0 = pc_wrap − pc_wrap²
        Quadratic, degree 2; code  jump_branch_slt's private booleanity

────────────────────────────────────────────────────────────────────────────────────────────
124     next_pc_rule — the target, or the fall-through                  Quadratic, degree 2
        code  jump_branch_slt::artifact

  positional  0 = M[5] + 2^32·W[37] − W[7] + W[35]·W[7] + W[24]·W[7] + W[23]·W[7]
                  − W[35]·M[4] − W[35]·W[11] − W[24]·M[4] − W[24]·W[11]
                  − W[23]·M[9] − W[23]·W[11] + W[23]·W[36]
  named, factored
    0 = pc_write_value + 2^32·pc_wrap
        − (1 − taken − kind_jal − kind_jalr)·decoded_next_pc
        − (taken + kind_jal)·(pc_read_value + decoded_imm)
        − kind_jalr·(rs1_read_value + decoded_imm − jalr_drop)

  reads as  at most one of taken, kind_jal and kind_jalr is 1 on a live row, so one arm:
              fall-through  next_pc = decoded_next_pc − 2^32·pc_wrap
              taken, jal    next_pc = pc + imm − 2^32·pc_wrap
              jalr          next_pc = rs1 + imm − jalr_drop − 2^32·pc_wrap
            With next_pc below 2^32 and even (next_pc_hi_range, next_pc_lo_range,
            next_pc_even), pc_wrap is the sum's carry — 0 on the fall-through, which is below
            2^24 — and, on a jalr row, jalr_drop its bit 0 (jump-branch-slt.md §4.3). The
            wrap and the default arm are ungated: a padding row holds only
            next_pc + 2^32·pc_wrap = decoded_next_pc (the honest fill writes 0 in all
            three). No row of the family can write HALT_PC, which is odd.

────────────────────────────────────────────────────────────────────────────────────────────
125     rd_value_rule — what the row computes for rd                    Quadratic, degree 2
        code  jump_branch_slt::artifact

  positional  0 = W[6] − W[24]·W[7] − W[23]·W[7] − W[13]·W[30] − W[14]·W[30] − W[15]·W[30]
                  − W[16]·W[30]
  named       0 = rd_selected − (kind_jal + kind_jalr)·decoded_next_pc
                  − (kind_slti + kind_sltiu + kind_slt + kind_sltu)·lt

  reads as  the link is the table's fall-through itself, a value with no sum to wrap; the four
            slt kinds write the one lt the branches read; a branch computes 0 and has no rd
            query to write it to (109). rd_selected is range-checked by rd_hi_range and
            rd_lo_range.
```

Of the 42 gates, 3 are degree 1: the two write-backs and `decoded_mask_bits`. All 42 have
constant 0, so each is 0 on the all-zero row, and the assembly records `zero_row_valid = true`
(the dump's padding contract).

### 4.6 The 22 lookups

`CircuitArtifact::lookups`, in order. The frame's 8 come from the private
`memory::gap_lookups`; 8–15 from `gadgets::comparison`; the rest from
`jump_branch_slt::artifact` (its private `range16`, `low_half`, `low_half_halved` and the inline
`decode_row`). Every lookup from 8 on is selected by `pc_mask`.

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `gap_hi_pc` | `TIMESTAMP` (0) | `M[1]` | `W[0]` | `pc_gap_hi` | `< 2^19` |
| 1 | `gap_lo_pc` | `TIMESTAMP` | `M[1]` | `4·M[0] − M[3] − 2^19·W[0] − 1` | `4·cycle − pc_read_ts − 2^19·pc_gap_hi − 1` | `< 2^19` |
| 2 | `gap_hi_rs1` | `TIMESTAMP` | `M[6]` | `W[1]` | `rs1_gap_hi` | `< 2^19` |
| 3 | `gap_lo_rs1` | `TIMESTAMP` | `M[6]` | `4·M[0] − M[8] − 2^19·W[1]` | `4·cycle − rs1_read_ts − 2^19·rs1_gap_hi` | `< 2^19` |
| 4 | `gap_hi_rs2` | `TIMESTAMP` | `M[11]` | `W[2]` | `rs2_gap_hi` | `< 2^19` |
| 5 | `gap_lo_rs2` | `TIMESTAMP` | `M[11]` | `4·M[0] − M[13] − 2^19·W[2] + 1` | `4·cycle − rs2_read_ts − 2^19·rs2_gap_hi + 1` | `< 2^19` |
| 6 | `gap_hi_rd` | `TIMESTAMP` | `M[16]` | `W[3]` | `rd_gap_hi` | `< 2^19` |
| 7 | `gap_lo_rd` | `TIMESTAMP` | `M[16]` | `4·M[0] − M[18] − 2^19·W[3] + 2` | `4·cycle − rd_read_ts − 2^19·rd_gap_hi + 2` | `< 2^19` |
| 8 | `cmp_lhs_hi_range` | `RANGE16` (1) | `M[1]` | `W[26]` | `rs1_hi` | `< 2^16` |
| 9 | `cmp_lhs_lo_range` | `RANGE16` | `M[1]` | `M[9] − 2^16·W[26]` | `rs1_read_value − 2^16·rs1_hi` | `< 2^16` |
| 10 | `cmp_rhs_hi_range` | `RANGE16` | `M[1]` | `W[28]` | `cmp_rhs_hi` | `< 2^16` |
| 11 | `cmp_rhs_lo_range` | `RANGE16` | `M[1]` | `W[25] − 2^16·W[28]` | `cmp_rhs − 2^16·cmp_rhs_hi` | `< 2^16` |
| 12 | `cmp_gap_hi_range` | `RANGE16` | `M[1]` | `W[32]` | `cmp_gap_hi` | `< 2^16` |
| 13 | `cmp_gap_lo_range` | `RANGE16` | `M[1]` | `W[31] − 2^16·W[32]` | `cmp_gap − 2^16·cmp_gap_hi` | `< 2^16` |
| 14 | `cmp_lhs_get_sign` | `GENERIC` (2) | `M[1]` | `(W[26] + 256, W[27], 0)` | `(rs1_hi + SIGN_BASE, rs1_sign, 0)` | the gated tuple `(rs1_hi + 257, rs1_sign, 0)` is a row of `S[7..10]` |
| 15 | `cmp_rhs_get_sign` | `GENERIC` | `M[1]` | `(W[28] + 256, W[29], 0)` | `(cmp_rhs_hi + SIGN_BASE, cmp_rhs_sign, 0)` | the gated tuple `(cmp_rhs_hi + 257, cmp_rhs_sign, 0)` is a row of `S[7..10]` |
| 16 | `rd_hi_range` | `RANGE16` | `M[1]` | `W[39]` | `rd_hi` | `< 2^16` |
| 17 | `rd_lo_range` | `RANGE16` | `M[1]` | `W[6] − 2^16·W[39]` | `rd_selected − 2^16·rd_hi` | `< 2^16` |
| 18 | `next_pc_hi_range` | `RANGE16` | `M[1]` | `W[38]` | `next_pc_hi` | `< 2^16` |
| 19 | `next_pc_lo_range` | `RANGE16` | `M[1]` | `M[5] − 2^16·W[38]` | `pc_write_value − 2^16·next_pc_hi` | `< 2^16` |
| 20 | `next_pc_even` | `RANGE16` | `M[1]` | `2⁻¹·M[5] − 2^15·W[38]` | `(pc_write_value − 2^16·next_pc_hi)/2` | `< 2^16` |
| 21 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[7], W[8], W[9], W[10], W[11], W[12])` | `(pc_read_value, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_imm, decoded_mask)` | a row of `S[0..7]` |

Read in pairs, as in §3.6: each `gap_hi`/`gap_lo` pair puts a read strictly before its own
write, and each `_hi_range`/`_lo_range` pair bounds `rs1_read_value`, `cmp_rhs`, `cmp_gap`,
`rd_selected` and `pc_write_value` below `2^32`. With `next_pc_lo_range`, `next_pc_even` holds
exactly when `next_pc`'s low halfword is even: an odd one halves to `(lo + p)/2`, far above
`2^16`. The two `_hi_range` obligations keep each sign lookup's key `hi + 257` in
`[257, 2^16 + 256]`, `U16GetSign`'s keys, never the `ZeroEntry`, an AND key or a `ShiftPowers`
key (`lookup.md` §4's precondition), so the only row that key can meet is
`(hi + 257, hi >> 15, 0)` and each sign is its operand's bit 31.

The channels, `jump_branch_slt::channels()`, in output order:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[40]` | 8 | 16 |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[41]` | 11 | 16 |
| 6, 7 | `GENERIC` | 2 | `S[7..10]` | `W[42]` | 2 | 4 |
| 8, 9 | `DECODER` | 3 | `S[0..7]` | `W[43]` | 1 | 2 |

`artifact` asserts the four obligation counts. The generic table's commitments are the key's
one triple, covered by its SRS digest, not identity's (§4.3).

### 4.7 Inner layers `L2`–`L5`: the row-wise reduction

The conventions are §3.7's.

**`L2`, gate list 1, 42 columns, relations 126–167.**

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 126 | `read_2_0` | `read_pc · read_rs1` |
| 1 | 127 | `read_2_1` | `read_rs2 · read_rd` |
| 2 | 128 | `write_2_0` | `write_pc · write_rs1` |
| 3 | 129 | `write_2_1` | `write_rs2 · write_rd` |
| 4, 5 | 130, 131 | `timestamp_2_0` | `timestamp_table + gap_hi_pc` |
| 6, 7 | 132, 133 | `timestamp_2_1` | `gap_lo_pc + gap_hi_rs1` |
| 8, 9 | 134, 135 | `timestamp_2_2` | `gap_lo_rs1 + gap_hi_rs2` |
| 10, 11 | 136, 137 | `timestamp_2_3` | `gap_lo_rs2 + gap_hi_rd` |
| 12, 13 | 138, 139 | `timestamp_2_4` | `gap_lo_rd + timestamp_pad_0` |
| 14, 15 | 140, 141 | `timestamp_2_5` | `timestamp_pad_1 + timestamp_pad_2` |
| 16, 17 | 142, 143 | `timestamp_2_6` | `timestamp_pad_3 + timestamp_pad_4` |
| 18, 19 | 144, 145 | `timestamp_2_7` | `timestamp_pad_5 + timestamp_pad_6` |
| 20, 21 | 146, 147 | `range16_2_0` | `range16_table + cmp_lhs_hi_range` |
| 22, 23 | 148, 149 | `range16_2_1` | `cmp_lhs_lo_range + cmp_rhs_hi_range` |
| 24, 25 | 150, 151 | `range16_2_2` | `cmp_rhs_lo_range + cmp_gap_hi_range` |
| 26, 27 | 152, 153 | `range16_2_3` | `cmp_gap_lo_range + rd_hi_range` |
| 28, 29 | 154, 155 | `range16_2_4` | `rd_lo_range + next_pc_hi_range` |
| 30, 31 | 156, 157 | `range16_2_5` | `next_pc_lo_range + next_pc_even` |
| 32, 33 | 158, 159 | `range16_2_6` | `range16_pad_0 + range16_pad_1` |
| 34, 35 | 160, 161 | `range16_2_7` | `range16_pad_2 + range16_pad_3` |
| 36, 37 | 162, 163 | `generic_2_0` | `generic_table + cmp_lhs_get_sign` |
| 38, 39 | 164, 165 | `generic_2_1` | `cmp_rhs_get_sign + generic_pad_0` |
| 40, 41 | 166, 167 | `decoder_2_0` | `decoder_table + decode_row` |

Positionally, `generic_2_0` is `L{2}[36] = L{1}[72]·L{1}[75] + L{1}[74]·L{1}[73]` and
`L{2}[37] = L{1}[73]·L{1}[75]`: `−mult_generic/(T + g) + 1/(E_cmp_lhs_get_sign + g)`, each
channel's first node being its table's fraction beside its first lookup's, as in §3.7.

**`L3`, gate list 2, 22 columns, relations 168–189.**

| `L3` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 168 | `read_3_0` | `read_2_0 · read_2_1` |
| 1 | 169 | `write_3_0` | `write_2_0 · write_2_1` |
| 2, 3 | 170, 171 | `timestamp_3_0` | `timestamp_2_0 + timestamp_2_1` |
| 4, 5 | 172, 173 | `timestamp_3_1` | `timestamp_2_2 + timestamp_2_3` |
| 6, 7 | 174, 175 | `timestamp_3_2` | `timestamp_2_4 + timestamp_2_5` |
| 8, 9 | 176, 177 | `timestamp_3_3` | `timestamp_2_6 + timestamp_2_7` |
| 10, 11 | 178, 179 | `range16_3_0` | `range16_2_0 + range16_2_1` |
| 12, 13 | 180, 181 | `range16_3_1` | `range16_2_2 + range16_2_3` |
| 14, 15 | 182, 183 | `range16_3_2` | `range16_2_4 + range16_2_5` |
| 16, 17 | 184, 185 | `range16_3_3` | `range16_2_6 + range16_2_7` |
| 18, 19 | 186, 187 | `generic_3_0` | `generic_2_0 + generic_2_1` |
| 20, 21 | 188, 189 | `decoder_3_0` | copy of `decoder_2_0` |

**`L4`, gate list 3, 14 columns, relations 190–203.**

| `L4` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 190 | `read_4_0` | copy of `read_3_0` |
| 1 | 191 | `write_4_0` | copy of `write_3_0` |
| 2, 3 | 192, 193 | `timestamp_4_0` | `timestamp_3_0 + timestamp_3_1` |
| 4, 5 | 194, 195 | `timestamp_4_1` | `timestamp_3_2 + timestamp_3_3` |
| 6, 7 | 196, 197 | `range16_4_0` | `range16_3_0 + range16_3_1` |
| 8, 9 | 198, 199 | `range16_4_1` | `range16_3_2 + range16_3_3` |
| 10, 11 | 200, 201 | `generic_4_0` | copy of `generic_3_0` |
| 12, 13 | 202, 203 | `decoder_4_0` | copy of `decoder_3_0` |

**`L5`, gate list 4, 10 columns, relations 204–213** — the row-wise top: one value per row per
tree.

| `L5` | relations | node | formula | value at row `y` |
| --- | --- | --- | --- | --- |
| 0 | 204 | `read_5_0` | copy of `read_4_0` | the product of row `y`'s 4 read leaves |
| 1 | 205 | `write_5_0` | copy of `write_4_0` | the product of row `y`'s 4 write leaves |
| 2, 3 | 206, 207 | `timestamp_5_0` | `timestamp_4_0 + timestamp_4_1` | the sum of row `y`'s 16 timestamp fractions |
| 4, 5 | 208, 209 | `range16_5_0` | `range16_4_0 + range16_4_1` | the sum of row `y`'s 16 range16 fractions |
| 6, 7 | 210, 211 | `generic_5_0` | copy of `generic_4_0` | the sum of row `y`'s 4 generic fractions |
| 8, 9 | 212, 213 | `decoder_5_0` | copy of `decoder_4_0` | the sum of row `y`'s 2 decoder fractions |

### 4.8 The halving layers and the outputs

Gate list `k`, for `5 ≤ k ≤ n + 4`, halves layer `k` into layer `k + 1`, which has
`n + 4 − k` variables. Its ten gates, relation `r = 214 + 10(k − 5)`, with §3.8's formulas:

| `L{k+1}` | relation | node | shape |
| --- | --- | --- | --- |
| 0 | `r` | `read_{k+1}_0` | `TreeProduct { L{k}[0] }` |
| 1 | `r + 1` | `write_{k+1}_0` | `TreeProduct { L{k}[1] }` |
| 2 | `r + 2` | `timestamp_{k+1}_0_num` | `TreeCross { L{k}[2], L{k}[3] }` |
| 3 | `r + 3` | `timestamp_{k+1}_0_den` | `TreeProduct { L{k}[3] }` |
| 4 | `r + 4` | `range16_{k+1}_0_num` | `TreeCross { L{k}[4], L{k}[5] }` |
| 5 | `r + 5` | `range16_{k+1}_0_den` | `TreeProduct { L{k}[5] }` |
| 6 | `r + 6` | `generic_{k+1}_0_num` | `TreeCross { L{k}[6], L{k}[7] }` |
| 7 | `r + 7` | `generic_{k+1}_0_den` | `TreeProduct { L{k}[7] }` |
| 8 | `r + 8` | `decoder_{k+1}_0_num` | `TreeCross { L{k}[8], L{k}[9] }` |
| 9 | `r + 9` | `decoder_{k+1}_0_den` | `TreeProduct { L{k}[9] }` |

In the last list, `k = n + 4`, the ten nodes are named `read_root`, `write_root`,
`timestamp_num_root`, `timestamp_den_root`, `range16_num_root`, `range16_den_root`,
`generic_num_root`, `generic_den_root`, `decoder_num_root` and `decoder_den_root`. At `n = 20`
the halving lists are 5 to 24, `L6` has 19 variables and `L25` none. At `n = 22` they are 5 to
26, and the top is `L27`.

**The outputs**, in output-map order. All ten are absorbed as one `GKR_OUTPUTS` message before
any challenge of the backward pass, and travel in `ShardProof::outputs`, as §3.8's eight do.

| # | address, `n = 20` | node | value | what `verify_shard` does with it |
| --- | --- | --- | --- | --- |
| 0 | `L{25}[0]` | `read_root` | the product of every read leaf of the shard | step 10: must equal `PublicInputs::memory_roots[p][0]`, `p` being the position of `(1, shard_index)` in `verifier_core::statement_shards`, after `INIT_TEARDOWN`'s shard, every `ZERO_WINDOWS` shard and every `ADD_SUB_LUI_AUIPC` shard (`shard-proof.md` §1.2); 2 in S17's statement; a factor of `reconciles` |
| 1 | `L{25}[1]` | `write_root` | the product of every write leaf | step 10: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |
| 2 | `L{25}[2]` | `timestamp_num_root` | as §3.8's output 2 | step 9: must be 0; otherwise `Lookup { channel: 0 }` |
| 3 | `L{25}[3]` | `timestamp_den_root` | as §3.8's output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 0 }` |
| 4 | `L{25}[4]` | `range16_num_root` | as output 2, for `RANGE16` | step 9: must be 0; otherwise `Lookup { channel: 1 }` |
| 5 | `L{25}[5]` | `range16_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 1 }` |
| 6 | `L{25}[6]` | `generic_num_root` | as output 2, for `GENERIC` | step 9: must be 0; otherwise `Lookup { channel: 2 }` |
| 7 | `L{25}[7]` | `generic_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 2 }` |
| 8 | `L{25}[8]` | `decoder_num_root` | as output 2, for `DECODER` | step 9: must be 0; otherwise `Lookup { channel: 3 }` |
| 9 | `L{25}[9]` | `decoder_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 3 }` |

### 4.9 Witness rows

The table shows eight of the 46 live `honest_rows` in `crates/checker/tests/jump_branch_slt.rs`,
and the padding row. The other 38 are `slt` at mixed signs, at equal operands and with
`rd = rs1`; `sltu` at mixed signs; `slti` and `sltiu` against −1 and 2047; the other three
comparisons into `x0`; each branch taken and not taken, a backward `bne` that falls through, and a `beq` taken to its own
fall-through; `jal` backward, into `x0` and `2^19` ahead; `jalr` into `x0`; and `c.jal` and
`c.beqz` at two bytes. §4.10 probes all 47. Each row is built from Rust's own `u32` and `i32`
arithmetic, and `every_row_kind_satisfies_every_gate_and_every_bound` holds it to every gate,
every range obligation and both table channels in CI: the suite's `violated_tables` checks a
generic tuple against `program::lookup_tables::generic_entries` and a decoder tuple against the
row's own `S[0..7]`.

A row is checked alone, as §3.9's are: each register query reads a write made 8 timestamps
before its own and the pc query the previous cycle's, so every `<q>_gap_hi` is 0; the
multiplicities are 0; `S[0..7]` hold the row's own table entry and `S[7..10]` are 0, and the
table below omits them. Every live row shown has cycle 9, pc `0x10100` and a 4-byte instruction,
and `P` is 0 in every cell.

`A` `blt x5, x6, +8` with `x5 = 0x80000000`, `x6 = 1`: taken. `B` `bltu` on the same operands:
not taken. `C` `bne x5, x0, −16` with `x5 = 3`: taken backward. `D` `slti x5, x6, −1` with
`x6 = 5`: 0. `E` `slt x0, x0, x6` with `x6 = 1`: computes 1, writes 0. `F` `jal x1, +0xa4`,
`x1` holding 9. `G` `jalr x7, −2(x7)` with `x7 = 0x101ab`. `H` `jalr x1, −4(x5)` with
`x5 = 0x10000`. `P` padding.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[2]` `pc_addr` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `M[3]` `pc_read_ts` | 32 | 32 | 32 | 32 | 32 | 32 | 32 | 32 | 0 |
| `M[4]` `pc_read_value` | `0x10100` | `0x10100` | `0x10100` | `0x10100` | `0x10100` | `0x10100` | `0x10100` | `0x10100` | 0 |
| `M[5]` `pc_write_value` | `0x10108` | `0x10104` | `0x100f0` | `0x10104` | `0x10104` | `0x101a4` | `0x101a8` | `0xfffc` | 0 |
| `M[6]` `rs1_mask` | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 0 |
| `M[7]` `rs1_addr` | 5 | 5 | 5 | 6 | 0 | 0 | 7 | 5 | 0 |
| `M[8]` `rs1_read_ts` | 29 | 29 | 29 | 29 | 29 | 0 | 29 | 29 | 0 |
| `M[9]`, `M[10]` `rs1_read_value`, `rs1_write_value` | `0x80000000` | `0x80000000` | 3 | 5 | 0 | 0 | `0x101ab` | `0x10000` | 0 |
| `M[11]` `rs2_mask` | 1 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 |
| `M[12]` `rs2_addr` | 6 | 6 | 0 | 0 | 6 | 0 | 0 | 0 | 0 |
| `M[13]` `rs2_read_ts` | 30 | 30 | 30 | 0 | 30 | 0 | 0 | 0 | 0 |
| `M[14]`, `M[15]` `rs2_read_value`, `rs2_write_value` | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `M[16]` `rd_mask` | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[17]` `rd_addr` | 0 | 0 | 0 | 5 | 0 | 1 | 7 | 1 | 0 |
| `M[18]` `rd_read_ts` | 0 | 0 | 0 | 31 | 31 | 31 | 31 | 31 | 0 |
| `M[19]` `rd_read_value` | 0 | 0 | 0 | 0 | 0 | 9 | `0x101ab` | 0 | 0 |
| `M[20]` `rd_write_value` | 0 | 0 | 0 | 0 | 0 | `0x10104` | `0x10104` | `0x10104` | 0 |
| `W[0..4]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[4]` `rd_inv` | 0 | 0 | 0 | `5⁻¹` | 0 | 1 | `7⁻¹` | 1 | 0 |
| `W[5]` `rd_is_zero` | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `W[6]` `rd_selected` | 0 | 0 | 0 | 0 | 1 | `0x10104` | `0x10104` | `0x10104` | 0 |
| `W[7]` `decoded_next_pc` | `0x10104` | `0x10104` | `0x10104` | `0x10104` | `0x10104` | `0x10104` | `0x10104` | `0x10104` | 0 |
| `W[8]` `decoded_rs1` | 5 | 5 | 5 | 6 | 0 | 0 | 7 | 5 | 0 |
| `W[9]` `decoded_rs2` | 6 | 6 | 0 | 0 | 6 | 0 | 0 | 0 | 0 |
| `W[10]` `decoded_rd` | 0 | 0 | 0 | 5 | 0 | 1 | 7 | 1 | 0 |
| `W[11]` `decoded_imm` | 8 | 8 | `0xfffffff0` | `0xffffffff` | 0 | `0xa4` | `0xfffffffe` | `0xfffffffc` | 0 |
| `W[12]` `decoded_mask` | `0x40` | `0x100` | `0x20` | 1 | 4 | `0x800` | `0x400` | `0x400` | 0 |
| `W[13..25]` the kind bit set | `blt` | `bltu` | `bne` | `slti` | `slt` | `jal` | `jalr` | `jalr` | none |
| `W[25]` `cmp_rhs` | 1 | 1 | 0 | `0xffffffff` | 1 | 0 | 0 | 0 | 0 |
| `W[26]` `rs1_hi` | `0x8000` | `0x8000` | 0 | 0 | 0 | 0 | 1 | 1 | 0 |
| `W[27]` `rs1_sign` | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[28]` `cmp_rhs_hi` | 0 | 0 | 0 | `0xffff` | 0 | 0 | 0 | 0 | 0 |
| `W[29]` `cmp_rhs_sign` | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `W[30]` `lt` | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `W[31]` `cmp_gap` | `0x7fffffff` | `0x7fffffff` | 3 | 6 | `0xffffffff` | 0 | `0x101ab` | `0x10000` | 0 |
| `W[32]` `cmp_gap_hi` | `0x7fff` | `0x7fff` | 0 | 0 | `0xffff` | 0 | 1 | 1 | 0 |
| `W[33]` `eq` | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `W[34]` `eq_inv` | `0x7fffffff⁻¹` | `0x7fffffff⁻¹` | `3⁻¹` | `(5 − 0xffffffff)⁻¹` | −1 | 0 | `0x101ab⁻¹` | `0x10000⁻¹` | 0 |
| `W[35]` `taken` | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[36]` `jalr_drop` | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `W[37]` `pc_wrap` | 0 | 0 | 1 | 0 | 0 | 0 | 1 | 1 | 0 |
| `W[38]` `next_pc_hi` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0 |
| `W[39]` `rd_hi` | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 0 |

`A` and `B` differ only in `sc`: the same operands give `cmp_gap = 0x7fffffff` in both, and
`lt` is 1 read signed, 0 read unsigned. `C`'s target is `pc + 0xfffffff0 − 2^32`, so
`pc_wrap = 1`; its `rs2` is `x0`, a present query at address 0. `D`'s right operand is the
immediate, whose sign bit is 1, so `5 < −1` is false; the retired table's SLTI defect, which read
that sign as 0, answered 1 (`jump-branch-slt.md` §5). `E` computes 1 and writes 0: `rd_selected`
keeps the result and `rd_write_masked` masks it, and `rd_inv` is 0 at address 0. `F`'s operands
both read 0, so `eq = 1` on a jump, where nothing reads it. `G`'s sum `0x101ab + 0xfffffffe` is
`2^32 + 0x101a9`: it wraps and has bit 0 set, so `next_pc = 0x101a8`, and its `rd` query reads
the same old `0x101ab` its `rs1` query read. `H`'s target `0xfffc` is below `2^16`, so
`next_pc_hi = 0`.

### 4.10 What fixes each cell

All 47 `honest_rows`, probed as in §3.10: 5 added to one `M` or `W` cell at a time, and each
boolean column flipped between 0 and 1, evaluated row-locally through `violated_relations`,
`violated_lookups` and the suite's `violated_tables`. A cell is listed below when, on some row,
no gate and no range obligation refuses the change. The table then says what does: a **table
channel**, when `violated_tables` alone refuses it; otherwise the **memory argument**, when the
cell is in a leaf whose mask is 1; or nothing. The multiplicities `W[40..44]` are not a row's
property, and the `S` columns are fixed by the opening, so neither is probed. Two cells, marked
(flip), are listed from the flips alone.

A read timestamp is a case apart, as in §3.10: `+5` stays inside a register's synthetic gap of 7,
so `M[8]`, `M[13]` and `M[18]` show up on every row, and the pc's gap is 3, so `M[3]` shows up
on padding alone.

| cell | fixed, on the rows that use it, by | rows where less fixes it, or nothing |
| --- | --- | --- |
| `M[0]` `cycle` | the memory argument (every write leaf's timestamp), with the gap obligations bounding it below | padding: nothing |
| `M[2]` `pc_addr` | the memory argument alone, as in §3.10 | padding: nothing |
| `M[3]`, `M[8]`, `M[13]`, `M[18]` read timestamps | the memory argument alone; the gap obligations only hold each below its own write | rows without that query, padding included: nothing |
| `M[4]` `pc_read_value` | the memory argument and the decoder table; on a taken branch or a `jal` row, also `next_pc_rule` | padding: nothing |
| `M[7]` `rs1_addr` | `rs1_addr_rule` | `jal` and padding rows: nothing |
| `M[12]` `rs2_addr` | `rs2_addr_rule` | `slti`, `sltiu`, `jal`, `jalr` and padding rows: nothing |
| `M[17]` `rd_addr` | `rd_addr_rule`, and the x0 gates | branch and padding rows: nothing |
| `M[19]` `rd_read_value` | the memory argument alone: no gate of this family reads it | branch and padding rows: nothing |
| `W[0]` `pc_gap_hi` | its gap obligations | padding: nothing |
| `W[1]`, `W[2]`, `W[3]` gap chunks | their gap obligations | rows without that query: nothing |
| `W[4]` `rd_inv` | `rd_is_zero_inverse`, where `rd_addr ≠ 0` | rows writing `x0`, branch rows, padding: nothing |
| `W[7]` `decoded_next_pc` | the decoder table, with `next_pc_rule` on a fall-through and `rd_value_rule` on a jump | taken branch rows: the decoder table alone, since `next_pc_rule` cancels it there and `rd_value_rule` does not read it; padding: `next_pc_rule` alone, which only ties it to `pc_write_value` and `pc_wrap` |
| `W[8]` `decoded_rs1` | `rs1_addr_rule` and the decoder table | `jal` rows: the decoder table alone; padding: nothing |
| `W[9]` `decoded_rs2` | `rs2_addr_rule` and the decoder table | `slti`, `sltiu`, `jal` and `jalr` rows: the decoder table alone; padding: nothing |
| `W[10]` `decoded_rd` | `rd_addr_rule` and the decoder table | branch rows: the decoder table alone; padding: nothing |
| `W[11]` `decoded_imm` | the decoder table, with `cmp_rhs_rule` on `slti` and `sltiu` rows and `next_pc_rule` on taken branch, `jal` and `jalr` rows | `slt`, `sltu` and not-taken branch rows: the decoder table alone; padding: nothing |
| `W[26]` `rs1_hi`, `W[28]` `cmp_rhs_hi`, `W[32]` `cmp_gap_hi`, `W[38]` `next_pc_hi`, `W[39]` `rd_hi` | their range obligations | padding: nothing |
| `W[27]` `rs1_sign`, `W[29]` `cmp_rhs_sign` (flip) | `cmp_order` on `slti`, `slt`, `blt` and `bge` rows, and the generic table | `sltiu`, `sltu`, `beq`, `bne`, `bltu`, `bgeu`, `jal` and `jalr` rows: the generic table alone, `cmp_order`'s sign terms being multiplied by `sc = 0`; padding: nothing |
| `W[34]` `eq_inv` | `eq_inverse`, where `rs1_read_value ≠ cmp_rhs` | rows whose operands are equal — the equal-operand comparisons and branches, and every `jal` row — and padding: nothing |
| `W[36]` `jalr_drop` (flip) | `next_pc_rule` on a `jalr` row | every other row, padding included: `jalr_drop_boolean` alone, which leaves it 0 or 1 |

Every other cell is refused row-locally on every row, padding included. Unlike §3.10's fence
row, no row lets `pc_mask` flip: `eq_inverse`, whose `enable` it is, refuses the flip on every
row (a `jal` row at `pc_mask = 0` breaks it and `rd_mask_rule`; the padding row at `pc_mask = 1`
breaks it and `gap_lo_pc`).

On a padding row every mask is 0 and every lookup is switched off, so no cell there reaches a
memory event or a table. With every kind bit 0, the gates hold `rd_selected`, `rd_write_value`,
`taken`, `cmp_rhs` and `eq` to 0 there, and `pc_write_value + 2^32·pc_wrap` to
`decoded_next_pc`. Beyond the cells above they leave free the pair `lt`, `cmp_gap` together
(`lt = 1` with `cmp_gap = 2^32` breaks nothing, `cmp_gap`'s range pair being off), and one kind
bit set with its packed mask, beside `taken = 1` for `bne`, `bge` and `bgeu`, whose constant
weight is 1: the mask rules' `pc_mask` factor, not the bits, keeps such a row from every memory
event. The honest fill writes 0 everywhere.

---

## 5. `SHIFT_BITWISE` — family 2

### 5.1 Header

`family_circuit(2, n)` is `shift_bitwise::artifact(n)` with `shift_bitwise::channels()`, built
by `memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` through the private
`family_spec` (`QUERIES`, the `SLOT_*` constants and the per-kind constants `SLLI` … `AND` are
private to `shift_bitwise.rs`). It uses neither S17 gadget: its comparison-free arithmetic needs
`is_zero` only for the frame's x0 rule, which `memory` builds. Normative spec:
`shift-bitwise.md`. Fill: `prover::family_fill(2)`, the private `fill::shift_bitwise`.

92 committed columns (21 `M`, 61 `W`, 10 `S`) and two virtual tables. Gate list 0 writes 124
leaves and holds 48 enforcing gates. 39 lookups on four channels, 10 outputs. At `n = 20`, the
height S18 proves, there are 26 gate lists, the top is `L26`, and the circuit has 458 inner
columns and 506 relations; a shard proof of it is 68,564 bytes (`crates/prover/tests/alu.rs`).
**It is one gate list deeper than §3's and §4's**, and the reason is §5.6's: its `range16` tree
carries 24 obligations beside its table fraction, 25 leaves padding to 32, where add/sub's and
jump/branch/slt's fit in 16. `artifact` panics unless the frame is `QUERIES`, the channels carry
exactly 8, 24, 6 and 1 obligations, `lookup::check_copowers` finds a direct range pair under the
same selector for each of the six columns it bounds by scaling — `residue`, `amount` and the
four `byte_a` keys — and every gate is zero on the all-zero row. It also panics on every refusal
of the assembly, among them `n < 19` (the 19-bit timestamp table needs 19 variables) and
`n > 30` (`MAX_TRACE_VARS`); `family_circuit` returns `None` for both rather than calling it.

### 5.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::shift_bitwise`, bit `k` being
`W[13 + k]`. The decoded table's `imm` is the value the instruction uses: the **raw five-bit
shamt** on `slli`, `srli` and `srai`, the sign-extended twelve-bit immediate on `andi`, `ori`
and `xori`, and 0 on every R-type row (`shift-bitwise.md` §1). A form's absent register is `x0`.
`src2 = rs2_read_value + decoded_imm` is the second operand of all twelve, one addend always
being 0. Every kind reads `rs1` and writes `rd`; the six R-type kinds read `rs2`.

| row kind | bit (`decoded_mask`) | `decoded_imm` | queries present | `f_shift`, `f_bitwise` | `src2` | `rd_selected` | `next_pc` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `slli` | 0 (1) | the shamt, `[0, 32)` | pc rs1 rd | 1, 0 | the shamt | `rs1 << (src2 mod 32)` | the fall-through |
| `xori` | 1 (2) | the immediate, sign-extended | pc rs1 rd | 0, 1 | the immediate | `rs1 ^ src2` | the fall-through |
| `srli` | 2 (4) | the shamt | pc rs1 rd | 1, 0 | the shamt | `rs1 >> (src2 mod 32)`, logical | the fall-through |
| `srai` | 3 (8) | the shamt | pc rs1 rd | 1, 0 | the shamt | `rs1 >> (src2 mod 32)`, arithmetic | the fall-through |
| `ori` | 4 (16) | the immediate | pc rs1 rd | 0, 1 | the immediate | `rs1 \| src2` | the fall-through |
| `andi` | 5 (32) | the immediate | pc rs1 rd | 0, 1 | the immediate | `rs1 & src2` | the fall-through |
| `sll` | 6 (64) | 0 | pc rs1 rs2 rd | 1, 0 | `rs2` | `rs1 << (src2 mod 32)` | the fall-through |
| `xor` | 7 (128) | 0 | pc rs1 rs2 rd | 0, 1 | `rs2` | `rs1 ^ src2` | the fall-through |
| `srl` | 8 (256) | 0 | pc rs1 rs2 rd | 1, 0 | `rs2` | `rs1 >> (src2 mod 32)`, logical | the fall-through |
| `sra` | 9 (512) | 0 | pc rs1 rs2 rd | 1, 0 | `rs2` | `rs1 >> (src2 mod 32)`, arithmetic | the fall-through |
| `or` | 10 (1024) | 0 | pc rs1 rs2 rd | 0, 1 | `rs2` | `rs1 \| src2` | the fall-through |
| `and` | 11 (2048) | 0 | pc rs1 rs2 rd | 0, 1 | `rs2` | `rs1 & src2` | the fall-through |
| padding | none; all 0 | 0 | none | free booleans | 0 | 0 | 0 |

Every kind is provable at S18. **No kind computes a pc**: `next_pc` is the decoded fall-through
on every row, so this family writes no target, needs no wrap bit and cannot reach `HALT_PC`,
which is odd and which no fall-through is (`shift-bitwise.md` §4.1, §6). `se` is 1 exactly on an
`srai` or `sra` row whose operand's bit 31 is set; `amount` is `src2 mod 32` on every row, and on
a bitwise row it keeps that value with `pow` and `copow` at 0. `rd = x0` is not a kind: the
table's `rd` is 0, the frame's x0 rule writes 0, and `rd_selected` keeps the computed value.
Seven of the twelve have compressed forms, so both fall-through widths occur. A live row at a pc
holding no instruction of the family meets the table's `MINUS_ONE` row, which its decoder tuple
cannot equal.

### 5.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §5.4 and §5.6.

**Memory-argument columns, `M[0..21]`** — §2's REG layout (`w = 4`), the same 21 columns
`JUMP_BRANCH_SLT` carries and the same bare frame fixture (`memory_frame_reg.bin`), filled by
`trace::build_memory_columns`; committed in `PublicInputs::memory_commitments`, absorbed at G8
before the memory challenges.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the cycle `c` | leaves `write_*` (all 4); obligations `gap_lo_*` (all 4) |
| `M[1]` | `pc_mask` | `frame(0, FIELD_MASK)` | Row is live | 1 | leaves `read_pc`, `write_pc`; `pc_mask_boolean`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`; selector of `gap_hi_pc`, `gap_lo_pc`, the fourteen `m_pc` `RANGE16` obligations, `rs1_get_sign` and `decode_row` |
| `M[2]` | `pc_addr` | `frame(0, FIELD_ADDR)` | PC address | 0 | leaves `read_pc`, `write_pc` |
| `M[3]` | `pc_read_ts` | `frame(0, FIELD_READ_TS)` | Previous pc write | `4(c − 1)` | leaf `read_pc`; `gap_lo_pc` |
| `M[4]` | `pc_read_value` | `frame(0, FIELD_READ_VALUE)` | Current pc | the instruction's pc | leaf `read_pc`; `decode_row` position 0 |
| `M[5]` | `pc_write_value` | `frame(0, FIELD_WRITE_VALUE)` | Next pc | the fall-through | leaf `write_pc`; `next_pc_rule` |
| `M[6]` | `rs1_mask` | `frame(1, FIELD_MASK)` | rs1 present | 1 on every kind | leaves `read_rs1`, `write_rs1`; `rs1_mask_boolean`, `rs1_mask_rule`, `rs1_addr_rule`, `rs1_value_masked`; selector of `gap_hi_rs1`, `gap_lo_rs1` |
| `M[7]` | `rs1_addr` | `frame(1, FIELD_ADDR)` | rs1 register | the decoded `rs1` | leaves `read_rs1`, `write_rs1`; `rs1_addr_rule` |
| `M[8]` | `rs1_read_ts` | `frame(1, FIELD_READ_TS)` | rs1 previous write | | leaf `read_rs1`; `gap_lo_rs1` |
| `M[9]` | `rs1_read_value` | `frame(1, FIELD_READ_VALUE)` | rs1 value; the shift's and the bitwise op's left operand | | leaf `read_rs1`; `rs1_writes_back`, `rs1_value_masked`, `shift_in_rule`, `shift_out_rule`, `rs1_bytes`, `bitwise_out_rule`; `rs1_lo_range` |
| `M[10]` | `rs1_write_value` | `frame(1, FIELD_WRITE_VALUE)` | rs1 written back | `rs1_read_value` | leaf `write_rs1`; `rs1_writes_back` |
| `M[11]` | `rs2_mask` | `frame(2, FIELD_MASK)` | rs2 present | 1 on the six R-type kinds | leaves `read_rs2`, `write_rs2`; `rs2_mask_boolean`, `rs2_mask_rule`, `rs2_addr_rule`, `rs2_value_masked`; selector of `gap_hi_rs2`, `gap_lo_rs2` |
| `M[12]` | `rs2_addr` | `frame(2, FIELD_ADDR)` | rs2 register | the decoded `rs2` | leaves `read_rs2`, `write_rs2`; `rs2_addr_rule` |
| `M[13]` | `rs2_read_ts` | `frame(2, FIELD_READ_TS)` | rs2 previous write | | leaf `read_rs2`; `gap_lo_rs2` |
| `M[14]` | `rs2_read_value` | `frame(2, FIELD_READ_VALUE)` | rs2 value; `src2`'s register addend | 0 on an I-type row | leaf `read_rs2`; `rs2_writes_back`, `rs2_value_masked`, `amount_split`, `src2_bytes`, `bitwise_out_rule`; `src2_lo_range` |
| `M[15]` | `rs2_write_value` | `frame(2, FIELD_WRITE_VALUE)` | rs2 written back | `rs2_read_value` | leaf `write_rs2`; `rs2_writes_back` |
| `M[16]` | `rd_mask` | `frame(3, FIELD_MASK)` | rd present | 1 on every kind | leaves `read_rd`, `write_rd`; `rd_mask_boolean`, `rd_is_zero_inverse`, `rd_mask_rule`, `rd_addr_rule`; selector of `gap_hi_rd`, `gap_lo_rd` |
| `M[17]` | `rd_addr` | `frame(3, FIELD_ADDR)` | rd register | the decoded `rd` | leaves `read_rd`, `write_rd`; `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_addr_rule` |
| `M[18]` | `rd_read_ts` | `frame(3, FIELD_READ_TS)` | rd previous write | | leaf `read_rd`; `gap_lo_rd` |
| `M[19]` | `rd_read_value` | `frame(3, FIELD_READ_VALUE)` | rd old value | | leaf `read_rd` |
| `M[20]` | `rd_write_value` | `frame(3, FIELD_WRITE_VALUE)` | rd new value | `rd_selected`, or 0 into `x0` | leaf `write_rd`; `rd_write_masked` |

The frame's slots in `shift_bitwise.rs` are `SLOT_PC = 0` through `SLOT_RD = 3`. Every query of
this frame is used by some kind.

**Witness columns, `W[0..61]`** — `W[0..6]` filled by `trace::build_frame_witness`, `W[6..57]`
by `fill::shift_bitwise` (`W[6]` in place of S14's), `W[57..61]` by
`trace::build_multiplicities` inside `prover::shard_columns`; committed in
`ShardProof::witness_commitments`, absorbed at S3 before `g` and `β`. The `KINDS[k]` rows name
the private constant beside each (`KINDS[kind::SLLI as usize]` is `SLLI`, with `kind` being
`constants::extra_mask::shift_bitwise`).

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0]` | `pc_gap_hi` | `memory::gap_hi(0)` | pc gap, high chunk | 0: a pc read's gap is always 3 | `gap_hi_pc`, `gap_lo_pc` |
| `W[1]` | `rs1_gap_hi` | `gap_hi(1)` | rs1 gap, high chunk | `gap >> 19` | `gap_hi_rs1`, `gap_lo_rs1` |
| `W[2]` | `rs2_gap_hi` | `gap_hi(2)` | rs2 gap, high chunk | | `gap_hi_rs2`, `gap_lo_rs2` |
| `W[3]` | `rd_gap_hi` | `gap_hi(3)` | rd gap, high chunk | | `gap_hi_rd`, `gap_lo_rd` |
| `W[4]` | `rd_inv` | `memory::rd_inv(4)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[5]` | `rd_is_zero` | `memory::rd_is_zero(4)` | rd is `x0` | | `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_is_zero_boolean`, `rd_write_masked` |
| `W[6]` | `rd_selected` | `memory::rd_selected(4)`; `sel` in `shift_bitwise.rs` | Result | what the instruction computes, `rd = x0` included: the fill overwrites the 0 S14's builder writes there | `rd_write_masked`, `shift_in_rule`, `shift_out_rule`, `bitwise_out_rule`; `rd_lo_range` |
| `W[7]` | `decoded_next_pc` | `shift_bitwise::DECODED[0]`; `SEQ` | Decoded fall-through | the table row's `next_pc` | `next_pc_rule`; `decode_row` position 1 |
| `W[8]` | `decoded_rs1` | `DECODED[1]` | Decoded rs1 | | `rs1_addr_rule`; `decode_row` position 2 |
| `W[9]` | `decoded_rs2` | `DECODED[2]` | Decoded rs2 | | `rs2_addr_rule`; `decode_row` position 3 |
| `W[10]` | `decoded_rd` | `DECODED[3]` | Decoded rd | | `rd_addr_rule`; `decode_row` position 4 |
| `W[11]` | `decoded_imm` | `DECODED[4]`; `IMM` | Decoded immediate | the shamt, the sign-extended immediate or 0 | `amount_split`, `src2_bytes`, `bitwise_out_rule`; `src2_lo_range`, `decode_row` position 5 |
| `W[12]` | `decoded_mask` | `DECODED[5]` | Decoded kind mask | `1 << bit` | `decoded_mask_bits`; `decode_row` position 6 |
| `W[13]` | `kind_slli` | `KINDS[0]`; `SLLI` | slli row | | `kind_slli_boolean`, `decoded_mask_bits`, `f_shift_rule`, `rs1_mask_rule`, `rd_mask_rule`, `shift_in_rule`, `shift_out_rule` |
| `W[14]` | `kind_xori` | `KINDS[1]`; `XORI` | xori row | | `kind_xori_boolean`, `decoded_mask_bits`, `f_bitwise_rule`, `rs1_mask_rule`, `rd_mask_rule`, `bitwise_out_rule` |
| `W[15]` | `kind_srli` | `KINDS[2]`; `SRLI` | srli row | | `kind_srli_boolean`, `decoded_mask_bits`, `f_shift_rule`, `rs1_mask_rule`, `rd_mask_rule`, `shift_in_rule`, `shift_out_rule` |
| `W[16]` | `kind_srai` | `KINDS[3]`; `SRAI` | srai row | | `kind_srai_boolean`, `decoded_mask_bits`, `f_shift_rule`, `rs1_mask_rule`, `rd_mask_rule`, `se_rule`, `shift_in_rule`, `shift_out_rule` |
| `W[17]` | `kind_ori` | `KINDS[4]`; `ORI` | ori row | | `kind_ori_boolean`, `decoded_mask_bits`, `f_bitwise_rule`, `rs1_mask_rule`, `rd_mask_rule`, `bitwise_out_rule` |
| `W[18]` | `kind_andi` | `KINDS[5]`; `ANDI` | andi row | | `kind_andi_boolean`, `decoded_mask_bits`, `f_bitwise_rule`, `rs1_mask_rule`, `rd_mask_rule`, `bitwise_out_rule` |
| `W[19]` | `kind_sll` | `KINDS[6]`; `SLL` | sll row | | `kind_sll_boolean`, `decoded_mask_bits`, `f_shift_rule`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `shift_in_rule`, `shift_out_rule` |
| `W[20]` | `kind_xor` | `KINDS[7]`; `XOR` | xor row | | `kind_xor_boolean`, `decoded_mask_bits`, `f_bitwise_rule`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `bitwise_out_rule` |
| `W[21]` | `kind_srl` | `KINDS[8]`; `SRL` | srl row | | `kind_srl_boolean`, `decoded_mask_bits`, `f_shift_rule`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `shift_in_rule`, `shift_out_rule` |
| `W[22]` | `kind_sra` | `KINDS[9]`; `SRA` | sra row | | `kind_sra_boolean`, `decoded_mask_bits`, `f_shift_rule`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `se_rule`, `shift_in_rule`, `shift_out_rule` |
| `W[23]` | `kind_or` | `KINDS[10]`; `OR` | or row | | `kind_or_boolean`, `decoded_mask_bits`, `f_bitwise_rule`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `bitwise_out_rule` |
| `W[24]` | `kind_and` | `KINDS[11]`; `AND` | and row | | `kind_and_boolean`, `decoded_mask_bits`, `f_bitwise_rule`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `bitwise_out_rule` |
| `W[25]` | `f_shift` | `shift_bitwise::F_SHIFT` | Row is a shift | the sum of the six shift bits | `f_shift_rule`, `f_shift_boolean`, `copower_rule`; **selector** of `amount_range`, `amount_scaled`, `shift_powers` |
| `W[26]` | `f_bitwise` | `F_BITWISE` | Row is bitwise | the sum of the six bitwise bits | `f_bitwise_rule`, `f_bitwise_boolean`, `bitwise_out_rule`; **selector** of the eight `byte_a*` bounds and the four `and_byte_*` lookups |
| `W[27]` | `rs1_hi` | `RS1_HI` | rs1, high halfword | `rs1 >> 16` | `rs1_hi_range`, `rs1_lo_range`; `rs1_get_sign` position 0 |
| `W[28]` | `rs1_sign` | `RS1_SIGN` | rs1, bit 31 | `rs1 >> 31` | `se_rule`, `rs1_sign_boolean`; `rs1_get_sign` position 1 |
| `W[29]` | `src2_hi` | `SRC2_HI` | `src2`, high halfword | `(rs2 + imm) >> 16` | `src2_hi_range`, `src2_lo_range` |
| `W[30]` | `amount` | `AMOUNT` | Truncated shift amount | `src2 mod 32`, on a bitwise row too | `amount_split`; `amount_range`, `amount_scaled`, `shift_powers` position 0 |
| `W[31]` | `pow` | `POW` | `2^amount` | 0 on a bitwise row | `copower_rule`, `shift_prod_rule`; `shift_powers` position 1 |
| `W[32]` | `copow` | `COPOW` | `2^(31 − amount)` | 0 on a bitwise row | `copower_rule`, `scaled_rule`; `shift_powers` position 2 |
| `W[33]` | `high` | `HIGH` | `src2 >> 5` | | `amount_split`; `high_lo_range` |
| `W[34]` | `high_hi` | `HIGH_HI` | `high`, high halfword | | `high_hi_range`, `high_lo_range` |
| `W[35]` | `se` | `SE` | Sign-extension term | `is_arithmetic·rs1_sign` | `se_rule`, `se_boolean`, `shift_in_rule`, `shift_out_rule` |
| `W[36]` | `shift_in` | `SHIFT_IN` | The one multiplicand | `rs1` on a left shift, `rd_selected − 2^32·se` on a right one, 0 elsewhere; **`Fr`-backed**, being negative on an `sra` of a negative operand | `shift_in_rule`, `shift_prod_rule` |
| `W[37]` | `shift_prod` | `SHIFT_PROD` | `shift_in·pow` | reaches `2^63` on a left shift; **`Fr`-backed** | `shift_prod_rule`, `shift_out_rule` |
| `W[38]` | `ovf` | `OVF` | Left shift's discarded high bits | 0 on every other kind | `shift_out_rule`; `ovf_lo_range` |
| `W[39]` | `ovf_hi` | `OVF_HI` | `ovf`, high halfword | | `ovf_hi_range`, `ovf_lo_range` |
| `W[40]` | `residue` | `RESIDUE` | Right shift's discarded low bits | 0 on every other kind | `shift_out_rule`, `scaled_rule`; `residue_lo_range` |
| `W[41]` | `residue_hi` | `RESIDUE_HI` | `residue`, high halfword | | `residue_hi_range`, `residue_lo_range` |
| `W[42]` | `scaled` | `SCALED` | `residue·2^(32 − amount)` | | `scaled_rule`; `scaled_lo_range` |
| `W[43]` | `scaled_hi` | `SCALED_HI` | `scaled`, high halfword | | `scaled_hi_range`, `scaled_lo_range` |
| `W[44..48]` | `byte_a0` … `byte_a3` | `BYTES_A[j]` | rs1's bytes, low first | `(rs1 >> 8j) & 255` | `rs1_bytes`; `byte_a{j}_range`, `byte_a{j}_scaled`, `and_byte_{j}` position 0 |
| `W[48..52]` | `byte_b0` … `byte_b3` | `BYTES_B[j]` | `src2`'s bytes, low first | `(src2 >> 8j) & 255` | `src2_bytes`; `and_byte_{j}` position 1 |
| `W[52..56]` | `byte_and0` … `byte_and3` | `BYTES_AND[j]` | The bytewise AND | `byte_a_j & byte_b_j` | `bitwise_out_rule`; `and_byte_{j}` position 2 |
| `W[56]` | `rd_hi` | `RD_HI` | Result, high halfword | `rd_selected >> 16` | `rd_hi_range`, `rd_lo_range` |
| `W[57]` | `mult_timestamp` | `MULTIPLICITIES[0]` | Timestamp-table count | per table row `t`: the gated gap chunks (`mask·chunk`) equal to `t`, credited to rows below `2^19` | leaf `timestamp_table_num` |
| `W[58]` | `mult_range16` | `MULTIPLICITIES[1]` | 16-bit-table count | per table row `t`: the gated halfwords equal to `t` — 14 of them under `pc_mask`, 2 under `f_shift` and 8 under `f_bitwise` | leaf `range16_table_num` |
| `W[59]` | `mult_generic` | `MULTIPLICITIES[2]` | Generic-table count | per table row `t`: the gated generic tuples equal to row `t`; a live row's sign lookup lands on `U16GetSign`'s row `2^16 + 1 + rs1_hi`, a shift row's on `ShiftPowers`' row `2^17 + 1 + amount`, a bitwise row's four on the AND table's rows `1 + byte_a_j` | leaf `generic_table_num` |
| `W[60]` | `mult_decoder` | `MULTIPLICITIES[3]` | Decoder-table count | per table row `t`: the live cycles at pc `2t`; and every padding row's switched-off tuple (`MINUS_ONE` in all seven positions) on the table's lowest non-live row, row 0 | leaf `decoder_table_num` |

A switched-off obligation's gated tuple is 0, so row 0 of `mult_timestamp` and `mult_range16`
counts every switched-off obligation. This family switches more off than either earlier one, and
it does so on **live** rows: `f_shift` and `f_bitwise` partition the kinds, so a shift row
switches off the eight `byte_a` bounds and a bitwise row the two `amount` bounds — ten of the 24
`RANGE16` obligations are under a selector that some live row sets to 0, where in §3 and §4
every `RANGE16` obligation is under `pc_mask` and so on wherever the row is live. A padding row
switches all 24 off, and all 8 timestamp obligations with them; a live I-type row also switches
off the two `rs2` chunks. Row 0 also counts every live chunk or
halfword whose value is 0, `pc_gap_hi` on every live row among them. In `mult_generic`, a
padding row's six generic tuples all gate to the all-zero tuple, the `ZeroEntry` at row 0, and so
does a live row's switched-off half (a shift row's four AND lookups, a bitwise row's
`shift_powers`).

**Setup columns, `S[0..10]`** — two tables. `S[0..7]` is the family's decoded table,
`program::lookup_tuple(2)` order, filled by `program::FamilyTable::column_poly(j)`; committed in
program identity (`program::setup_commitments`) and carried as `VerifyingKey::setup_commitments`
for the family. `S[7..10]` is the packed generic table (§0.3), filled by
`program::lookup_tables::generic_table(n)` — the same three commitments at every even `n ≥ 18`,
carried in every key as `VerifyingKey::generic_table` and covered by the key's SRS digest, not by
identity. A shard opens `S[7..10]` against them, after identity's list, because
`FamilyCircuit::reads_generic_table` holds for this circuit (`shard-proof.md` §3, §5.1, §7;
`jump-branch-slt.md` §6, which S18 did not amend). Each is read only by its table's denominator,
at the `β` power in the last column.

| address | name | Rust | descriptive name | contents | read by | weight |
| --- | --- | --- | --- | --- | --- | --- |
| `S[0]` | `table_pc` | `shift_bitwise::channels()[3].table[0]` | Table pc | `RowField::Pc` | `decoder_table_den` | 1 |
| `S[1]` | `table_next_pc` | `channels()[3].table[1]` | Table fall-through | `RowField::NextPc` | `decoder_table_den` | `β` |
| `S[2]` | `table_rs1` | `channels()[3].table[2]` | Table rs1 | `RowField::Rs1` | `decoder_table_den` | `β²` |
| `S[3]` | `table_rs2` | `channels()[3].table[3]` | Table rs2 | `RowField::Rs2` | `decoder_table_den` | `β³` |
| `S[4]` | `table_rd` | `channels()[3].table[4]` | Table rd | `RowField::Rd` | `decoder_table_den` | `β⁴` |
| `S[5]` | `table_imm` | `channels()[3].table[5]` | Table immediate | `RowField::Imm` | `decoder_table_den` | `β⁵` |
| `S[6]` | `table_extra_mask` | `channels()[3].table[6]` | Table kind mask | `RowField::ExtraMask` | `decoder_table_den` | `β⁶` |
| `S[7]` | `generic_key` | `shift_bitwise::GENERIC_TABLE[0]`, `channels()[2].table[0]` | Generic key | 0, `AND_BASE + a + 1`, `SIGN_BASE + h + 1` or `SHIFT_BASE + s + 1` | `generic_table_den` | 1 |
| `S[8]` | `generic_value` | `GENERIC_TABLE[1]` | Generic value | 0, `b`, `h >> 15` or `2^s` | `generic_table_den` | `β` |
| `S[9]` | `generic_result` | `GENERIC_TABLE[2]` | Generic result | 0, `a & b`, 0 or `2^(31 − s)` | `generic_table_den` | `β²` |

`shift_bitwise::TABLE_WIDTH` is 7 and `constants::generic_table::WIDTH` is 3.

**Virtual tables** — never committed, never opened; `gkr_verify::verify` evaluates their
closed forms.

| address | name | Rust | descriptive name | value at row `y` | read by |
| --- | --- | --- | --- | --- | --- |
| `V[range19]` | `range19` | `VirtualKind::Range19`, wire tag 2 | 19-bit range table | `y mod 2^19` | `timestamp_table_den` |
| `V[range16]` | `range16` | `VirtualKind::Range16`, wire tag 3 | 16-bit range table | `y mod 2^16` | `range16_table_den` |

### 5.4 Gate list 0: the 124 leaves

A leaf's relation number equals its `L1` offset, 0 to 123.

**The memory product trees.** The read side is `L1[0..4]` and the write side `L1[4..8]`, each
leaf per §0.6, and each is §4.4's address for address — the frame is the same. Four queries fill
each side, so neither has a pad.

| `L1` | node | mask | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `read_pc` | `M[1]` | 3 | `M[2]` | `M[3]` | `M[4]` |
| 1 | `read_rs1` | `M[6]` | 1 | `M[7]` | `M[8]` | `M[9]` |
| 2 | `read_rs2` | `M[11]` | 1 | `M[12]` | `M[13]` | `M[14]` |
| 3 | `read_rd` | `M[16]` | 1 | `M[17]` | `M[18]` | `M[19]` |
| 4 | `write_pc` | `M[1]` | 3 | `M[2]` | `4·M[0] + 0` | `M[5]` |
| 5 | `write_rs1` | `M[6]` | 1 | `M[7]` | `4·M[0] + 1` | `M[10]` |
| 6 | `write_rs2` | `M[11]` | 1 | `M[12]` | `4·M[0] + 2` | `M[15]` |
| 7 | `write_rd` | `M[16]` | 1 | `M[17]` | `4·M[0] + 3` | `M[20]` |

**The `timestamp` fraction tree**, `L1[8..40]`: 16 fractions, the table's then 8 gap obligations
then 7 pads, §4.4's list unchanged. Fraction `i` is `(L1[8 + 2i], L1[9 + 2i])`, named
`<node>_num` and `<node>_den`.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 8, 9 | `timestamp_table` | `−mult_timestamp` | `V[range19] + g` |
| 1 | 10, 11 | `gap_hi_pc` | 1 | `g + pc_mask·pc_gap_hi` |
| 2 | 12, 13 | `gap_lo_pc` | 1 | `g − pc_mask + 4·pc_mask·cycle − pc_mask·pc_read_ts − 2^19·pc_mask·pc_gap_hi` |
| 3 | 14, 15 | `gap_hi_rs1` | 1 | `g + rs1_mask·rs1_gap_hi` |
| 4 | 16, 17 | `gap_lo_rs1` | 1 | `g + 4·rs1_mask·cycle − rs1_mask·rs1_read_ts − 2^19·rs1_mask·rs1_gap_hi` |
| 5 | 18, 19 | `gap_hi_rs2` | 1 | `g + rs2_mask·rs2_gap_hi` |
| 6 | 20, 21 | `gap_lo_rs2` | 1 | `g + rs2_mask + 4·rs2_mask·cycle − rs2_mask·rs2_read_ts − 2^19·rs2_mask·rs2_gap_hi` |
| 7 | 22, 23 | `gap_hi_rd` | 1 | `g + rd_mask·rd_gap_hi` |
| 8 | 24, 25 | `gap_lo_rd` | 1 | `g + 2·rd_mask + 4·rd_mask·cycle − rd_mask·rd_read_ts − 2^19·rd_mask·rd_gap_hi` |
| 9–15 | 26–39 | `timestamp_pad_0` … `timestamp_pad_6` | 0 | 1 |

**The `range16` fraction tree**, `L1[40..104]`: **32 fractions**, the table's then 24 obligations
then 7 pads. This is the tree that makes the circuit a list deeper than §3's and §4's.

| fraction | `L1` | node | numerator | denominator (named) | selector |
| --- | --- | --- | --- | --- | --- |
| 0 | 40, 41 | `range16_table` | `−mult_range16` | `V[range16] + g` | — |
| 1 | 42, 43 | `rs1_hi_range` | 1 | `g + pc_mask·rs1_hi` | `pc_mask` |
| 2 | 44, 45 | `rs1_lo_range` | 1 | `g + pc_mask·rs1_read_value − 2^16·pc_mask·rs1_hi` | `pc_mask` |
| 3 | 46, 47 | `src2_hi_range` | 1 | `g + pc_mask·src2_hi` | `pc_mask` |
| 4 | 48, 49 | `src2_lo_range` | 1 | `g + pc_mask·rs2_read_value + pc_mask·decoded_imm − 2^16·pc_mask·src2_hi` | `pc_mask` |
| 5 | 50, 51 | `high_hi_range` | 1 | `g + pc_mask·high_hi` | `pc_mask` |
| 6 | 52, 53 | `high_lo_range` | 1 | `g + pc_mask·high − 2^16·pc_mask·high_hi` | `pc_mask` |
| 7 | 54, 55 | `ovf_hi_range` | 1 | `g + pc_mask·ovf_hi` | `pc_mask` |
| 8 | 56, 57 | `ovf_lo_range` | 1 | `g + pc_mask·ovf − 2^16·pc_mask·ovf_hi` | `pc_mask` |
| 9 | 58, 59 | `residue_hi_range` | 1 | `g + pc_mask·residue_hi` | `pc_mask` |
| 10 | 60, 61 | `residue_lo_range` | 1 | `g + pc_mask·residue − 2^16·pc_mask·residue_hi` | `pc_mask` |
| 11 | 62, 63 | `scaled_hi_range` | 1 | `g + pc_mask·scaled_hi` | `pc_mask` |
| 12 | 64, 65 | `scaled_lo_range` | 1 | `g + pc_mask·scaled − 2^16·pc_mask·scaled_hi` | `pc_mask` |
| 13 | 66, 67 | `rd_hi_range` | 1 | `g + pc_mask·rd_hi` | `pc_mask` |
| 14 | 68, 69 | `rd_lo_range` | 1 | `g + pc_mask·rd_selected − 2^16·pc_mask·rd_hi` | `pc_mask` |
| 15 | 70, 71 | `amount_range` | 1 | `g + f_shift·amount` | `f_shift` |
| 16 | 72, 73 | `amount_scaled` | 1 | `g + 2048·f_shift·amount` | `f_shift` |
| 17 | 74, 75 | `byte_a0_range` | 1 | `g + f_bitwise·byte_a0` | `f_bitwise` |
| 18 | 76, 77 | `byte_a0_scaled` | 1 | `g + 256·f_bitwise·byte_a0` | `f_bitwise` |
| 19, 20 | 78–81 | `byte_a1_range`, `byte_a1_scaled` | 1 | as 17, 18 over `byte_a1` | `f_bitwise` |
| 21, 22 | 82–85 | `byte_a2_range`, `byte_a2_scaled` | 1 | as 17, 18 over `byte_a2` | `f_bitwise` |
| 23, 24 | 86–89 | `byte_a3_range`, `byte_a3_scaled` | 1 | as 17, 18 over `byte_a3` | `f_bitwise` |
| 25–31 | 90–103 | `range16_pad_0` … `range16_pad_6` | 0 | 1 | — |

**The `generic` fraction tree**, `L1[104..120]`: 8 fractions, the table's then 6 lookups then 1
pad.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 104, 105 | `generic_table` | `−mult_generic` | `generic_key + β·generic_value + β²·generic_result + g` |
| 1 | 106, 107 | `rs1_get_sign` | 1 | `g + 257·pc_mask + pc_mask·rs1_hi + β·pc_mask·rs1_sign` |
| 2 | 108, 109 | `shift_powers` | 1 | `g + 65793·f_shift + f_shift·amount + β·f_shift·pow + β²·f_shift·copow` |
| 3 | 110, 111 | `and_byte_0` | 1 | `g + f_bitwise + f_bitwise·byte_a0 + β·f_bitwise·byte_b0 + β²·f_bitwise·byte_and0` |
| 4–6 | 112–117 | `and_byte_1` … `and_byte_3` | 1 | as fraction 3 over byte `j` |
| 7 | 118, 119 | `generic_pad_0` | 0 | 1 |

The three literals are the three sub-tables' gated key bases, `constants::generic_table`'s
`AND_BASE + 1 = 1`, `SIGN_BASE + 1 = 257` and `SHIFT_BASE + 1 = 65793`:

```text
L{1}[109]  shift_powers_den
  positional  g + 65793·W[25] + 1·W[25]·W[30] + lookup_beta·W[25]·W[31]
                + lookup_beta_2·W[25]·W[32]
  reads as    g + f_shift·(e_0 + 1) + β·f_shift·e_1 + β²·f_shift·e_2,
              e = (amount + SHIFT_BASE, pow, copow), SHIFT_BASE = 65792:
              the key amount + 65793 and the row's two powers at f_shift = 1,
              the ZeroEntry at 0
```

**The `decoder` fraction tree**, `L1[120..124]`: 2 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 120, 121 | `decoder_table` | `−mult_decoder` | `table_pc + β·table_next_pc + β²·table_rs1 + β³·table_rs2 + β⁴·table_rd + β⁵·table_imm + β⁶·table_extra_mask + g` |
| 1 | 122, 123 | `decode_row` | 1 | `g_dec + (1 + β + β² + β³ + β⁴ + β⁵ + β⁶)·pc_mask + pc_mask·pc_read_value + β·pc_mask·decoded_next_pc + β²·pc_mask·decoded_rs1 + β³·pc_mask·decoded_rs2 + β⁴·pc_mask·decoded_rd + β⁵·pc_mask·decoded_imm + β⁶·pc_mask·decoded_mask` |

`decode_row_den` is §4.4's with the decoded row at `W[7..13]`, address for address.

### 5.5 Gate list 0: the 48 enforcing gates

Relations 124–171, in list order, in §3.5's format. The family's 38 come from
`shift_bitwise::family_spec` and its private helpers `booleanity`, `flag_rule`, `mask_rule`,
`addr_rule` and `value_masked`.

**A. The frame's gates (124–133)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
124–127 <q>_mask_boolean — each query's presence flag is a bit          Quadratic, degree 2
        code  memory::booleanity(frame(s, FIELD_MASK)), in frame_body

  124 pc_mask_boolean    0 = M[1]  − M[1]·M[1]      0 = pc_mask  − pc_mask²
  125 rs1_mask_boolean   0 = M[6]  − M[6]·M[6]      0 = rs1_mask − rs1_mask²
  126 rs2_mask_boolean   0 = M[11] − M[11]·M[11]    0 = rs2_mask − rs2_mask²
  127 rd_mask_boolean    0 = M[16] − M[16]·M[16]    0 = rd_mask  − rd_mask²

────────────────────────────────────────────────────────────────────────────────────────────
128–129 <q>_writes_back — a read-only register is left unchanged        Linear, degree 1
        code  memory::write_back(s), in frame_body

  128 rs1_writes_back    0 = M[10] − M[9]     0 = rs1_write_value − rs1_read_value
  129 rs2_writes_back    0 = M[15] − M[14]    0 = rs2_write_value − rs2_read_value

────────────────────────────────────────────────────────────────────────────────────────────
130–133 the x0 rule                                                    Quadratic, degree 2
        code  memory::x0_gates(3, 4), whose first two are
              gadgets::is_zero(&[(1, rd_addr)], rd_inv, rd_is_zero, rd_mask)

  130 rd_is_zero_inverse     0 = W[5] − M[16] + M[17]·W[4]
                             0 = rd_addr·rd_inv + rd_is_zero − rd_mask
  131 rd_is_zero_at_nonzero  0 = M[17]·W[5]        0 = rd_addr·rd_is_zero
  132 rd_is_zero_boolean     0 = W[5] − W[5]·W[5]  0 = rd_is_zero − rd_is_zero²
  133 rd_write_masked        0 = M[20] − W[6] + W[5]·W[6]
                             0 = rd_write_value − (1 − rd_is_zero)·rd_selected

  reads as (124–133)  §4.5's 84–93, address for address: the frame is the same four
                      queries, and the bare frame fixture memory_frame_reg.bin is the
                      same file.
```

**B. What the row is (134–150)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
134–145 kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2
        code  shift_bitwise's private booleanity(KINDS[k])

  134 kind_slli_boolean   0 = W[13] − W[13]·W[13]    139 kind_andi_boolean  W[18]
  135 kind_xori_boolean   0 = W[14] − W[14]·W[14]    140 kind_sll_boolean   W[19]
  136 kind_srli_boolean   0 = W[15] − W[15]·W[15]    141 kind_xor_boolean   W[20]
  137 kind_srai_boolean   0 = W[16] − W[16]·W[16]    142 kind_srl_boolean   W[21]
  138 kind_ori_boolean    0 = W[17] − W[17]·W[17]    143 kind_sra_boolean   W[22]
                                                     144 kind_or_boolean    W[23]
                                                     145 kind_and_boolean   W[24]

────────────────────────────────────────────────────────────────────────────────────────────
146     decoded_mask_bits — the packed mask is its twelve bits          Linear, degree 1
        code  shift_bitwise::family_spec, `bits`

  positional  0 = W[13] + 2·W[14] + 4·W[15] + 8·W[16] + 16·W[17] + 32·W[18] + 64·W[19]
                  + 128·W[20] + 256·W[21] + 512·W[22] + 1024·W[23] + 2048·W[24] − W[12]
  named       0 = Σ_k 2^k·kind_k − decoded_mask,  k in extra_mask::shift_bitwise order

  reads as  §4.5's 106 over this family's twelve bits. One-hotness is not here: the decoder
            table, whose masks are single bits, is what enforces it (lookup.md §10), and on
            a padding row, where the lookup is off, the bits are free.

────────────────────────────────────────────────────────────────────────────────────────────
147–150 the two halves                                Linear/Quadratic, degrees 1 and 2
        code  flag_rule(F_SHIFT, &SHIFTS), booleanity(F_SHIFT), and the same for BITWISE

  147 f_shift_rule     0 = W[25] − W[13] − W[15] − W[16] − W[19] − W[21] − W[22]
                       0 = f_shift − (kind_slli + kind_srli + kind_srai
                                      + kind_sll + kind_srl + kind_sra)
  148 f_shift_boolean  0 = W[25] − W[25]·W[25]     0 = f_shift − f_shift²
  149 f_bitwise_rule   0 = W[26] − W[14] − W[17] − W[18] − W[20] − W[23] − W[24]
                       0 = f_bitwise − (kind_xori + kind_ori + kind_andi
                                        + kind_xor + kind_or + kind_and)
  150 f_bitwise_boolean 0 = W[26] − W[26]·W[26]    0 = f_bitwise − f_bitwise²

  reads as  each half is a committed column because each is a **lookup selector**, and
            validate refuses a selector without a booleanity gate; every other helper flag
            this family needs is a linear form over the bits and stays inline (§1's
            signals). On a live row the bits are one-hot, so exactly one of the two is 1;
            on a padding row both are free booleans, which costs a table multiplicity and
            nothing else (§5.10).
```

**C. Which queries a row makes, and where (151–158)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
151     rs1_mask_rule — every kind reads rs1                            Quadratic, degree 2
        code  mask_rule(frame(1, FIELD_MASK), &KINDS)

  positional  0 = M[6] − M[1]·W[13] − M[1]·W[14] − … − M[1]·W[24]      (all twelve bits)
  named       0 = rs1_mask − pc_mask·Σ_k kind_k

────────────────────────────────────────────────────────────────────────────────────────────
152     rs2_mask_rule — only the R-type half reads rs2                  Quadratic, degree 2
        code  mask_rule(frame(2, FIELD_MASK), &READS_RS2)

  positional  0 = M[11] − M[1]·W[19] − M[1]·W[21] − M[1]·W[22] − M[1]·W[24] − M[1]·W[23]
                  − M[1]·W[20]
  named       0 = rs2_mask − pc_mask·(kind_sll + kind_srl + kind_sra
                                      + kind_and + kind_or + kind_xor)

────────────────────────────────────────────────────────────────────────────────────────────
153     rd_mask_rule — every kind writes rd                             Quadratic, degree 2
        code  mask_rule(frame(3, FIELD_MASK), &KINDS)

  positional  0 = M[16] − M[1]·W[13] − M[1]·W[14] − … − M[1]·W[24]
  named       0 = rd_mask − pc_mask·Σ_k kind_k

  reads as (151–153)  on a live row the bits are one-hot, so each sum is 0 or 1 and the
                      mask is the kind's use of the query; an I-type row makes no rs2
                      query and reads 0 there (158). On a padding row pc_mask = 0 and every
                      mask is 0, whatever the bits hold: S14's control C8, which the row
                      suite refuses on this frame twice — bare, by 153 with 156, and
                      dressed to satisfy every other gate, by 153 alone (§5.10).

────────────────────────────────────────────────────────────────────────────────────────────
154–156 <q>_addr_rule — a present query's register is the decoded one  Quadratic, degree 2
        code  addr_rule(slot, DECODED_<Q>)

  154 rs1_addr_rule   0 = M[6]·M[7]   − M[6]·W[8]     0 = rs1_mask·(rs1_addr − decoded_rs1)
  155 rs2_addr_rule   0 = M[11]·M[12] − M[11]·W[9]    0 = rs2_mask·(rs2_addr − decoded_rs2)
  156 rd_addr_rule    0 = M[16]·M[17] − M[16]·W[10]   0 = rd_mask·(rd_addr − decoded_rd)

  reads as  §4.5's 110–112: no constant term, this family having no ecall row. rd = x0
            needs no bit — the table's rd is 0, 156 makes the write's address 0, and
            130–133 write 0 whatever rd_selected is.

────────────────────────────────────────────────────────────────────────────────────────────
157–158 <q>_value_masked — an absent operand reads 0                   Quadratic, degree 2
        code  value_masked(slot)

  157 rs1_value_masked  0 = M[9]  − M[6]·M[9]      0 = (1 − rs1_mask)·rs1_read_value
  158 rs2_value_masked  0 = M[14] − M[11]·M[14]    0 = (1 − rs2_mask)·rs2_read_value

  reads as  158 is what makes `src2 = rs2 + imm` one expression for both operand shapes:
            an I-type row's rs2 reads 0, so src2 is the immediate, and an R-type row's
            decoded imm is 0 (the table's), so src2 is the register. One addend is always
            zero, the field sum is the integer sum, and no wrap bit is needed
            (shift-bitwise.md §1).
```

**D. The pc, the amount and the powers (159–164)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
159     next_pc_rule — the pc falls through, always                     Linear, degree 1
        code  shift_bitwise::family_spec

  positional  0 = M[5] − W[7]
  named       0 = pc_write_value − decoded_next_pc

  reads as  no kind here computes a pc, so there is no wrap bit and no bound of its own:
            the decoder lookup binds decoded_next_pc to the identity-committed table
            exactly as it binds rs1, rs2, rd and imm, none of which is range-checked
            either. S17's rule that a family computing a pc keeps its next_pc even does not
            reach a family that copies one (shift-bitwise.md §4.1).

────────────────────────────────────────────────────────────────────────────────────────────
160     amount_split — the shamt is the low five bits of src2           Linear, degree 1
        code  shift_bitwise::family_spec, `split`

  positional  0 = M[14] + W[11] − 32·W[33] − W[30]
  named       0 = rs2_read_value + decoded_imm − 32·high − amount

  reads as  ungated and degree 1. With `amount` in [0, 32) from ShiftPowers' domain, `high`
            bounded by its own 16+16 pair and `src2` by its own, the split is the unique
            one and `amount` really is src2 mod 32. **Never leave the shamt free**: an
            amount used only as a lookup key is prover-chosen, and `sll` with rs2 = 4 would
            shift by 8 — the row the suite's
            the_shamt_is_not_free_and_the_high_chunks_bound_is_what_closes_it builds, whose
            only honest `high` is −1/8 and which one of high's two obligations refuses. On
            a bitwise row the gate still holds, the fill writing the true split, and
            `amount` is unconstrained beyond it, ShiftPowers being off there.

────────────────────────────────────────────────────────────────────────────────────────────
161     copower_rule — the looked-up pair multiplies to 2^31            Quadratic, degree 2
        code  shift_bitwise::family_spec, over generic_table::SHIFT_COPOWER_BITS

  positional  0 = −2147483648·W[25] + W[31]·W[32]
  named       0 = pow·copow − 2^31·f_shift

  reads as  the table stores the copower **halved**, 2^(31 − s) rather than 2^(32 − s),
            because at s = 0 the latter is 2^32 and the packed table's columns are
            u32-backed; the two gates that read it carry the compensating factor 2
            (shift-bitwise.md §3.1). The gate is redundant given 160 and the key bound of
            §5.6 — those confine the key to ShiftPowers' own 32 rows, so the looked-up pair
            is already that row's — and is kept as the circuit's own reading of the table:
            a ShiftPowers row generated wrong stops the honest prover here rather than
            licensing a residue bound that is not one. On a bitwise row f_shift is 0, so it
            says pow·copow = 0 and the fill writes both as 0.

────────────────────────────────────────────────────────────────────────────────────────────
162     se_rule — the sign-extension term                               Quadratic, degree 2
        code  shift_bitwise::family_spec, over ARITHMETIC

  positional  0 = W[35] − W[16]·W[28] − W[22]·W[28]
  named       0 = se − (kind_srai + kind_sra)·rs1_sign

163     rs1_sign_boolean   0 = W[28] − W[28]·W[28]    0 = rs1_sign − rs1_sign²
164     se_boolean         0 = W[35] − W[35]·W[35]    0 = se − se²
        Quadratic, degree 2; code  shift_bitwise's private booleanity

  reads as (162–164)  `se` is 0 on every logical shift and every bitwise row, and rs1's bit
                      31 on sra and srai. It is committed rather than inlined for the
                      degree: is_arithmetic·rs1_sign appears inside two further products
                      (165, 167), and inlining it would make each degree 3. se_boolean is
                      implied by 162 over a boolean rs1_sign and one-hot kind bits; it is
                      written anyway, S18 must-be-exact 5 asking a sign bit's
                      sign-weighted form to carry one. The suite's
                      an_srai_carrying_srlis_answer_is_refused_by_se_rule_alone is the row
                      that shows 162 load-bearing: an srli's whole honest witness with the
                      kind bit and the packed mask swapped to srai, which every other gate
                      and the decoder lookup accept.
```

**E. The one product, and both shift directions (165–168)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
165     shift_in_rule — which multiplicand the product takes            Quadratic, degree 2
        code  shift_bitwise::family_spec, over LEFT then RIGHT

  positional  0 = W[36] − W[13]·M[9] − W[19]·M[9]
                  − W[15]·W[6] + 2^32·W[15]·W[35] − W[16]·W[6] + 2^32·W[16]·W[35]
                  − W[21]·W[6] + 2^32·W[21]·W[35] − W[22]·W[6] + 2^32·W[22]·W[35]
  named, factored
    0 = shift_in − (kind_slli + kind_sll)·rs1_read_value
                 − (kind_srli + kind_srai + kind_srl + kind_sra)·(rd_selected − 2^32·se)

────────────────────────────────────────────────────────────────────────────────────────────
166     shift_prod_rule — the one multiplication by pow                 Quadratic, degree 2
        code  shift_bitwise::family_spec

  positional  0 = W[37] − W[36]·W[31]
  named       0 = shift_prod − shift_in·pow

────────────────────────────────────────────────────────────────────────────────────────────
167     shift_out_rule — both directions read the one product           Quadratic, degree 2
        code  shift_bitwise::family_spec, over LEFT then RIGHT

  positional  0 = W[13]·W[37] − W[13]·W[6] − 2^32·W[13]·W[38]
                  + W[19]·W[37] − W[19]·W[6] − 2^32·W[19]·W[38]
                  + W[15]·W[37] + W[15]·W[40] − W[15]·M[9] + 2^32·W[15]·W[35]
                  + W[16]·W[37] + W[16]·W[40] − W[16]·M[9] + 2^32·W[16]·W[35]
                  + W[21]·W[37] + W[21]·W[40] − W[21]·M[9] + 2^32·W[21]·W[35]
                  + W[22]·W[37] + W[22]·W[40] − W[22]·M[9] + 2^32·W[22]·W[35]
  named, factored
    0 = (kind_slli + kind_sll)·(shift_prod − rd_selected − 2^32·ovf)
      + (kind_srli + kind_srai + kind_srl + kind_sra)
        ·(shift_prod + residue − rs1_read_value + 2^32·se)

────────────────────────────────────────────────────────────────────────────────────────────
168     scaled_rule — the copower half of the residue bound             Quadratic, degree 2
        code  shift_bitwise::family_spec

  positional  0 = W[42] − 2·W[40]·W[32]
  named       0 = scaled − 2·residue·copow

  reads as (165–168)  **one product serves both directions**: 166 is ungated and is the
                      only multiplication by pow, and 165 is what chooses its multiplicand,
                      which is what keeps 167 degree 2 — writing either arm as
                      is_left·(rs1·pow − …) would be degree 3.
                      Left:  shift_in = rs1, so shift_prod = rs1·2^s < 2^63, and 167 splits
                             it as rd + 2^32·ovf with both parts 16+16 range-checked, a
                             split of an integer below 2^64 that is unique.
                      Right: with rs1_adj = rs1 − 2^32·se and rd_adj = rd − 2^32·se, 167 is
                             the floor-division identity rs1_adj = rd_adj·2^s + residue,
                             which covers both signs because an arithmetic shift of a
                             negative word is the floor division of its signed value and
                             the result's sign is the operand's.
                      On a bitwise row every arm is multiplied by a kind bit that is 0, so
                      165–167 hold at shift_in = shift_prod = 0, which the fill writes; the
                      forgeries that show each load-bearing are the suite's `and carrying a
                      shift multiplicand`, `and carrying a shift product` and the two slli
                      rows whose product and whose result each move by themselves.
                      168 is the residue bound's scaled half: scaled = residue·2^(32 − s),
                      16+16 range-checked, which says residue < 2^s — *given* residue is an
                      integer. Over Fr a "residue" of s·(2^(32−s))^{-1} satisfies the scaled
                      bound and absorbs rs1 − rd·2^s for any rd, so residue carries its own
                      **direct** 16+16 pair and check_copowers refuses the circuit without
                      it (shift-bitwise.md §4.3; the suite's
                      a_residue_that_is_not_an_integer_is_refused_by_its_own_bound).
```

**F. The bitwise half (169–171)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
169     rs1_bytes — rs1 is its four bytes                               Linear, degree 1
170     src2_bytes — src2 is its four bytes                             Linear, degree 1
        code  shift_bitwise::family_spec, over byte_weights

  169 positional  0 = M[9] − W[44] − 256·W[45] − 65536·W[46] − 16777216·W[47]
      named       0 = rs1_read_value − Σ_j 2^(8j)·byte_a_j
  170 positional  0 = M[14] + W[11] − W[48] − 256·W[49] − 65536·W[50] − 16777216·W[51]
      named       0 = rs2_read_value + decoded_imm − Σ_j 2^(8j)·byte_b_j

  reads as  both are ungated and degree 1. On a shift row the byte columns carry no table
            lookup — f_bitwise is 0 — so a decomposition always exists and constrains
            nothing; on a bitwise row §5.6's key bound holds each `byte_a_j` below 256 and
            the AND row it matches holds `byte_b_j` there, so all eight are bytes and the
            decomposition is the unique one.

────────────────────────────────────────────────────────────────────────────────────────────
171     bitwise_out_rule — AND, OR and XOR from one accumulator         Quadratic, degree 2
        code  shift_bitwise::family_spec, `bitwise`

  positional  0 = W[26]·W[6]
                  − (W[23] + W[17] + W[20] + W[14])·(M[14] + W[11] + M[9])   ×as written
                  − Σ_j 2^(8j)·(W[24] + W[18])·byte_and_j
                  + Σ_j 2^(8j)·(W[23] + W[17])·byte_and_j
                  + Σ_j 2^(8j+1)·(W[20] + W[14])·byte_and_j
  named, factored
    0 = f_bitwise·rd_selected − t1·(rs1_read_value + rs2_read_value + decoded_imm)
                              − t2·Σ_j 2^(8j)·byte_and_j,
    t1 = kind_or + kind_ori + kind_xor + kind_xori,
    t2 = (kind_and + kind_andi) − (kind_or + kind_ori) − 2·(kind_xor + kind_xori)

  reads as  per byte `or = a + b − and` and `xor = a + b − 2·and`; summing by weight and
            using 169 and 170, rd = t1·(rs1 + src2) + t2·Σ 2^(8j)·and_j. So **there is no
            XOR table and no OR table**: `and` is Σ 2^(8j)·and_j, `or` is
            rs1 + src2 − Σ 2^(8j)·and_j and `xor` is rs1 + src2 − 2·Σ 2^(8j)·and_j, each
            exact over the integers since a | b and a ^ b are below 2^32 and no carry
            crosses a byte (acceptance 7, checked over the whole 8×8-bit domain by the
            suite). The accumulator is inlined as that linear form and is never a column.
            **The rd term is gated by the family bit, not by the bracket**: on a shift row
            t1 and t2 are both 0, so a bare rd_selected would force rd = 0 and break every
            shift; with f_bitwise in front the gate is 0 = 0 there.
```

Of the 48 gates, 9 are degree 1: the two write-backs, `decoded_mask_bits`, the two flag rules,
`next_pc_rule`, `amount_split` and the two byte decompositions. All 48 have constant 0, so each
is 0 on the all-zero row, and the assembly records `zero_row_valid = true` (the dump's padding
contract) — which `assemble` asserts before returning.

### 5.6 The 39 lookups

`CircuitArtifact::lookups`, in order. The frame's 8 come from the private `memory::gap_lookups`;
the rest from `shift_bitwise::family_spec` (its private `range32`, `low_half`, `key_bound`,
`generic` and the inline `decode_row`). Fourteen `RANGE16` obligations are selected by `pc_mask`,
two by `f_shift` and eight by `f_bitwise`.

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `gap_hi_pc` | `TIMESTAMP` (0) | `M[1]` | `W[0]` | `pc_gap_hi` | `< 2^19` |
| 1 | `gap_lo_pc` | `TIMESTAMP` | `M[1]` | `4·M[0] − M[3] − 2^19·W[0] − 1` | `4·cycle − pc_read_ts − 2^19·pc_gap_hi − 1` | `< 2^19` |
| 2 | `gap_hi_rs1` | `TIMESTAMP` | `M[6]` | `W[1]` | `rs1_gap_hi` | `< 2^19` |
| 3 | `gap_lo_rs1` | `TIMESTAMP` | `M[6]` | `4·M[0] − M[8] − 2^19·W[1]` | `4·cycle − rs1_read_ts − 2^19·rs1_gap_hi` | `< 2^19` |
| 4 | `gap_hi_rs2` | `TIMESTAMP` | `M[11]` | `W[2]` | `rs2_gap_hi` | `< 2^19` |
| 5 | `gap_lo_rs2` | `TIMESTAMP` | `M[11]` | `4·M[0] − M[13] − 2^19·W[2] + 1` | `4·cycle − rs2_read_ts − 2^19·rs2_gap_hi + 1` | `< 2^19` |
| 6 | `gap_hi_rd` | `TIMESTAMP` | `M[16]` | `W[3]` | `rd_gap_hi` | `< 2^19` |
| 7 | `gap_lo_rd` | `TIMESTAMP` | `M[16]` | `4·M[0] − M[18] − 2^19·W[3] + 2` | `4·cycle − rd_read_ts − 2^19·rd_gap_hi + 2` | `< 2^19` |
| 8 | `rs1_hi_range` | `RANGE16` (1) | `M[1]` | `W[27]` | `rs1_hi` | `< 2^16` |
| 9 | `rs1_lo_range` | `RANGE16` | `M[1]` | `M[9] − 2^16·W[27]` | `rs1_read_value − 2^16·rs1_hi` | `< 2^16` |
| 10 | `src2_hi_range` | `RANGE16` | `M[1]` | `W[29]` | `src2_hi` | `< 2^16` |
| 11 | `src2_lo_range` | `RANGE16` | `M[1]` | `M[14] + W[11] − 2^16·W[29]` | `rs2_read_value + decoded_imm − 2^16·src2_hi` | `< 2^16` |
| 12 | `high_hi_range` | `RANGE16` | `M[1]` | `W[34]` | `high_hi` | `< 2^16` |
| 13 | `high_lo_range` | `RANGE16` | `M[1]` | `W[33] − 2^16·W[34]` | `high − 2^16·high_hi` | `< 2^16` |
| 14 | `ovf_hi_range` | `RANGE16` | `M[1]` | `W[39]` | `ovf_hi` | `< 2^16` |
| 15 | `ovf_lo_range` | `RANGE16` | `M[1]` | `W[38] − 2^16·W[39]` | `ovf − 2^16·ovf_hi` | `< 2^16` |
| 16 | `residue_hi_range` | `RANGE16` | `M[1]` | `W[41]` | `residue_hi` | `< 2^16` |
| 17 | `residue_lo_range` | `RANGE16` | `M[1]` | `W[40] − 2^16·W[41]` | `residue − 2^16·residue_hi` | `< 2^16` |
| 18 | `scaled_hi_range` | `RANGE16` | `M[1]` | `W[43]` | `scaled_hi` | `< 2^16` |
| 19 | `scaled_lo_range` | `RANGE16` | `M[1]` | `W[42] − 2^16·W[43]` | `scaled − 2^16·scaled_hi` | `< 2^16` |
| 20 | `rd_hi_range` | `RANGE16` | `M[1]` | `W[56]` | `rd_hi` | `< 2^16` |
| 21 | `rd_lo_range` | `RANGE16` | `M[1]` | `W[6] − 2^16·W[56]` | `rd_selected − 2^16·rd_hi` | `< 2^16` |
| 22 | `amount_range` | `RANGE16` | `W[25]` | `W[30]` | `amount` | `< 2^16` |
| 23 | `amount_scaled` | `RANGE16` | `W[25]` | `2048·W[30]` | `2^11·amount` | `< 2^16`, i.e. `amount < 2^5` |
| 24 | `byte_a0_range` | `RANGE16` | `W[26]` | `W[44]` | `byte_a0` | `< 2^16` |
| 25 | `byte_a0_scaled` | `RANGE16` | `W[26]` | `256·W[44]` | `2^8·byte_a0` | `< 2^16`, i.e. `byte_a0 < 2^8` |
| 26–31 | `byte_a1_range` … `byte_a3_scaled` | `RANGE16` | `W[26]` | `W[45]`, `256·W[45]`, `W[46]`, `256·W[46]`, `W[47]`, `256·W[47]` | the same pair per byte | `byte_a_j < 2^8` |
| 32 | `rs1_get_sign` | `GENERIC` (2) | `M[1]` | `(W[27] + 256, W[28], 0)` | `(rs1_hi + SIGN_BASE, rs1_sign, 0)` | the gated tuple `(rs1_hi + 257, rs1_sign, 0)` is a row of `S[7..10]` |
| 33 | `shift_powers` | `GENERIC` | `W[25]` | `(W[30] + 65792, W[31], W[32])` | `(amount + SHIFT_BASE, pow, copow)` | the gated tuple `(amount + 65793, pow, copow)` is a row of `S[7..10]` |
| 34 | `and_byte_0` | `GENERIC` | `W[26]` | `(W[44], W[48], W[52])` | `(byte_a0 + AND_BASE, byte_b0, byte_and0)` | the gated tuple `(byte_a0 + 1, byte_b0, byte_and0)` is a row of `S[7..10]` |
| 35–37 | `and_byte_1` … `and_byte_3` | `GENERIC` | `W[26]` | `(W[45], W[49], W[53])`, `(W[46], W[50], W[54])`, `(W[47], W[51], W[55])` | the same per byte | as 34 |
| 38 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[7], W[8], W[9], W[10], W[11], W[12])` | `(pc_read_value, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_imm, decoded_mask)` | a row of `S[0..7]` |

Read in pairs, as in §3.6 and §4.6: each `gap_hi`/`gap_lo` pair puts a read strictly before its
own write, and each `_hi_range`/`_lo_range` pair bounds `rs1_read_value`, `src2`, `high`, `ovf`,
`residue`, `scaled` and `rd_selected` below `2^32`.

**Ten of the 24 `RANGE16` obligations are key bounds, and they are the most important thing in
this family's accounting.** `lookup.md` §4 states the precondition — a family must bound the keys
it looks up — and with **three sub-tables packed into one channel** it is load-bearing in a way
it was not when the channel held one map each stage used: an out-of-range key does not *miss* the
table, it lands on **another sub-table's row**, and the lookup holds while the row means
something else entirely. This is a witness against an earlier draft of this circuit rather than a
hypothesis. A bitwise row claiming `byte_a0 = 65_823` produces the gated key `65_824`, which is
`ShiftPowers`' row for `s = 31`, `(65_824, 2^31, 1)`; the lookup then holds with
`byte_b0 = 2^31` and `byte_and0 = 1`, and with `rs1 = 65_823` and `rs2 = 2^31` — both ordinary
register values — the recomposition writes 1 for `and` where the answer is 0, and
`rs1 ^ rs2 − 2` for `xor`. Every other gate holds and both results are inside `[0, 2^32)`
(`shift-bitwise.md` §3.3; the suite's
`a_byte_key_outside_the_and_table_is_refused_by_its_own_bound`).

So each of the three keys this family looks up carries its own bound, and each bound is a
**pair** — the direct halfword check, and the column scaled so that the product is a halfword
only below the bound:

| key | sub-table | bound | obligations | under |
| --- | --- | --- | --- | --- |
| `rs1_hi + SIGN_BASE` | `U16GetSign` | `rs1_hi < 2^16` | 8, 9 — the 16+16 pair on `rs1` | `pc_mask` |
| `amount + SHIFT_BASE` | `ShiftPowers` | `amount < 2^5` | 22, 23 | `f_shift` |
| `byte_a_j + AND_BASE` | the AND byte table | `byte_a_j < 2^8` | 24–31, two per byte | `f_bitwise` |

Neither half of a pair is redundant. The **direct** half is the other half of S15's copower rule:
a scaled bound alone admits `k·2^(bits − 16)` for a small `k`, which is not a small integer at
all — `byte_a0 = 256` gates to 257, `U16GetSign`'s row for the halfword 0, and is below `2^16`,
so the direct half accepts it and the scaled half alone refuses it. The **scaled** half is what
turns a 16-bit table into a 5-bit or an 8-bit one. `lookup::check_copowers`, **tightened at
S18**, now takes each copower-scaled column with the selector its scaled obligation carries and
requires the direct pair under *that same* selector: S17 matched an obligation on its expression
alone, so a circuit whose direct pair sat under a narrower selector than its scaled obligation
passed while bounding nothing on the rows the narrow selector switches off
(`shift-bitwise.md` §3.4). `assemble` runs it over all six scaled columns — `residue` under
`pc_mask`, whose scale is the looked-up `copow`, and `amount` and the four byte keys under their
own selectors, whose scales are literals — and the unit test
`a_residue_bound_under_a_narrower_selector_fails_the_build` is that check firing.

Bounding the *key* is all that is needed. With `byte_a_j` below 256 the row it matches is an AND
row, and that row fixes `byte_b_j` below 256 and `byte_and_j` to `byte_a_j & byte_b_j`; with
`amount` below 32 the row is a `ShiftPowers` row, and that row fixes `pow` and `copow`.
**No gate bounds `amount` to `[0, 32)`; its key bound does, and `ShiftPowers`' domain again** —
the table's holding because `ShiftPowers` is the highest sub-table and a key past its last row
matches nothing at all. Which is why the suite's
`an_untruncated_amount_is_refused_by_its_scaled_bound_and_the_table` builds a row whose `amount`
is 33 with `pow = 2^33` and a copower of `2^-2`, so that `pow·copow` is still `2^31`, and finds
`amount_scaled` and the lookup refusing it together.

The channels, `shift_bitwise::channels()`, in output order:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[57]` | 8 | 16 |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[58]` | **24** | **32** |
| 6, 7 | `GENERIC` | 2 | `S[7..10]` | `W[59]` | 6 | 8 |
| 8, 9 | `DECODER` | 3 | `S[0..7]` | `W[60]` | 1 | 2 |

`artifact` asserts the four obligation counts. The `RANGE16` row is why this circuit is 26 gate
lists deep at `n = 20` where §3's and §4's are 25: 24 obligations plus one table fraction is 25
leaves, which pads to 32 and takes five row-wise levels instead of four.

### 5.7 Inner layers `L2`–`L6`: the row-wise reduction

The conventions are §3.7's. There are **five** row-wise reduction lists here, not four.

**`L2`, gate list 1, 62 columns, relations 172–233.**

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 172 | `read_2_0` | `read_pc · read_rs1` |
| 1 | 173 | `read_2_1` | `read_rs2 · read_rd` |
| 2 | 174 | `write_2_0` | `write_pc · write_rs1` |
| 3 | 175 | `write_2_1` | `write_rs2 · write_rd` |
| 4, 5 | 176, 177 | `timestamp_2_0` | `timestamp_table + gap_hi_pc` |
| 6, 7 | 178, 179 | `timestamp_2_1` | `gap_lo_pc + gap_hi_rs1` |
| 8, 9 | 180, 181 | `timestamp_2_2` | `gap_lo_rs1 + gap_hi_rs2` |
| 10, 11 | 182, 183 | `timestamp_2_3` | `gap_lo_rs2 + gap_hi_rd` |
| 12, 13 | 184, 185 | `timestamp_2_4` | `gap_lo_rd + timestamp_pad_0` |
| 14, 15 | 186, 187 | `timestamp_2_5` | `timestamp_pad_1 + timestamp_pad_2` |
| 16, 17 | 188, 189 | `timestamp_2_6` | `timestamp_pad_3 + timestamp_pad_4` |
| 18, 19 | 190, 191 | `timestamp_2_7` | `timestamp_pad_5 + timestamp_pad_6` |
| 20, 21 | 192, 193 | `range16_2_0` | `range16_table + rs1_hi_range` |
| 22, 23 | 194, 195 | `range16_2_1` | `rs1_lo_range + src2_hi_range` |
| 24, 25 | 196, 197 | `range16_2_2` | `src2_lo_range + high_hi_range` |
| 26, 27 | 198, 199 | `range16_2_3` | `high_lo_range + ovf_hi_range` |
| 28, 29 | 200, 201 | `range16_2_4` | `ovf_lo_range + residue_hi_range` |
| 30, 31 | 202, 203 | `range16_2_5` | `residue_lo_range + scaled_hi_range` |
| 32, 33 | 204, 205 | `range16_2_6` | `scaled_lo_range + rd_hi_range` |
| 34, 35 | 206, 207 | `range16_2_7` | `rd_lo_range + amount_range` |
| 36, 37 | 208, 209 | `range16_2_8` | `amount_scaled + byte_a0_range` |
| 38, 39 | 210, 211 | `range16_2_9` | `byte_a0_scaled + byte_a1_range` |
| 40, 41 | 212, 213 | `range16_2_10` | `byte_a1_scaled + byte_a2_range` |
| 42, 43 | 214, 215 | `range16_2_11` | `byte_a2_scaled + byte_a3_range` |
| 44, 45 | 216, 217 | `range16_2_12` | `byte_a3_scaled + range16_pad_0` |
| 46, 47 | 218, 219 | `range16_2_13` | `range16_pad_1 + range16_pad_2` |
| 48, 49 | 220, 221 | `range16_2_14` | `range16_pad_3 + range16_pad_4` |
| 50, 51 | 222, 223 | `range16_2_15` | `range16_pad_5 + range16_pad_6` |
| 52, 53 | 224, 225 | `generic_2_0` | `generic_table + rs1_get_sign` |
| 54, 55 | 226, 227 | `generic_2_1` | `shift_powers + and_byte_0` |
| 56, 57 | 228, 229 | `generic_2_2` | `and_byte_1 + and_byte_2` |
| 58, 59 | 230, 231 | `generic_2_3` | `and_byte_3 + generic_pad_0` |
| 60, 61 | 232, 233 | `decoder_2_0` | `decoder_table + decode_row` |

Positionally, `range16_2_8` is `L{2}[36] = L{1}[72]·L{1}[75] + L{1}[74]·L{1}[73]` and
`L{2}[37] = L{1}[73]·L{1}[75]`: `1/(E_amount_scaled + g) + 1/(E_byte_a0_range + g)`, two
obligations under two different selectors added as ordinary fractions — the tree does not know
that one is off wherever the other is on.

**`L3`, gate list 2, 32 columns, relations 234–265.**

| `L3` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 234 | `read_3_0` | `read_2_0 · read_2_1` |
| 1 | 235 | `write_3_0` | `write_2_0 · write_2_1` |
| 2, 3 | 236, 237 | `timestamp_3_0` | `timestamp_2_0 + timestamp_2_1` |
| 4, 5 | 238, 239 | `timestamp_3_1` | `timestamp_2_2 + timestamp_2_3` |
| 6, 7 | 240, 241 | `timestamp_3_2` | `timestamp_2_4 + timestamp_2_5` |
| 8, 9 | 242, 243 | `timestamp_3_3` | `timestamp_2_6 + timestamp_2_7` |
| 10, 11 | 244, 245 | `range16_3_0` | `range16_2_0 + range16_2_1` |
| 12, 13 | 246, 247 | `range16_3_1` | `range16_2_2 + range16_2_3` |
| 14, 15 | 248, 249 | `range16_3_2` | `range16_2_4 + range16_2_5` |
| 16, 17 | 250, 251 | `range16_3_3` | `range16_2_6 + range16_2_7` |
| 18, 19 | 252, 253 | `range16_3_4` | `range16_2_8 + range16_2_9` |
| 20, 21 | 254, 255 | `range16_3_5` | `range16_2_10 + range16_2_11` |
| 22, 23 | 256, 257 | `range16_3_6` | `range16_2_12 + range16_2_13` |
| 24, 25 | 258, 259 | `range16_3_7` | `range16_2_14 + range16_2_15` |
| 26, 27 | 260, 261 | `generic_3_0` | `generic_2_0 + generic_2_1` |
| 28, 29 | 262, 263 | `generic_3_1` | `generic_2_2 + generic_2_3` |
| 30, 31 | 264, 265 | `decoder_3_0` | copy of `decoder_2_0` |

**`L4`, gate list 3, 18 columns, relations 266–283.**

| `L4` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 266 | `read_4_0` | copy of `read_3_0` |
| 1 | 267 | `write_4_0` | copy of `write_3_0` |
| 2, 3 | 268, 269 | `timestamp_4_0` | `timestamp_3_0 + timestamp_3_1` |
| 4, 5 | 270, 271 | `timestamp_4_1` | `timestamp_3_2 + timestamp_3_3` |
| 6, 7 | 272, 273 | `range16_4_0` | `range16_3_0 + range16_3_1` |
| 8, 9 | 274, 275 | `range16_4_1` | `range16_3_2 + range16_3_3` |
| 10, 11 | 276, 277 | `range16_4_2` | `range16_3_4 + range16_3_5` |
| 12, 13 | 278, 279 | `range16_4_3` | `range16_3_6 + range16_3_7` |
| 14, 15 | 280, 281 | `generic_4_0` | `generic_3_0 + generic_3_1` |
| 16, 17 | 282, 283 | `decoder_4_0` | copy of `decoder_3_0` |

**`L5`, gate list 4, 12 columns, relations 284–295.**

| `L5` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 284 | `read_5_0` | copy of `read_4_0` |
| 1 | 285 | `write_5_0` | copy of `write_4_0` |
| 2, 3 | 286, 287 | `timestamp_5_0` | `timestamp_4_0 + timestamp_4_1` |
| 4, 5 | 288, 289 | `range16_5_0` | `range16_4_0 + range16_4_1` |
| 6, 7 | 290, 291 | `range16_5_1` | `range16_4_2 + range16_4_3` |
| 8, 9 | 292, 293 | `generic_5_0` | copy of `generic_4_0` |
| 10, 11 | 294, 295 | `decoder_5_0` | copy of `decoder_4_0` |

**`L6`, gate list 5, 10 columns, relations 296–305** — the row-wise top: one value per row per
tree. Every tree but `range16` has finished and is copied up one more time than in §3 and §4.

| `L6` | relations | node | formula | value at row `y` |
| --- | --- | --- | --- | --- |
| 0 | 296 | `read_6_0` | copy of `read_5_0` | the product of row `y`'s 4 read leaves |
| 1 | 297 | `write_6_0` | copy of `write_5_0` | the product of row `y`'s 4 write leaves |
| 2, 3 | 298, 299 | `timestamp_6_0` | copy of `timestamp_5_0` | the sum of row `y`'s 16 timestamp fractions |
| 4, 5 | 300, 301 | `range16_6_0` | `range16_5_0 + range16_5_1` | the sum of row `y`'s 32 range16 fractions |
| 6, 7 | 302, 303 | `generic_6_0` | copy of `generic_5_0` | the sum of row `y`'s 8 generic fractions |
| 8, 9 | 304, 305 | `decoder_6_0` | copy of `decoder_5_0` | the sum of row `y`'s 2 decoder fractions |

### 5.8 The halving layers and the outputs

Gate list `k`, for `6 ≤ k ≤ n + 5`, halves layer `k` into layer `k + 1`, which has
`n + 5 − k` variables. Its ten gates, relation `r = 306 + 10(k − 6)`, with §3.8's formulas:

| `L{k+1}` | relation | node | shape |
| --- | --- | --- | --- |
| 0 | `r` | `read_{k+1}_0` | `TreeProduct { L{k}[0] }` |
| 1 | `r + 1` | `write_{k+1}_0` | `TreeProduct { L{k}[1] }` |
| 2 | `r + 2` | `timestamp_{k+1}_0_num` | `TreeCross { L{k}[2], L{k}[3] }` |
| 3 | `r + 3` | `timestamp_{k+1}_0_den` | `TreeProduct { L{k}[3] }` |
| 4 | `r + 4` | `range16_{k+1}_0_num` | `TreeCross { L{k}[4], L{k}[5] }` |
| 5 | `r + 5` | `range16_{k+1}_0_den` | `TreeProduct { L{k}[5] }` |
| 6 | `r + 6` | `generic_{k+1}_0_num` | `TreeCross { L{k}[6], L{k}[7] }` |
| 7 | `r + 7` | `generic_{k+1}_0_den` | `TreeProduct { L{k}[7] }` |
| 8 | `r + 8` | `decoder_{k+1}_0_num` | `TreeCross { L{k}[8], L{k}[9] }` |
| 9 | `r + 9` | `decoder_{k+1}_0_den` | `TreeProduct { L{k}[9] }` |

In the last list, `k = n + 5`, the ten nodes are named `read_root`, `write_root`,
`timestamp_num_root`, `timestamp_den_root`, `range16_num_root`, `range16_den_root`,
`generic_num_root`, `generic_den_root`, `decoder_num_root` and `decoder_den_root`. At `n = 20`
the halving lists are 6 to 25, `L7` has 19 variables and `L26` none. At `n = 22` they are 6 to
27, and the top is `L28`.

**The outputs**, in output-map order. All ten are absorbed as one `GKR_OUTPUTS` message before
any challenge of the backward pass, and travel in `ShardProof::outputs`.

| # | address, `n = 20` | node | value | what `verify_shard` does with it |
| --- | --- | --- | --- | --- |
| 0 | `L{26}[0]` | `read_root` | the product of every read leaf of the shard | step 10: must equal `PublicInputs::memory_roots[p][0]`, `p` being the position of `(2, shard_index)` in `verifier_core::statement_shards`, after `INIT_TEARDOWN`'s shard, every `ZERO_WINDOWS` shard and every `ADD_SUB_LUI_AUIPC` and `JUMP_BRANCH_SLT` shard (`shard-proof.md` §1.2); 3 in S18's statement; a factor of `reconciles` |
| 1 | `L{26}[1]` | `write_root` | the product of every write leaf | step 10: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |
| 2 | `L{26}[2]` | `timestamp_num_root` | as §3.8's output 2 | step 9: must be 0; otherwise `Lookup { channel: 0 }` |
| 3 | `L{26}[3]` | `timestamp_den_root` | as §3.8's output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 0 }` |
| 4 | `L{26}[4]` | `range16_num_root` | as output 2, for `RANGE16` | step 9: must be 0; otherwise `Lookup { channel: 1 }` |
| 5 | `L{26}[5]` | `range16_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 1 }` |
| 6 | `L{26}[6]` | `generic_num_root` | as output 2, for `GENERIC` | step 9: must be 0; otherwise `Lookup { channel: 2 }` |
| 7 | `L{26}[7]` | `generic_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 2 }` |
| 8 | `L{26}[8]` | `decoder_num_root` | as output 2, for `DECODER` | step 9: must be 0; otherwise `Lookup { channel: 3 }` |
| 9 | `L{26}[9]` | `decoder_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 3 }` |

### 5.9 Witness rows

The table shows eight of the 34 live `honest_rows` in `crates/checker/tests/shift_bitwise.rs`,
and the padding row. The other 26 are the remaining kinds over mixed patterns; `slli`, `srli`
and `srai` at shamt 0, 1 and 31; `sll`, `srl` and `sra` by `rs2 = 32`, `33` and `0xffffffff`,
which truncate to 0, 1 and 31; a small-operand `sll by rs2 = 33`, whose doubled word still fits a
32-bit `ovf`; `andi into x0`; and a compressed `srli`, whose fall-through is `pc + 2`. Each row is
built from Rust's own `u32` and `i32` arithmetic, and
`every_row_kind_satisfies_every_gate_and_every_bound` holds it to every gate, every range
obligation and both table channels in CI: the suite's `violated_tables` checks a generic tuple
against `program::lookup_tables::generic_entries` and a decoder tuple against the row's own
`S[0..7]`.

A row is checked alone, as §3.9's and §4.9's are: each register query reads a write made eight
timestamps before its own and the pc query the previous cycle's, so every `<q>_gap_hi` is 0; the
multiplicities are 0; `S[0..7]` hold the row's own table entry and `S[7..10]` are 0, and the
table below omits them. Every live row shown has cycle 7, pc `0x1000` and a 4-byte instruction,
`rs1` is `x5`, `rs2` is `x6` on an R-type row and `x0` on an I-type one, `rd` is `x7`, and `P` is
0 in every cell.

`A` `slli x7, x5, 3` with `x5 = 0x12345679`. `B` `srai x7, x5, 3` with `x5 = 0xfedcba98`.
`C` `sll x7, x5, x6` with `x5 = 0x12345679`, `x6 = 4`. `D` `sra x7, x5, x6` with
`x5 = 0xfedcba99`, `x6 = 33`, which truncates to 1. `E` `and x7, x5, x6` with
`x5 = 0xf0f00ff0`, `x6 = 0x0ff0f00f`. `F` `xori x7, x5, -1` with `x5 = 0x12345678`.
`G` `slli x0, x5, 3` with `x5 = 0x12345679`: computes, writes nothing. `H` `or x7, x0, x6` with
`x6 = 0x0ff0f00f`: an `x0` operand, which reads 0. `P` padding.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[2]` `pc_addr` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `M[3]` `pc_read_ts` | 24 | 24 | 24 | 24 | 24 | 24 | 24 | 24 | 0 |
| `M[4]` `pc_read_value` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | 0 |
| `M[5]` `pc_write_value` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | 0 |
| `M[6]` `rs1_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[7]` `rs1_addr` | 5 | 5 | 5 | 5 | 5 | 5 | 5 | 0 | 0 |
| `M[8]` `rs1_read_ts` | 21 | 21 | 21 | 21 | 21 | 21 | 21 | 21 | 0 |
| `M[9]`, `M[10]` `rs1_read_value`, `rs1_write_value` | `0x12345679` | `0xfedcba98` | `0x12345679` | `0xfedcba99` | `0xf0f00ff0` | `0x12345678` | `0x12345679` | 0 | 0 |
| `M[11]` `rs2_mask` | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 1 | 0 |
| `M[12]` `rs2_addr` | 0 | 0 | 6 | 6 | 6 | 0 | 0 | 6 | 0 |
| `M[13]` `rs2_read_ts` | 0 | 0 | 22 | 22 | 22 | 0 | 0 | 22 | 0 |
| `M[14]`, `M[15]` `rs2_read_value`, `rs2_write_value` | 0 | 0 | 4 | 33 | `0x0ff0f00f` | 0 | 0 | `0x0ff0f00f` | 0 |
| `M[16]` `rd_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[17]` `rd_addr` | 7 | 7 | 7 | 7 | 7 | 7 | 0 | 7 | 0 |
| `M[18]` `rd_read_ts` | 23 | 23 | 23 | 23 | 23 | 23 | 23 | 23 | 0 |
| `M[19]` `rd_read_value` | `0x11111111` | `0x11111111` | `0x11111111` | 0 | `0x11111111` | `0x11111111` | 0 | 0 | 0 |
| `M[20]` `rd_write_value` | `0x91a2b3c8` | `0xffdb9753` | `0x23456790` | `0xff6e5d4c` | `0x00f00000` | `0xedcba987` | 0 | `0x0ff0f00f` | 0 |
| `W[0..4]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[4]` `rd_inv` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | 0 | `7⁻¹` | 0 |
| `W[5]` `rd_is_zero` | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `W[6]` `rd_selected` | `0x91a2b3c8` | `0xffdb9753` | `0x23456790` | `0xff6e5d4c` | `0x00f00000` | `0xedcba987` | `0x91a2b3c8` | `0x0ff0f00f` | 0 |
| `W[7]` `decoded_next_pc` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | 0 |
| `W[8]` `decoded_rs1` | 5 | 5 | 5 | 5 | 5 | 5 | 5 | 0 | 0 |
| `W[9]` `decoded_rs2` | 0 | 0 | 6 | 6 | 6 | 0 | 0 | 6 | 0 |
| `W[10]` `decoded_rd` | 7 | 7 | 7 | 7 | 7 | 7 | 0 | 7 | 0 |
| `W[11]` `decoded_imm` | 3 | 3 | 0 | 0 | 0 | `0xffffffff` | 3 | 0 | 0 |
| `W[12]` `decoded_mask` | 1 | 8 | `0x40` | `0x200` | `0x800` | 2 | 1 | `0x400` | 0 |
| `W[13..25]` the kind bit set | `slli` | `srai` | `sll` | `sra` | `and` | `xori` | `slli` | `or` | none |
| `W[25]` `f_shift` | 1 | 1 | 1 | 1 | 0 | 0 | 1 | 0 | 0 |
| `W[26]` `f_bitwise` | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 1 | 0 |
| `W[27]` `rs1_hi` | `0x1234` | `0xfedc` | `0x1234` | `0xfedc` | `0xf0f0` | `0x1234` | `0x1234` | 0 | 0 |
| `W[28]` `rs1_sign` | 0 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 |
| `W[29]` `src2_hi` | 0 | 0 | 0 | 0 | `0x0ff0` | `0xffff` | 0 | `0x0ff0` | 0 |
| `W[30]` `amount` | 3 | 3 | 4 | 1 | 15 | 31 | 3 | 15 | 0 |
| `W[31]` `pow` | 8 | 8 | 16 | 2 | 0 | 0 | 8 | 0 | 0 |
| `W[32]` `copow` | `2^28` | `2^28` | `2^27` | `2^30` | 0 | 0 | `2^28` | 0 | 0 |
| `W[33]` `high` | 0 | 0 | 0 | 1 | `0x7f8780` | `0x07ffffff` | 0 | `0x7f8780` | 0 |
| `W[34]` `high_hi` | 0 | 0 | 0 | 0 | `0x7f` | `0x07ff` | 0 | `0x7f` | 0 |
| `W[35]` `se` | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `W[36]` `shift_in` | `0x12345679` | `−2386093` | `0x12345679` | `−9544372` | 0 | 0 | `0x12345679` | 0 | 0 |
| `W[37]` `shift_prod` | `0x91a2b3c8` | `−19088744` | `0x123456790` | `−19088744` | 0 | 0 | `0x91a2b3c8` | 0 | 0 |
| `W[38]` `ovf` | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[40]` `residue` | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `W[42]` `scaled` | 0 | 0 | 0 | `0x80000000` | 0 | 0 | 0 | 0 | 0 |
| `W[43]` `scaled_hi` | 0 | 0 | 0 | `0x8000` | 0 | 0 | 0 | 0 | 0 |
| `W[44..48]` `byte_a0..3` | `79 56 34 12` | `98 ba dc fe` | `79 56 34 12` | `99 ba dc fe` | `f0 0f f0 f0` | `78 56 34 12` | `79 56 34 12` | `00 00 00 00` | 0 |
| `W[48..52]` `byte_b0..3` | `03 00 00 00` | `03 00 00 00` | `04 00 00 00` | `21 00 00 00` | `0f f0 f0 0f` | `ff ff ff ff` | `03 00 00 00` | `0f f0 f0 0f` | 0 |
| `W[52..56]` `byte_and0..3` | `01 00 00 00` | `00 00 00 00` | `00 00 00 00` | `01 00 00 00` | `00 00 f0 00` | `78 56 34 12` | `01 00 00 00` | `00 00 00 00` | 0 |
| `W[56]` `rd_hi` | `0x91a2` | `0xffdb` | `0x2345` | `0xff6e` | `0x00f0` | `0xedcb` | `0x91a2` | `0x0ff0` | 0 |

`W[39]` `ovf_hi`, `W[41]` `residue_hi` are 0 on all nine and are omitted; `shift_in` and
`shift_prod` are written as signed integers, their field values being `p − |v|` where negative.

`A` is the plain left shift: `0x12345679 · 8` is below `2^32`, so `ovf` is 0 and the whole
product is the result. `C` is the same shift by 4, whose product `0x123456790` overflows a word:
`ovf = 1` and `rd` is the low half. `B` and `D` are the arithmetic right shifts, where `se = 1`
carries the sign into both `shift_in` and `shift_out_rule`'s right arm; `D`'s `rs2` is 33, which
`amount_split` truncates to 1 with `high = 1`, and its residue 1 is the dropped bit, scaled by
`2·copow = 2^31`. `E` and `F` are the bitwise rows: `pow` and `copow` are 0, `shift_in` and
`shift_prod` are 0, and `amount` keeps its honest value with `ShiftPowers` switched off. `F`
shows XOR derived from AND alone — its four `byte_and` are `rs1`'s own bytes, because
`byte_b_j = 0xff` — and `rd = rs1 + src2 − 2·Σ 2^(8j)·and_j` is `0xedcba987`. `G` computes
`0x91a2b3c8` into `rd_selected` and writes 0: the x0 rule masks it, and `rd_inv` is 0 at address
0. `H`'s `rs1` is `x0`, a present query at address 0 reading 0, so `or` returns `src2`.

### 5.10 What fixes each cell

The per-cell accounting is `crates/checker/tests/shift_bitwise.rs`' own, and it is a committed
one: `each_gate_is_the_one_that_refuses_its_row` carries 25 tampers, each an edit to a named
honest row beside **the exact set** of relations that refuse it, asserted equal — not a
membership — so a gate that stopped being load-bearing on the row shape it exists for fails the
suite. The table below is that list read as a cell-by-cell account, with the two address tampers
on one line. `every_booleanity_gate_refuses_a_value_of_two` adds the sixteen booleans this
family commits — the twelve kind bits, the two half flags, `rs1_sign` and `se` — and six
further tests isolate one bound or one gate each. §5.5's 171 derives `or` and `xor` from the one
AND accumulator by linearity, so the AND table is the only one either reads.

| cell moved | on the row | refused by, exactly |
| --- | --- | --- |
| `decoded_mask` | `slli 3`, claiming `srli`'s mask | `decoded_mask_bits` |
| `f_shift` → 0 | `slli 3`, switching `ShiftPowers` off | `f_shift_rule`, `copower_rule` |
| `f_bitwise` → 0 | `and to zero`, switching the byte table off | `f_bitwise_rule` |
| `rs1_mask` (query dropped) | `or with an x0 operand` | `rs1_mask_rule` |
| `rs2_mask` (query added) | `slli 3` | `rs2_mask_rule` |
| `rd_mask` (query dropped) | `and to zero` | `rd_mask_rule` |
| `rs1_addr`, `rs2_addr` `+ 1` | `sll` | `rs1_addr_rule`, `rs2_addr_rule` |
| `rd_addr` → 5 | `slli 3` | `rd_addr_rule` |
| `rs1_read_value` → 5 | padding | `rs1_value_masked` |
| `rs2_read_value` → 32 | `slli 0`, whose shift by `32 mod 32 = 0` is unchanged by it | `rs2_value_masked` |
| `pc_write_value` `+ 4` | `slli 3` | `next_pc_rule` |
| `amount` → 2, with `pow`, `copow`, `shift_prod`, `ovf` and the result moved to match | `slli 3` | `amount_split` |
| `copow` halved, with `scaled` halved so its own pair still holds | `srli 3` | `copower_rule` |
| `kind_sra` → `kind_srl`, mask and all | an honest `sra` | `se_rule` |
| `shift_in` → 5 | `and`, where `pow` is 0 | `shift_in_rule` |
| `shift_prod` → 5 | `and` | `shift_prod_rule` |
| `shift_prod` `+ 8`, carried into the result | `slli 3` | `shift_prod_rule` |
| `rd_selected` `+ 2^16`, `rd_hi` moved with it | `slli 3` | `shift_out_rule` |
| `scaled` `+ 1` | `srli 3` | `scaled_rule` |
| `byte_a0` `+ 1` | `and` | `rs1_bytes` |
| `byte_b0` `+ 1` | `and` | `src2_bytes` |
| `rd_selected` → the AND accumulator | `or` | `bitwise_out_rule` |
| an `rd` query rewriting `x10` | padding | `rd_mask_rule`, `rd_addr_rule` |
| the same, dressed as `or` with `decoded_rd = 10` and a written 0 | padding | `rd_mask_rule` |

What no gate refuses, and what does:

- **`amount` above 31**: nothing in gate list 0, and not `amount_range` either, 33 being a
  perfectly good halfword. `amount_scaled` refuses it and so does `ShiftPowers`' domain, which is
  the point of `an_untruncated_amount_is_refused_by_its_scaled_bound_and_the_table` — an `sll by
  rs2 = 33, small rs1` row claiming to shift by 33, with `pow = 2^33` and a copower of `2^-2` so
  that `copower_rule` still holds, an `ovf` of `rs1·2` that is still a word, and a result of 0.
  Every gate accepts it; the two obligations on its key are the refusal.
- **A byte key above 255**: the key bound of §5.6 and nothing else. At `byte_a0 = 256` the scaled
  half alone refuses (256 is a perfectly good halfword); at `byte_a0 = 65_823` both halves do.
- **A shamt claimed different from `src2 mod 32`**: `amount_split` with `high`'s pair, which is
  the only integer witness (`the_shamt_is_not_free_and_the_high_chunks_bound_is_what_closes_it`).
- **A residue at or above `2^amount`**: the scaled pair alone — `residue`'s own direct pair
  accepts 24 on a shift by 4, and so does `shift_out_rule` with the quotient one too low.
- **A residue that is not an integer**: `residue`'s **direct** pair alone on a left shift, where
  `shift_out_rule` does not read it; on a right shift the two direct pairs on `residue` and
  `rd_selected` together, the non-integer residue dragging the result out of the word with it.
  The scaled pair is in neither set, which is `check_copowers`' whole reason for existing.

On a padding row `pc_mask = 0`, every frame mask is 0, every leaf is 1 and every obligation under
`pc_mask` is vacuous. `f_shift` and `f_bitwise` are **free booleans** there, so a padding row may
look `ShiftPowers` or the byte table up; it consumes a table multiplicity, which the honest
prover's recount covers, and changes nothing, the `rd` query being absent. With every kind bit 0
the gates hold `rd_selected` — through `bitwise_out_rule` under a claimed `f_bitwise` — and
`shift_in`, `shift_prod`, `se`, `pc_write_value − decoded_next_pc` and `pow·copow` to 0, and
leave `amount`, `high` and the eight byte columns free subject to the two decompositions and the
split. The honest fill writes 0 everywhere.

---

## 6. `MUL_DIV` — family 3

### 6.1 Header

`family_circuit(3, n)` is `mul_div::artifact(n)` with `mul_div::channels()`, built by
`memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` through the private
`family_spec`, whose arithmetic half is the public `mul_div::arithmetic_gates(WORD_BITS)` — the
**width seam** S18's exhaustive reduced-width check drives, as `gadgets::comparison_equation` is
at S17. It uses one S17 gadget, `gadgets::is_zero`, twice in its own arithmetic — beside the
frame's x0 rule, which `memory` builds on the same gadget — and deliberately not
`gadgets::comparison`: its magnitude bound is a directly range-checked gap, which is where the
zero-divisor correction lives and which the comparison gadget's operand range pairs and two sign
lookups would only duplicate (`mul-div.md` decision 1). Normative spec: `mul-div.md`. Fill:
`prover::family_fill(3)`, the private `fill::mul_div`.

84 committed columns (21 `M`, 54 `W`, **9** `S`) and two virtual tables. Gate list 0 writes 116
leaves and holds 54 enforcing gates. 27 lookups on four channels, 10 outputs. At `n = 20`, the
height S18 proves, there are 26 gate lists, the top is `L26`, and the circuit has 444 inner
columns and 498 relations; a shard proof of it is 67,412 bytes (`crates/prover/tests/alu.rs`).
It is 26 lists deep for a different reason than §5's: **its `range16` tree carries 16
obligations, so with its table fraction it is 17 leaves and pads to 32** — one leaf past the
16-leaf trees of §3 and §4.

**This family's decoded tuple has no immediate, and that is visible everywhere.** RV32M is all
R-type, so `program::lookup_tuple(3)` is `pc next_pc rs1 rs2 rd extra_mask` — **six columns, not
seven** — which makes `mul_div::TABLE_WIDTH` 6, the claimed decoded row five columns
(`W[7..12]`), the decoder tuple six wide, the setup subtree **nine** columns where a family
carrying both an immediate and the packed table commits ten, the packed generic table `S[6..9]`
rather than `S[7..10]`, and the decoder denominator's top `β` power `β⁵` rather than `β⁶`
(§0.4). Since S19 it shares that shape with `ATOMICS` (§9), whose tuple has no immediate for
the same reason — RV32A is all R-type — so the two of them are the registered circuits whose
`g_dec` is `g − Σ_{j<6} β^j`.

`artifact` panics unless the frame is `QUERIES`, the channels carry exactly 8, 16, 2 and 1
obligations, and every gate is zero on the all-zero row. `arithmetic_gates` panics unless its
width is between 1 and 32. `artifact` also panics on every refusal of the assembly, among them
`n < 19` and `n > 30`; `family_circuit` returns `None` for both rather than calling it.

### 6.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::mul_div`, bit `k` being `W[12 + k]`.
**Every one of the eight is R-type**: it reads `rs1` and `rs2` and writes `rd`, so all three mask
rules are `m_pc·Σ(all eight bits)` and the queries present are the same on every live row.
`next_pc` is the fall-through, always `pc + 4`: the M extension has no compressed form.

| row kind | bit (`decoded_mask`) | `s1` | `s2` | `f_div` | `mx` | `my` | `rd_selected` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mul` | 0 (1) | `rs1_top` | `rs2_top` | 0 | `rs1_adj` | `rs2_adj` | `p_low` |
| `mulh` | 1 (2) | `rs1_top` | `rs2_top` | 0 | `rs1_adj` | `rs2_adj` | `p_high` |
| `mulhsu` | 2 (4) | `rs1_top` | 0 | 0 | `rs1_adj` | `rs2` | `p_high` |
| `mulhu` | 3 (8) | 0 | 0 | 0 | `rs1` | `rs2` | `p_high` |
| `div` | 4 (16) | `rs1_top` | `rs2_top` | 1 | `rs2_adj` | `q_adj` | `q` |
| `divu` | 5 (32) | 0 | 0 | 1 | `rs2` | `q_adj` | `q` |
| `rem` | 6 (64) | `rs1_top` | `rs2_top` | 1 | `rs2_adj` | `q_adj` | `r` |
| `remu` | 7 (128) | 0 | 0 | 1 | `rs2` | `q_adj` | `r` |
| padding | none; all 0 | 0 | 0 | a free boolean | 0 | 0 | 0 |

`rs1_adj = rs1 − 2^32·s1` and `rs2_adj = rs2 − 2^32·s2`; `q_adj = q − 2^32·q_sign` and
`r_adj = r − 2^32·r_sign`. `mul` is listed as signed × signed: its low half is the same read
either way, so the choice is free, and taking it signed is what lets **one** product identity
serve all four multiplies. `mulhsu` is the asymmetric one — `rs1` signed, `rs2` not — which the
two separate flag lists (`LHS_SIGNED`, `RHS_SIGNED`) express and no case split does. An
**unsigned position forces its flag to 0** whatever the operand's top bit, which is what keeps
the selection degree 2.

Every kind is provable at S18. **No kind computes a pc**: `next_pc` is the decoded fall-through,
so this family, like §5's, needs no wrap bit and cannot reach `HALT_PC`. `rd = x0` is not a kind.
A live row at a pc holding no instruction of the family meets the table's `MINUS_ONE` row, which
its decoder tuple cannot equal.

### 6.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §6.4 and §6.6.

**Memory-argument columns, `M[0..21]`** — §2's REG layout (`w = 4`), the same 21 columns and the
same bare frame fixture (`memory_frame_reg.bin`) as §4's and §5's, filled by
`trace::build_memory_columns`; committed in `PublicInputs::memory_commitments`, absorbed at G8
before the memory challenges. `M[0..9]`, `M[10..14]`, `M[15..21]` and their frame gates are
§5.3's, address for address; the "read by" column below differs only where this family's own
gates read one.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the cycle `c` | leaves `write_*` (all 4); obligations `gap_lo_*` (all 4) |
| `M[1]` | `pc_mask` | `frame(0, FIELD_MASK)` | Row is live | 1 | leaves `read_pc`, `write_pc`; `pc_mask_boolean`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`; selector of `gap_hi_pc`, `gap_lo_pc`, all sixteen `RANGE16` obligations, both `GENERIC` lookups and `decode_row` |
| `M[2]` | `pc_addr` | `frame(0, FIELD_ADDR)` | PC address | 0 | leaves `read_pc`, `write_pc` |
| `M[3]` | `pc_read_ts` | `frame(0, FIELD_READ_TS)` | Previous pc write | `4(c − 1)` | leaf `read_pc`; `gap_lo_pc` |
| `M[4]` | `pc_read_value` | `frame(0, FIELD_READ_VALUE)` | Current pc | the instruction's pc | leaf `read_pc`; `decode_row` position 0 |
| `M[5]` | `pc_write_value` | `frame(0, FIELD_WRITE_VALUE)` | Next pc | `pc + 4` | leaf `write_pc`; `next_pc_rule` |
| `M[6]` | `rs1_mask` | `frame(1, FIELD_MASK)` | rs1 present | 1 on every kind | leaves `read_rs1`, `write_rs1`; `rs1_mask_boolean`, `rs1_mask_rule`, `rs1_addr_rule`, `rs1_value_masked`; selector of `gap_hi_rs1`, `gap_lo_rs1` |
| `M[7]` | `rs1_addr` | `frame(1, FIELD_ADDR)` | rs1 register | the decoded `rs1` | leaves `read_rs1`, `write_rs1`; `rs1_addr_rule` |
| `M[8]` | `rs1_read_ts` | `frame(1, FIELD_READ_TS)` | rs1 previous write | | leaf `read_rs1`; `gap_lo_rs1` |
| `M[9]` | `rs1_read_value` | `frame(1, FIELD_READ_VALUE)` | rs1; a multiply's left operand, a division's dividend | | leaf `read_rs1`; `rs1_writes_back`, `rs1_value_masked`, `mx_rule`, `division_rule`; `rs1_lo_range` |
| `M[10]` | `rs1_write_value` | `frame(1, FIELD_WRITE_VALUE)` | rs1 written back | `rs1_read_value` | leaf `write_rs1`; `rs1_writes_back` |
| `M[11]` | `rs2_mask` | `frame(2, FIELD_MASK)` | rs2 present | 1 on every kind | leaves `read_rs2`, `write_rs2`; `rs2_mask_boolean`, `rs2_mask_rule`, `rs2_addr_rule`, `rs2_value_masked`; selector of `gap_hi_rs2`, `gap_lo_rs2` |
| `M[12]` | `rs2_addr` | `frame(2, FIELD_ADDR)` | rs2 register | the decoded `rs2` | leaves `read_rs2`, `write_rs2`; `rs2_addr_rule` |
| `M[13]` | `rs2_read_ts` | `frame(2, FIELD_READ_TS)` | rs2 previous write | | leaf `read_rs2`; `gap_lo_rs2` |
| `M[14]` | `rs2_read_value` | `frame(2, FIELD_READ_VALUE)` | rs2; a multiply's right operand, a division's **divisor** | | leaf `read_rs2`; `rs2_writes_back`, `rs2_value_masked`, `mx_rule`, `my_rule`, `dz_inverse`, `dz_at_nonzero`, `abs_d_rule`; `rs2_lo_range` |
| `M[15]` | `rs2_write_value` | `frame(2, FIELD_WRITE_VALUE)` | rs2 written back | `rs2_read_value` | leaf `write_rs2`; `rs2_writes_back` |
| `M[16]` | `rd_mask` | `frame(3, FIELD_MASK)` | rd present | 1 on every kind | leaves `read_rd`, `write_rd`; `rd_mask_boolean`, `rd_is_zero_inverse`, `rd_mask_rule`, `rd_addr_rule`; selector of `gap_hi_rd`, `gap_lo_rd` |
| `M[17]` | `rd_addr` | `frame(3, FIELD_ADDR)` | rd register | the decoded `rd` | leaves `read_rd`, `write_rd`; `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_addr_rule` |
| `M[18]` | `rd_read_ts` | `frame(3, FIELD_READ_TS)` | rd previous write | | leaf `read_rd`; `gap_lo_rd` |
| `M[19]` | `rd_read_value` | `frame(3, FIELD_READ_VALUE)` | rd old value | | leaf `read_rd` |
| `M[20]` | `rd_write_value` | `frame(3, FIELD_WRITE_VALUE)` | rd new value | `rd_selected`, or 0 into `x0` | leaf `write_rd`; `rd_write_masked` |

The frame's slots in `mul_div.rs` are `SLOT_PC = 0` through `SLOT_RD = 3`. `rs2_read_value` is
the most-read column of the family: it is a multiplicand, the is-zero gadget's subject, the
divisor whose magnitude the gap bounds, and a range-checked word.

**Witness columns, `W[0..54]`** — `W[0..6]` filled by `trace::build_frame_witness`, `W[6..50]`
by `fill::mul_div` (`W[6]` in place of S14's), `W[50..54]` by `trace::build_multiplicities`
inside `prover::shard_columns`; committed in `ShardProof::witness_commitments`, absorbed at S3
before `g` and `β`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0..4]` | `pc_gap_hi` … `rd_gap_hi` | `memory::gap_hi(s)` | gap high chunks | `gap >> 19`; the pc's is always 0 | `gap_hi_<q>`, `gap_lo_<q>` |
| `W[4]` | `rd_inv` | `memory::rd_inv(4)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[5]` | `rd_is_zero` | `memory::rd_is_zero(4)` | rd is `x0` | | `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_is_zero_boolean`, `rd_write_masked` |
| `W[6]` | `rd_selected` | `memory::rd_selected(4)`; `sel` in `mul_div.rs` | Result | the half, quotient or remainder the kind takes, `rd = x0` included: the fill overwrites the 0 S14's builder writes there | `rd_write_masked`, `rd_value_rule`; `rd_lo_range` |
| `W[7]` | `decoded_next_pc` | `mul_div::DECODED[0]`; `SEQ` | Decoded fall-through | `pc + 4` | `next_pc_rule`; `decode_row` position 1 |
| `W[8]` | `decoded_rs1` | `DECODED[1]` | Decoded rs1 | | `rs1_addr_rule`; `decode_row` position 2 |
| `W[9]` | `decoded_rs2` | `DECODED[2]` | Decoded rs2 | | `rs2_addr_rule`; `decode_row` position 3 |
| `W[10]` | `decoded_rd` | `DECODED[3]` | Decoded rd | | `rd_addr_rule`; `decode_row` position 4 |
| `W[11]` | `decoded_mask` | `DECODED[4]` | Decoded kind mask | `1 << bit`; **`DECODED` is five wide, there being no `imm`** | `decoded_mask_bits`; `decode_row` position 5 |
| `W[12]` | `kind_mul` | `KINDS[0]`; `MUL` | mul row | | `kind_mul_boolean`, `decoded_mask_bits`, the three mask rules, `s1_rule`, `s2_rule`, `mx_rule`, `my_rule`, `rd_value_rule` |
| `W[13]` | `kind_mulh` | `KINDS[1]`; `MULH` | mulh row | | as `kind_mul`, with `rd_value_rule` taking `p_high` |
| `W[14]` | `kind_mulhsu` | `KINDS[2]`; `MULHSU` | mulhsu row | | `kind_mulhsu_boolean`, `decoded_mask_bits`, the three mask rules, `s1_rule` **but not `s2_rule`**, `mx_rule`, `my_rule`, `rd_value_rule` |
| `W[15]` | `kind_mulhu` | `KINDS[3]`; `MULHU` | mulhu row | | `kind_mulhu_boolean`, `decoded_mask_bits`, the three mask rules, `mx_rule`, `my_rule`, `rd_value_rule`; **neither sign rule** |
| `W[16]` | `kind_div` | `KINDS[4]`; `DIV` | div row | | `kind_div_boolean`, `decoded_mask_bits`, the three mask rules, `f_div_rule`, `s1_rule`, `s2_rule`, `rd_value_rule` |
| `W[17]` | `kind_divu` | `KINDS[5]`; `DIVU` | divu row | | `kind_divu_boolean`, `decoded_mask_bits`, the three mask rules, `f_div_rule`, `rd_value_rule` |
| `W[18]` | `kind_rem` | `KINDS[6]`; `REM` | rem row | | as `kind_div`, `rd_value_rule` taking `r` |
| `W[19]` | `kind_remu` | `KINDS[7]`; `REMU` | remu row | | as `kind_divu`, `rd_value_rule` taking `r` |
| `W[20]` | `f_div` | `mul_div::F_DIV` | Row is a division | the sum of the four division bits | `f_div_rule`, `f_div_boolean`, `mx_rule`, `my_rule`, `division_rule`, `rz_inverse`, `dz_inverse`, `d1_rule`, `gap_rule` — the **`enable` of both is-zero gadgets**, which is why it is a column |
| `W[21]` | `rs1_hi` | `RS1_HI` | rs1, high halfword | `rs1 >> 16` | `rs1_hi_range`, `rs1_lo_range`; `rs1_get_sign` position 0 |
| `W[22]` | `rs1_top` | `RS1_TOP` | rs1, bit 31 | `rs1 >> 31`, whatever the kind | `s1_rule`, `rs1_top_boolean`; `rs1_get_sign` position 1 |
| `W[23]` | `rs2_hi` | `RS2_HI` | rs2, high halfword | `rs2 >> 16` | `rs2_hi_range`, `rs2_lo_range`; `rs2_get_sign` position 0 |
| `W[24]` | `rs2_top` | `RS2_TOP` | rs2, bit 31 | `rs2 >> 31` | `s2_rule`, `rs2_top_boolean`; `rs2_get_sign` position 1 |
| `W[25]` | `s1` | `S1` | lhs sign **adjustment** | `lhs_signed·rs1_top` | `s1_rule`, `s1_boolean`, `mx_rule`, `division_rule`, `d1_rule` |
| `W[26]` | `s2` | `S2` | rhs sign adjustment | `rhs_signed·rs2_top` | `s2_rule`, `s2_boolean`, `mx_rule`, `my_rule`, `abs_d_rule` |
| `W[27]` | `mx` | `MX` | First multiplicand | `rs1_adj` on a multiply, `rs2_adj` on a division; **`Fr`-backed**, being signed | `mx_rule`, `product_rule` |
| `W[28]` | `my` | `MY` | Second multiplicand | `rs2_adj` on a multiply, `q_adj` on a division; **`Fr`-backed** | `my_rule`, `product_rule` |
| `W[29]` | `p_low` | `P_LOW` | Product, low word | | `product_rule`, `division_rule`, `rd_value_rule`; `p_low_lo_range` |
| `W[30]` | `p_low_hi` | `P_LOW_HI` | `p_low`, high halfword | | `p_low_hi_range`, `p_low_lo_range` |
| `W[31]` | `p_high` | `P_HIGH` | Product, high word | | `product_rule`, `division_rule`, `rd_value_rule`; `p_high_lo_range` |
| `W[32]` | `p_high_hi` | `P_HIGH_HI` | `p_high`, high halfword | | `p_high_hi_range`, `p_high_lo_range` |
| `W[33]` | `p_sign` | `P_SIGN` | Product is negative | | `p_sign_boolean`, `product_rule`, `division_rule` |
| `W[34]` | `q` | `Q` | Quotient, as a word | 0 on a multiply row | `my_rule`, `zero_divisor_quotient`, `rd_value_rule`; `q_lo_range` |
| `W[35]` | `q_hi` | `Q_HI` | `q`, high halfword | | `q_hi_range`, `q_lo_range` |
| `W[36]` | `q_sign` | `Q_SIGN` | Quotient sign adjustment | **a free boolean**, pinned only by `q`'s own range (§6.5 E) | `q_sign_boolean`, `my_rule` |
| `W[37]` | `r` | `R` | Remainder, as a word | 0 on a multiply row | `division_rule`, `rz_inverse`, `rz_at_nonzero`, `abs_r_rule`, `rd_value_rule`; `r_lo_range` |
| `W[38]` | `r_hi` | `R_HI` | `r`, high halfword | | `r_hi_range`, `r_lo_range` |
| `W[39]` | `r_sign` | `R_SIGN` | Remainder sign adjustment | `d1·(1 − rz)`: 1 exactly on a division row with a negative dividend and a nonzero remainder | `r_sign_boolean`, `division_rule`, `r_sign_rule`, `abs_r_rule` |
| `W[40]` | `r_inv` | `R_INV` | Inverse of the remainder | `r⁻¹` on a division row with `r ≠ 0`, else 0; **`Fr`-backed** | `rz_inverse` |
| `W[41]` | `rz` | `RZ` | Remainder is zero | `f_div·[r = 0]`; boolean by the gadget, so no booleanity gate | `rz_inverse`, `rz_at_nonzero`, `r_sign_rule` |
| `W[42]` | `d1` | `D1` | Division with a negative dividend | `f_div·s1`; boolean by the two columns it multiplies | `d1_rule`, `r_sign_rule` |
| `W[43]` | `d_inv` | `D_INV` | Inverse of the divisor | `rs2⁻¹` on a division row with `rs2 ≠ 0`, else 0; **`Fr`-backed** | `dz_inverse` |
| `W[44]` | `dz` | `DZ` | Divisor is zero | `f_div·[rs2 = 0]`; boolean by the gadget | `dz_inverse`, `dz_at_nonzero`, `gap_rule`, `zero_divisor_quotient` |
| `W[45]` | `abs_r` | `ABS_R` | `\|r_adj\|` | | `abs_r_rule`, `gap_rule` |
| `W[46]` | `abs_d` | `ABS_D` | `\|rs2_adj\|` | computed on a multiply row too, the gate being ungated | `abs_d_rule`, `gap_rule` |
| `W[47]` | `gap` | `GAP` | `\|divisor\| − \|rem\| − 1`, corrected | `f_div·(abs_d − abs_r − 1) + 2^32·dz` | `gap_rule`; `gap_lo_range` |
| `W[48]` | `gap_hi` | `GAP_HI` | `gap`, high halfword | | `gap_hi_range`, `gap_lo_range` |
| `W[49]` | `rd_hi` | `RD_HI` | Result, high halfword | `rd_selected >> 16` | `rd_hi_range`, `rd_lo_range` |
| `W[50]` | `mult_timestamp` | `MULTIPLICITIES[0]` | Timestamp-table count | per table row `t`: the gated gap chunks equal to `t`, credited to rows below `2^19` | leaf `timestamp_table_num` |
| `W[51]` | `mult_range16` | `MULTIPLICITIES[1]` | 16-bit-table count | per table row `t`: the gated halfwords (`pc_mask·expression`) equal to `t` | leaf `range16_table_num` |
| `W[52]` | `mult_generic` | `MULTIPLICITIES[2]` | Generic-table count | per table row `t`: the gated sign tuples equal to row `t`; a live row's two land on `U16GetSign`'s rows `2^16 + 1 + rs1_hi` and `2^16 + 1 + rs2_hi`, a padding row's two on row 0, the `ZeroEntry` | leaf `generic_table_num` |
| `W[53]` | `mult_decoder` | `MULTIPLICITIES[3]` | Decoder-table count | per table row `t`: the live cycles at pc `2t`; and every padding row's switched-off tuple (`MINUS_ONE` in all **six** positions) on the table's lowest non-live row, row 0 | leaf `decoder_table_num` |

Every obligation of this family is selected by `pc_mask` except the eight timestamp gaps, whose
selectors are their own queries' masks — and every query of this frame is present on every live
row, so **on a live row nothing is switched off**. Row 0 of `mult_timestamp` and `mult_range16`
therefore counts a padding row's whole set, all 8 and all 16, plus every live chunk or halfword
whose value is 0. That is the simplest multiplicity picture of the seven registered execution
families.

**Setup columns, `S[0..9]`** — two tables, **nine columns, not ten**. `S[0..6]` is the family's
decoded table in `program::lookup_tuple(3)` order — `pc next_pc rs1 rs2 rd extra_mask`, with no
`imm` — filled by `program::FamilyTable::column_poly(j)`; committed in program identity and
carried as `VerifyingKey::setup_commitments` for the family. `S[6..9]` is the packed generic
table (§0.3), filled by `program::lookup_tables::generic_table(n)`: the same three commitments
every key carries, covered by the key's SRS digest and not by identity, which a shard opens after
identity's list because `FamilyCircuit::reads_generic_table` holds (`shard-proof.md` §3, §5.1,
§7). Each is read only by its table's denominator, at the `β` power in the last column.

| address | name | Rust | descriptive name | contents | read by | weight |
| --- | --- | --- | --- | --- | --- | --- |
| `S[0]` | `table_pc` | `mul_div::channels()[3].table[0]` | Table pc | `RowField::Pc` | `decoder_table_den` | 1 |
| `S[1]` | `table_next_pc` | `channels()[3].table[1]` | Table fall-through | `RowField::NextPc` | `decoder_table_den` | `β` |
| `S[2]` | `table_rs1` | `channels()[3].table[2]` | Table rs1 | `RowField::Rs1` | `decoder_table_den` | `β²` |
| `S[3]` | `table_rs2` | `channels()[3].table[3]` | Table rs2 | `RowField::Rs2` | `decoder_table_den` | `β³` |
| `S[4]` | `table_rd` | `channels()[3].table[4]` | Table rd | `RowField::Rd` | `decoder_table_den` | `β⁴` |
| `S[5]` | `table_extra_mask` | `channels()[3].table[5]` | Table kind mask | `RowField::ExtraMask` | `decoder_table_den` | `β⁵` |
| `S[6]` | `generic_key` | `mul_div::GENERIC_TABLE[0]`, `channels()[2].table[0]` | Generic key | 0, `AND_BASE + a + 1`, `SIGN_BASE + h + 1` or `SHIFT_BASE + s + 1` | `generic_table_den` | 1 |
| `S[7]` | `generic_value` | `GENERIC_TABLE[1]` | Generic value | 0, `b`, `h >> 15` or `2^s` | `generic_table_den` | `β` |
| `S[8]` | `generic_result` | `GENERIC_TABLE[2]` | Generic result | 0, `a & b`, 0 or `2^(31 − s)` | `generic_table_den` | `β²` |

`mul_div::TABLE_WIDTH` is **6**; `constants::generic_table::WIDTH` is 3. The packed table's other
two sub-tables are there because the table is one artifact of the ceremony shared by every family
that reads the channel; this family looks nothing up in them.

**Virtual tables** — never committed, never opened.

| address | name | Rust | descriptive name | value at row `y` | read by |
| --- | --- | --- | --- | --- | --- |
| `V[range19]` | `range19` | `VirtualKind::Range19`, wire tag 2 | 19-bit range table | `y mod 2^19` | `timestamp_table_den` |
| `V[range16]` | `range16` | `VirtualKind::Range16`, wire tag 3 | 16-bit range table | `y mod 2^16` | `range16_table_den` |

### 6.4 Gate list 0: the 116 leaves

A leaf's relation number equals its `L1` offset, 0 to 115.

**The memory product trees.** `L1[0..4]` read, `L1[4..8]` write, §5.4's table address for
address — the frame is the same. Four queries fill each side, so neither has a pad.

| `L1` | node | mask | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `read_pc` | `M[1]` | 3 | `M[2]` | `M[3]` | `M[4]` |
| 1 | `read_rs1` | `M[6]` | 1 | `M[7]` | `M[8]` | `M[9]` |
| 2 | `read_rs2` | `M[11]` | 1 | `M[12]` | `M[13]` | `M[14]` |
| 3 | `read_rd` | `M[16]` | 1 | `M[17]` | `M[18]` | `M[19]` |
| 4 | `write_pc` | `M[1]` | 3 | `M[2]` | `4·M[0] + 0` | `M[5]` |
| 5 | `write_rs1` | `M[6]` | 1 | `M[7]` | `4·M[0] + 1` | `M[10]` |
| 6 | `write_rs2` | `M[11]` | 1 | `M[12]` | `4·M[0] + 2` | `M[15]` |
| 7 | `write_rd` | `M[16]` | 1 | `M[17]` | `4·M[0] + 3` | `M[20]` |

**The `timestamp` fraction tree**, `L1[8..40]`: 16 fractions, §5.4's and §4.4's list unchanged —
the table's, then `gap_hi_pc`, `gap_lo_pc`, `gap_hi_rs1`, `gap_lo_rs1`, `gap_hi_rs2`,
`gap_lo_rs2`, `gap_hi_rd`, `gap_lo_rd`, then `timestamp_pad_0` … `timestamp_pad_6`. Fraction `i`
is `(L1[8 + 2i], L1[9 + 2i])`.

**The `range16` fraction tree**, `L1[40..104]`: 32 fractions, the table's then 16 obligations then
**15 pads** — the longest pad run of any registered circuit, and the reason the tree costs a
fifth row-wise level for one leaf past 16.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 40, 41 | `range16_table` | `−mult_range16` | `V[range16] + g` |
| 1 | 42, 43 | `rs1_hi_range` | 1 | `g + pc_mask·rs1_hi` |
| 2 | 44, 45 | `rs1_lo_range` | 1 | `g + pc_mask·rs1_read_value − 2^16·pc_mask·rs1_hi` |
| 3 | 46, 47 | `rs2_hi_range` | 1 | `g + pc_mask·rs2_hi` |
| 4 | 48, 49 | `rs2_lo_range` | 1 | `g + pc_mask·rs2_read_value − 2^16·pc_mask·rs2_hi` |
| 5 | 50, 51 | `p_low_hi_range` | 1 | `g + pc_mask·p_low_hi` |
| 6 | 52, 53 | `p_low_lo_range` | 1 | `g + pc_mask·p_low − 2^16·pc_mask·p_low_hi` |
| 7 | 54, 55 | `p_high_hi_range` | 1 | `g + pc_mask·p_high_hi` |
| 8 | 56, 57 | `p_high_lo_range` | 1 | `g + pc_mask·p_high − 2^16·pc_mask·p_high_hi` |
| 9 | 58, 59 | `q_hi_range` | 1 | `g + pc_mask·q_hi` |
| 10 | 60, 61 | `q_lo_range` | 1 | `g + pc_mask·q − 2^16·pc_mask·q_hi` |
| 11 | 62, 63 | `r_hi_range` | 1 | `g + pc_mask·r_hi` |
| 12 | 64, 65 | `r_lo_range` | 1 | `g + pc_mask·r − 2^16·pc_mask·r_hi` |
| 13 | 66, 67 | `gap_hi_range` | 1 | `g + pc_mask·gap_hi` |
| 14 | 68, 69 | `gap_lo_range` | 1 | `g + pc_mask·gap − 2^16·pc_mask·gap_hi` |
| 15 | 70, 71 | `rd_hi_range` | 1 | `g + pc_mask·rd_hi` |
| 16 | 72, 73 | `rd_lo_range` | 1 | `g + pc_mask·rd_selected − 2^16·pc_mask·rd_hi` |
| 17–31 | 74–103 | `range16_pad_0` … `range16_pad_14` | 0 | 1 |

`gap_hi_range` is this family's `RANGE16` obligation on the `gap` column and has nothing to do
with the frame's `gap_hi_<q>` timestamp obligations, which are on channel 0 and named per query.

**The `generic` fraction tree**, `L1[104..112]`: 4 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 104, 105 | `generic_table` | `−mult_generic` | `generic_key + β·generic_value + β²·generic_result + g` |
| 1 | 106, 107 | `rs1_get_sign` | 1 | `g + 257·pc_mask + pc_mask·rs1_hi + β·pc_mask·rs1_top` |
| 2 | 108, 109 | `rs2_get_sign` | 1 | `g + 257·pc_mask + pc_mask·rs2_hi + β·pc_mask·rs2_top` |
| 3 | 110, 111 | `generic_pad_0` | 0 | 1 |

```text
L{1}[107]  rs1_get_sign_den
  positional  g + 257·M[1] + M[1]·W[21] + lookup_beta·M[1]·W[22]
  reads as    g + pc_mask·(e_0 + 1) + β·pc_mask·e_1 + β²·pc_mask·e_2,
              e = (rs1_hi + SIGN_BASE, rs1_top, 0), SIGN_BASE = 256:
              the key rs1_hi + 257 and the top bit at pc_mask = 1, the ZeroEntry at 0;
              e_2 is the constant 0 and contributes no term, so neither sign lookup
              reads β² — §4.6's note, unchanged
```

Each key is bounded before it is looked up, `lookup.md` §4's precondition: `rs1_hi` and `rs2_hi`
by their own 16+16 pairs under the same selector `pc_mask`, which keeps each key `hi + 257` in
`[257, 2^16 + 256]`, `U16GetSign`'s own range, and never the `ZeroEntry`, an AND key or a
`ShiftPowers` key. §5.6 is why that matters now that three sub-tables share the channel.

**The `decoder` fraction tree**, `L1[112..116]`: 2 fractions, and **six** columns wide.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 112, 113 | `decoder_table` | `−mult_decoder` | `table_pc + β·table_next_pc + β²·table_rs1 + β³·table_rs2 + β⁴·table_rd + β⁵·table_extra_mask + g` |
| 1 | 114, 115 | `decode_row` | 1 | `g_dec + (1 + β + β² + β³ + β⁴ + β⁵)·pc_mask + pc_mask·pc_read_value + β·pc_mask·decoded_next_pc + β²·pc_mask·decoded_rs1 + β³·pc_mask·decoded_rs2 + β⁴·pc_mask·decoded_rd + β⁵·pc_mask·decoded_mask` |

Here `g_dec` is `g − Σ_{j<6} β^j`, not `g − Σ_{j<7} β^j`: `gkr_verify::insert_lookup_challenges`
derives it from the artifact's own decoder tuple width, so the six-column tuple gets its own
neutral value and nothing else in the engine changes.

### 6.5 Gate list 0: the 54 enforcing gates

Relations 116–169, in list order, in §3.5's format. The frame's ten are `memory`'s; the family's
forty-four are **eighteen from `mul_div::family_spec`** — the plumbing, which has no width: the
eight kind booleanities, `decoded_mask_bits`, three mask rules, three address rules, two
`value_masked` and `next_pc_rule` — and **twenty-six from `mul_div::arithmetic_gates(32)`**,
relations 144–169, which are the tail of the list in order, a fact
`the_layout_and_the_gates_are_the_spec` asserts by comparing
`enforcing[54 − arithmetic.len()..]` against the function's own output.

**A. The frame's gates (116–125)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
116–125 the frame, §5.5's A and §4.5's A over the REG layout

  116 pc_mask_boolean     0 = M[1]  − M[1]·M[1]          Quadratic, degree 2
  117 rs1_mask_boolean    0 = M[6]  − M[6]·M[6]
  118 rs2_mask_boolean    0 = M[11] − M[11]·M[11]
  119 rd_mask_boolean     0 = M[16] − M[16]·M[16]
  120 rs1_writes_back     0 = M[10] − M[9]                Linear, degree 1
  121 rs2_writes_back     0 = M[15] − M[14]               Linear, degree 1
  122 rd_is_zero_inverse  0 = W[5] − M[16] + M[17]·W[4]
  123 rd_is_zero_at_nonzero  0 = M[17]·W[5]
  124 rd_is_zero_boolean  0 = W[5] − W[5]·W[5]
  125 rd_write_masked     0 = M[20] − W[6] + W[5]·W[6]
        code  memory::booleanity, memory::write_back, memory::x0_gates(3, 4)
```

**B. What the row is (126–134)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
126–133 kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2
        code  mul_div's private booleanity(KINDS[k])

  126 kind_mul_boolean     0 = W[12] − W[12]·W[12]    130 kind_div_boolean   W[16]
  127 kind_mulh_boolean    0 = W[13] − W[13]·W[13]    131 kind_divu_boolean  W[17]
  128 kind_mulhsu_boolean  0 = W[14] − W[14]·W[14]    132 kind_rem_boolean   W[18]
  129 kind_mulhu_boolean   0 = W[15] − W[15]·W[15]    133 kind_remu_boolean  W[19]

────────────────────────────────────────────────────────────────────────────────────────────
134     decoded_mask_bits — the packed mask is its eight bits           Linear, degree 1
        code  mul_div::family_spec, `bits`

  positional  0 = W[12] + 2·W[13] + 4·W[14] + 8·W[15] + 16·W[16] + 32·W[17] + 64·W[18]
                  + 128·W[19] − W[11]
  named       0 = Σ_k 2^k·kind_k − decoded_mask,  k in extra_mask::mul_div order

  reads as  §5.5's 146 over eight bits. One-hotness is the decoder table's domain
            (lookup.md §10), and W[11] is the fifth decoded column, not the sixth: this
            family's tuple has no imm.
```

**C. Which queries a row makes, and where (135–143)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
135–137 <q>_mask_rule — every one of the eight is R-type               Quadratic, degree 2
        code  mask_rule(frame(s, FIELD_MASK), &KINDS), for s = 1, 2, 3

  135 rs1_mask_rule  0 = M[6]  − M[1]·W[12] − M[1]·W[13] − … − M[1]·W[19]
  136 rs2_mask_rule  0 = M[11] − M[1]·W[12] − M[1]·W[13] − … − M[1]·W[19]
  137 rd_mask_rule   0 = M[16] − M[1]·W[12] − M[1]·W[13] − … − M[1]·W[19]
  named             0 = <q>_mask − pc_mask·Σ_k kind_k,  each over all eight bits

  reads as  the three lists are identical, which no other registered family's are: every
            kind reads both operands and writes rd. On a live row the bits are one-hot, so
            each mask is 1; on a padding row pc_mask = 0 and every mask is 0, whatever the
            bits hold. S14's control C8 is refused here by 137 with 140 and 169 — the
            decoded rd of a row that decodes nothing is 0 and the value it claims to write
            is not a selection of anything (§6.10).

────────────────────────────────────────────────────────────────────────────────────────────
138–140 <q>_addr_rule — a present query's register is the decoded one  Quadratic, degree 2
        code  addr_rule(slot, DECODED_<Q>)

  138 rs1_addr_rule  0 = M[6]·M[7]   − M[6]·W[8]
  139 rs2_addr_rule  0 = M[11]·M[12] − M[11]·W[9]
  140 rd_addr_rule   0 = M[16]·M[17] − M[16]·W[10]

────────────────────────────────────────────────────────────────────────────────────────────
141–142 <q>_value_masked — an absent operand reads 0                   Quadratic, degree 2
        code  value_masked(slot)

  141 rs1_value_masked  0 = M[9]  − M[6]·M[9]
  142 rs2_value_masked  0 = M[14] − M[11]·M[14]

  reads as  both operands are present on every live row, so these two bite on padding rows
            alone — which is exactly where they are needed: an unmasked operand carrying a
            value is what a forged padding row would use, and 142 is what keeps a padding
            row's divisor 0 (§6.10).

────────────────────────────────────────────────────────────────────────────────────────────
143     next_pc_rule — the pc falls through, always                     Linear, degree 1
        code  mul_div::family_spec

  positional  0 = M[5] − W[7]
  named       0 = pc_write_value − decoded_next_pc

  reads as  §5.5's 159: this family computes no pc either (shift-bitwise.md §4.1).
```

**D. The flags and the signs (144–154)** — from here to the end, `arithmetic_gates(32)`.

```text
────────────────────────────────────────────────────────────────────────────────────────────
144–145 f_div, the division half                      Linear/Quadratic, degrees 1 and 2
        code  arithmetic_gates, over DIVS

  144 f_div_rule     0 = W[20] − W[16] − W[17] − W[18] − W[19]
                     0 = f_div − (kind_div + kind_divu + kind_rem + kind_remu)
  145 f_div_boolean  0 = W[20] − W[20]·W[20]

  reads as  f_div is a committed column because it is the **enable** of both is-zero
            gadgets (159, 161), which multiply it against another column; every other
            signal this family needs is a linear form over the kind bits and stays inline
            (mul-div.md §1). Unlike §5's two halves it is not a lookup selector — nothing
            here is selected by anything but pc_mask and the frame's masks — but its
            booleanity is load-bearing all the same: at f_div = 2 a gadget's enable would
            make `rz` 2.

────────────────────────────────────────────────────────────────────────────────────────────
146–147 s<i>_rule — each operand's sign adjustment                     Quadratic, degree 2
        code  arithmetic_gates, over LHS_SIGNED and RHS_SIGNED

  146 s1_rule  0 = W[25] − W[12]·W[22] − W[13]·W[22] − W[14]·W[22] − W[16]·W[22]
                   − W[18]·W[22]
      named    0 = s1 − (kind_mul + kind_mulh + kind_mulhsu + kind_div + kind_rem)·rs1_top
  147 s2_rule  0 = W[26] − W[12]·W[24] − W[13]·W[24] − W[16]·W[24] − W[18]·W[24]
      named    0 = s2 − (kind_mul + kind_mulh + kind_div + kind_rem)·rs2_top

  reads as  the two lists differ by exactly one bit, kind_mulhsu, which is the whole of the
            asymmetry: its rs1 is signed and its rs2 is not. An **unsigned position forces
            its flag to 0** whatever the operand's top bit, which is what keeps the
            selection degree 2 and makes mulhsu one gate rather than a case split. The two
            top bits themselves come from U16GetSign over range-checked halfwords (§6.6),
            so each is genuinely the operand's bit 31 on a live row.

────────────────────────────────────────────────────────────────────────────────────────────
148–154 the booleans                                                   Quadratic, degree 2
        code  arithmetic_gates, its booleanity list

  148 rs1_top_boolean  0 = W[22] − W[22]·W[22]    152 p_sign_boolean  W[33]
  149 rs2_top_boolean  0 = W[24] − W[24]·W[24]    153 q_sign_boolean  W[36]
  150 s1_boolean       0 = W[25] − W[25]·W[25]    154 r_sign_boolean  W[39]
  151 s2_boolean       0 = W[26] − W[26]·W[26]

  reads as  every boolean the family leaves **free** carries one — f_div, p_sign and
            q_sign — and the four that are implied carry one anyway: the two top bits by
            the sign lookup, s1 and s2 by 146 and 147 over boolean bits, r_sign by 158.
            `rz`, `dz` and `d1` do not: the first two are boolean by the is-zero gadget's
            construction and the third by the two columns it multiplies, as S17's `eq` is
            (mul-div.md §3).
```

**E. One product identity, and the division built on it (155–158)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
155     mx_rule — the first multiplicand                                Quadratic, degree 2
156     my_rule — the second                                            Quadratic, degree 2
        code  arithmetic_gates, over MULS then F_DIV

  155 positional  0 = W[27] − W[12]·M[9] + 2^32·W[12]·W[25] − W[13]·M[9] + 2^32·W[13]·W[25]
                      − W[14]·M[9] + 2^32·W[14]·W[25] − W[15]·M[9] + 2^32·W[15]·W[25]
                      − W[20]·M[14] + 2^32·W[20]·W[26]
      named, factored
        0 = mx − Σ_mul kind·(rs1_read_value − 2^32·s1) − f_div·(rs2_read_value − 2^32·s2)
  156 positional  0 = W[28] − W[12]·M[14] + 2^32·W[12]·W[26] − … − W[20]·W[34]
                      + 2^32·W[20]·W[36]
      named, factored
        0 = my − Σ_mul kind·(rs2_read_value − 2^32·s2) − f_div·(q − 2^32·q_sign)

────────────────────────────────────────────────────────────────────────────────────────────
157     product_rule — the one multiplication of two row values         Quadratic, degree 2
        code  arithmetic_gates, over word = 2^32 and double = 2^64

  positional  0 = −W[29] − 2^32·W[31] + 2^64·W[33] + W[27]·W[28]
  named       0 = mx·my − p_low − 2^32·p_high + 2^64·p_sign

  reads as (155–157)  on a multiply row the multiplicands are the two operands; on a
                      division row they are the **divisor and the quotient**. 157 is
                      ungated and is the only multiplication of two row values, which is
                      what lets both readings share it and keeps the identity degree 2.
                      On a multiply row mx and my each lie in [−2^31, 2^32); on a division
                      row mx is the sign-adjusted divisor and my is q − 2^32·q_sign with q
                      range-checked and q_sign boolean, so (−2^32, 2^32). The product is
                      therefore in (−2^64, 2^64) — the extremes are −2^31·(2^32 − 1) and
                      just under 2^32·2^32, neither reaching the endpoint — and with p_low
                      and p_high each range-checked below 2^32 and p_sign boolean,
                      p_low + 2^32·p_high − 2^64·p_sign covers that interval exactly once.
                      So the field identity is the integer identity and the decomposition
                      is unique. The dump prints 2^32 as 0x…0100000000, −2^32 as
                      0x30644e72…f0000001, 2^64 as 0x…00010000000000000000 and −2^64 as
                      0x30644e72e131a029b85045b68181585d2833e84879b9709043e1f593f0000001.

────────────────────────────────────────────────────────────────────────────────────────────
158     division_rule — divisor·quotient + rem = dividend               Quadratic, degree 2
        code  arithmetic_gates

  positional  0 = W[20]·W[29] + 2^32·W[20]·W[31] − 2^64·W[20]·W[33] + W[20]·W[37]
                  − 2^32·W[20]·W[39] − W[20]·M[9] + 2^32·W[20]·W[25]
  named, factored
    0 = f_div·(p_low + 2^32·p_high − 2^64·p_sign + r − 2^32·r_sign
               − rs1_read_value + 2^32·s1)
      = f_div·(rs2_adj·q_adj + r_adj − rs1_adj)

  reads as  **it is gated, and must be.** On a multiply row f_div is 0, so 163 gives d1 = 0
            and therefore r_sign = 0, and r is range-checked non-negative — so r_adj ≥ 0.
            An ungated identity over a multiply row whose rs2 is 0 then reads
            r_adj = rs1_adj, which no non-negative r_adj satisfies when rs1_adj is
            negative, and `mul t0, t1, x0` with a negative t1 — an ordinary instruction —
            would be unprovable (mul-div.md §4.3).
            **The identity alone says nothing useful.** On a zero divisor it degenerates to
            r_adj = rs1_adj, and on every inexact division a floored witness satisfies it as
            readily as a truncated one. 159–164 are what pin it.
```

**F. The remainder's sign (159–164)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
159–160 the is-zero gadget over r, enabled by f_div                    Quadratic, degree 2
        code  gadgets::is_zero(&[(1, R)], R_INV, RZ, F_DIV)

  159 rz_inverse     0 = W[41] − W[20] + W[37]·W[40]
                     0 = r·r_inv + rz − f_div
  160 rz_at_nonzero  0 = W[37]·W[41]        0 = r·rz

────────────────────────────────────────────────────────────────────────────────────────────
161–162 the is-zero gadget over the divisor, enabled by f_div          Quadratic, degree 2
        code  gadgets::is_zero(&[(1, rs2_read_value)], D_INV, DZ, F_DIV)

  161 dz_inverse     0 = W[44] − W[20] + M[14]·W[43]
                     0 = rs2_read_value·d_inv + dz − f_div
  162 dz_at_nonzero  0 = M[14]·W[44]        0 = rs2_read_value·dz

  reads as (159–162)  each pair makes its flag `f_div` where the subject is 0 and 0 where it
                      is not, with no booleanity gate of its own — S17's argument for `eq`,
                      unchanged. Enabling both by f_div is what leaves q and r free on a
                      multiply row.

────────────────────────────────────────────────────────────────────────────────────────────
163     d1_rule — a division with a negative dividend                   Quadratic, degree 2
164     r_sign_rule — the remainder's sign, as a definition              Quadratic, degree 2
        code  arithmetic_gates

  163 positional  0 = W[42] − W[20]·W[25]        0 = d1 − f_div·s1
  164 positional  0 = W[39] − W[42] + W[42]·W[41]
      named       0 = r_sign − d1·(1 − rz)

  reads as  r_sign is 1 exactly where the row is a division, the dividend is negative and
            the remainder is not zero. Stated as a **definition** rather than as the
            implication `rem ≠ 0 ⇒ sign(rem) = sign(dividend)`, it is the same constraint
            and is cheaper: the implication gated to division rows is degree 3, and d1 is
            the committed column that brings it back to 2.
            **This is the easiest line to leave out and the one that separates truncated
            from floored division.** Without it DIV(−7, 2) takes −4 as readily as −3,
            because 2·(−4) + 1 = −7 satisfies 158 and |1| < |2| satisfies 165–167 — the row
            the suite builds as `floored_minus_seven_over_two`, which 164 alone refuses. And
            on an unsigned row, where d1 is 0 and so r_sign is 0, it is what forces
            r_adj = r ≥ 0, without which DIVU(0xDEADBEEF, 0x1234) could return 801702 for
            801701 (mul-div.md §4.4).
```

**G. The magnitude bound, the pin and the selection (165–169)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
165–166 abs_<x>_rule — |x| in one degree-2 line                        Quadratic, degree 2
        code  arithmetic_gates, the (name, abs, value, sign) loop

  165 abs_r_rule  0 = W[45] − W[37] − 2^32·W[39] + 2·W[37]·W[39]
      named       0 = abs_r − (r + 2^32·r_sign − 2·r·r_sign)   = |r_adj|
  166 abs_d_rule  0 = W[46] − M[14] − 2^32·W[26] + 2·M[14]·W[26]
      named       0 = abs_d − (rs2 + 2^32·s2 − 2·rs2·s2)       = |rs2_adj|

  reads as  |x| = x + 2^w·sign − 2·x·sign is degree 2 and exact for both flag values. Both
            gates are **ungated**, so a multiply row computes both magnitudes too; nothing
            reads them there, 167's f_div factor being 0 (§6.9's row C carries
            abs_d = 0xffffffff on a mulhsu).

────────────────────────────────────────────────────────────────────────────────────────────
167     gap_rule — |rem| < |divisor|, with the zero-divisor correction  Quadratic, degree 2
        code  arithmetic_gates

  positional  0 = W[47] + W[20] − 2^32·W[44] − W[20]·W[46] + W[20]·W[45]
  named       0 = gap − f_div·(abs_d − abs_r − 1) − 2^32·dz

  reads as  gap is 16+16 range-checked (§6.6), so on a division row with a nonzero divisor
            abs_d − abs_r − 1 ∈ [0, 2^32), which is |rem| < |divisor|. The step that
            carries it is that **neither magnitude can reach 2^32**, so the difference
            cannot wrap into range from below: abs_d = 2^32 − rs2 only where s2 = 1, which
            needs rs2 ≥ 2^31, so abs_d ≤ 2^31; abs_r = 2^32 − r only where r_sign = 1, which
            164 allows only where rz = 0 and so r ≠ 0, so abs_r ≤ 2^32 − 1. With both in
            [0, 2^32), abs_d − abs_r − 1 lies in (−2^32 − 1, 2^32), and a field element of
            that interval is in [0, 2^32) exactly when it is non-negative. Neither magnitude
            needs a range obligation of its own (mul-div.md §4.5).
            **The zero-divisor correction is what makes a zero divisor impose no bound**:
            at dz = 1, abs_d is 0 and gap is 2^32 − abs_r − 1, in range for every abs_r
            below 2^32. On a multiply row f_div is 0, so gap is 0 and in range.

────────────────────────────────────────────────────────────────────────────────────────────
168     zero_divisor_quotient — division by zero is all ones            Quadratic, degree 2
        code  arithmetic_gates, coefficient Fr::ONE − 2^32

  positional  0 = −4294967295·W[44] + W[44]·W[34]
  named       0 = dz·(q − (2^32 − 1))

  reads as  the whole of the div-by-zero pin. The remainder needs none: with rs2_adj = 0 the
            identity gives r_adj = rs1_adj directly, and 164 then fixes the word to rs1. The
            **signed overflow** −2^31 ÷ −1 needs no pin either: |rem| < 1 forces rem = 0,
            158 gives q_adj = 2^31, and q's own range forces q_sign = 0 and q = 0x80000000,
            the ISA's answer. That case is also why **q_sign must stay a free boolean**:
            there q's top bit is set while q_sign is 0, so a circuit taking q_sign from
            U16GetSign over q_hi, as it takes s1 and s2 from the operands, would make that
            one row unprovable (mul-div.md §5.3).

────────────────────────────────────────────────────────────────────────────────────────────
169     rd_value_rule — which of the four results the kind writes       Quadratic, degree 2
        code  arithmetic_gates, over MUL, TAKES_HIGH, TAKES_QUOTIENT, TAKES_REMAINDER

  positional  0 = W[6] − W[12]·W[29] − W[13]·W[31] − W[14]·W[31] − W[15]·W[31]
                  − W[16]·W[34] − W[17]·W[34] − W[18]·W[37] − W[19]·W[37]
  named       0 = rd_selected − kind_mul·p_low
                  − (kind_mulh + kind_mulhsu + kind_mulhu)·p_high
                  − (kind_div + kind_divu)·q − (kind_rem + kind_remu)·r

  reads as  the selection is by sums of committed kind bits and never by a bare decoder
            output. rd_selected carries its own 16+16 pair, which is **implied** — every
            source it selects carries one — and kept anyway, because every family bounds
            what it writes to rd in the same place (mul-div.md §5.4). Nothing else in this
            circuit is redundant.
```

Of the 54 gates, 5 are degree 1: the two write-backs, `decoded_mask_bits`, `next_pc_rule` and
`f_div_rule`. All 54 have constant 0, so each is 0 on the all-zero row, and the assembly records
`zero_row_valid = true`, which `assemble` asserts before returning.

### 6.6 The 27 lookups

`CircuitArtifact::lookups`, in order. The frame's 8 come from the private `memory::gap_lookups`;
the rest from `mul_div::family_spec` (its private `range32`, `get_sign` and the inline
`decode_row`). **Every lookup from 8 on is selected by `pc_mask`** — this family has no
selector of its own, unlike §5's two halves.

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `gap_hi_pc` | `TIMESTAMP` (0) | `M[1]` | `W[0]` | `pc_gap_hi` | `< 2^19` |
| 1 | `gap_lo_pc` | `TIMESTAMP` | `M[1]` | `4·M[0] − M[3] − 2^19·W[0] − 1` | `4·cycle − pc_read_ts − 2^19·pc_gap_hi − 1` | `< 2^19` |
| 2 | `gap_hi_rs1` | `TIMESTAMP` | `M[6]` | `W[1]` | `rs1_gap_hi` | `< 2^19` |
| 3 | `gap_lo_rs1` | `TIMESTAMP` | `M[6]` | `4·M[0] − M[8] − 2^19·W[1]` | `4·cycle − rs1_read_ts − 2^19·rs1_gap_hi` | `< 2^19` |
| 4 | `gap_hi_rs2` | `TIMESTAMP` | `M[11]` | `W[2]` | `rs2_gap_hi` | `< 2^19` |
| 5 | `gap_lo_rs2` | `TIMESTAMP` | `M[11]` | `4·M[0] − M[13] − 2^19·W[2] + 1` | `4·cycle − rs2_read_ts − 2^19·rs2_gap_hi + 1` | `< 2^19` |
| 6 | `gap_hi_rd` | `TIMESTAMP` | `M[16]` | `W[3]` | `rd_gap_hi` | `< 2^19` |
| 7 | `gap_lo_rd` | `TIMESTAMP` | `M[16]` | `4·M[0] − M[18] − 2^19·W[3] + 2` | `4·cycle − rd_read_ts − 2^19·rd_gap_hi + 2` | `< 2^19` |
| 8 | `rs1_hi_range` | `RANGE16` (1) | `M[1]` | `W[21]` | `rs1_hi` | `< 2^16` |
| 9 | `rs1_lo_range` | `RANGE16` | `M[1]` | `M[9] − 2^16·W[21]` | `rs1_read_value − 2^16·rs1_hi` | `< 2^16` |
| 10 | `rs2_hi_range` | `RANGE16` | `M[1]` | `W[23]` | `rs2_hi` | `< 2^16` |
| 11 | `rs2_lo_range` | `RANGE16` | `M[1]` | `M[14] − 2^16·W[23]` | `rs2_read_value − 2^16·rs2_hi` | `< 2^16` |
| 12 | `p_low_hi_range` | `RANGE16` | `M[1]` | `W[30]` | `p_low_hi` | `< 2^16` |
| 13 | `p_low_lo_range` | `RANGE16` | `M[1]` | `W[29] − 2^16·W[30]` | `p_low − 2^16·p_low_hi` | `< 2^16` |
| 14 | `p_high_hi_range` | `RANGE16` | `M[1]` | `W[32]` | `p_high_hi` | `< 2^16` |
| 15 | `p_high_lo_range` | `RANGE16` | `M[1]` | `W[31] − 2^16·W[32]` | `p_high − 2^16·p_high_hi` | `< 2^16` |
| 16 | `q_hi_range` | `RANGE16` | `M[1]` | `W[35]` | `q_hi` | `< 2^16` |
| 17 | `q_lo_range` | `RANGE16` | `M[1]` | `W[34] − 2^16·W[35]` | `q − 2^16·q_hi` | `< 2^16` |
| 18 | `r_hi_range` | `RANGE16` | `M[1]` | `W[38]` | `r_hi` | `< 2^16` |
| 19 | `r_lo_range` | `RANGE16` | `M[1]` | `W[37] − 2^16·W[38]` | `r − 2^16·r_hi` | `< 2^16` |
| 20 | `gap_hi_range` | `RANGE16` | `M[1]` | `W[48]` | `gap_hi` | `< 2^16` |
| 21 | `gap_lo_range` | `RANGE16` | `M[1]` | `W[47] − 2^16·W[48]` | `gap − 2^16·gap_hi` | `< 2^16` |
| 22 | `rd_hi_range` | `RANGE16` | `M[1]` | `W[49]` | `rd_hi` | `< 2^16` |
| 23 | `rd_lo_range` | `RANGE16` | `M[1]` | `W[6] − 2^16·W[49]` | `rd_selected − 2^16·rd_hi` | `< 2^16` |
| 24 | `rs1_get_sign` | `GENERIC` (2) | `M[1]` | `(W[21] + 256, W[22], 0)` | `(rs1_hi + SIGN_BASE, rs1_top, 0)` | the gated tuple `(rs1_hi + 257, rs1_top, 0)` is a row of `S[6..9]` |
| 25 | `rs2_get_sign` | `GENERIC` | `M[1]` | `(W[23] + 256, W[24], 0)` | `(rs2_hi + SIGN_BASE, rs2_top, 0)` | the gated tuple `(rs2_hi + 257, rs2_top, 0)` is a row of `S[6..9]` |
| 26 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[7], W[8], W[9], W[10], W[11])` | `(pc_read_value, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_mask)` | a row of `S[0..6]`, **six columns** |

Read in pairs: each `gap_hi`/`gap_lo` pair puts a read strictly before its own write, and each
`_hi_range`/`_lo_range` pair bounds `rs1_read_value`, `rs2_read_value`, `p_low`, `p_high`, `q`,
`r`, `gap` and `rd_selected` below `2^32`. The two `_hi_range` obligations keep each sign
lookup's key `hi + 257` in `[257, 2^16 + 256]`, `U16GetSign`'s keys — never the `ZeroEntry`, an
AND key or a `ShiftPowers` key (`lookup.md` §4's precondition, and §5.6 for why the precondition
now matters more than it did) — so the only row that key can meet is `(hi + 257, hi >> 15, 0)`
and each top bit is its operand's bit 31. **There is no copower obligation in this circuit**: no
column here is bounded by scaling, so `check_copowers` has nothing to check and `assemble` does
not call it.

The channels, `mul_div::channels()`, in output order:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[50]` | 8 | 16 |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[51]` | **16** | **32** |
| 6, 7 | `GENERIC` | 2 | `S[6..9]` | `W[52]` | 2 | 4 |
| 8, 9 | `DECODER` | 3 | `S[0..6]` | `W[53]` | 1 | 2 |

`artifact` asserts the four obligation counts. **Sixteen obligations plus one table fraction is
seventeen leaves**, one past a 16-leaf tree, so the `range16` tree pads to 32 and costs a fifth
row-wise level — which is why this circuit is 26 gate lists deep at `n = 20` where §3's and §4's
are 25. Dropping one obligation would take a whole level off the circuit; none is droppable
(`rd_selected`'s pair is the only implied one, and §6.5 G says why it is kept).

### 6.7 Inner layers `L2`–`L6`: the row-wise reduction

The conventions are §3.7's. There are **five** row-wise reduction lists, as in §5.7.

**`L2`, gate list 1, 58 columns, relations 170–227.**

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 170 | `read_2_0` | `read_pc · read_rs1` |
| 1 | 171 | `read_2_1` | `read_rs2 · read_rd` |
| 2 | 172 | `write_2_0` | `write_pc · write_rs1` |
| 3 | 173 | `write_2_1` | `write_rs2 · write_rd` |
| 4, 5 | 174, 175 | `timestamp_2_0` | `timestamp_table + gap_hi_pc` |
| 6, 7 | 176, 177 | `timestamp_2_1` | `gap_lo_pc + gap_hi_rs1` |
| 8, 9 | 178, 179 | `timestamp_2_2` | `gap_lo_rs1 + gap_hi_rs2` |
| 10, 11 | 180, 181 | `timestamp_2_3` | `gap_lo_rs2 + gap_hi_rd` |
| 12, 13 | 182, 183 | `timestamp_2_4` | `gap_lo_rd + timestamp_pad_0` |
| 14, 15 | 184, 185 | `timestamp_2_5` | `timestamp_pad_1 + timestamp_pad_2` |
| 16, 17 | 186, 187 | `timestamp_2_6` | `timestamp_pad_3 + timestamp_pad_4` |
| 18, 19 | 188, 189 | `timestamp_2_7` | `timestamp_pad_5 + timestamp_pad_6` |
| 20, 21 | 190, 191 | `range16_2_0` | `range16_table + rs1_hi_range` |
| 22, 23 | 192, 193 | `range16_2_1` | `rs1_lo_range + rs2_hi_range` |
| 24, 25 | 194, 195 | `range16_2_2` | `rs2_lo_range + p_low_hi_range` |
| 26, 27 | 196, 197 | `range16_2_3` | `p_low_lo_range + p_high_hi_range` |
| 28, 29 | 198, 199 | `range16_2_4` | `p_high_lo_range + q_hi_range` |
| 30, 31 | 200, 201 | `range16_2_5` | `q_lo_range + r_hi_range` |
| 32, 33 | 202, 203 | `range16_2_6` | `r_lo_range + gap_hi_range` |
| 34, 35 | 204, 205 | `range16_2_7` | `gap_lo_range + rd_hi_range` |
| 36, 37 | 206, 207 | `range16_2_8` | `rd_lo_range + range16_pad_0` |
| 38, 39 | 208, 209 | `range16_2_9` | `range16_pad_1 + range16_pad_2` |
| 40, 41 | 210, 211 | `range16_2_10` | `range16_pad_3 + range16_pad_4` |
| 42, 43 | 212, 213 | `range16_2_11` | `range16_pad_5 + range16_pad_6` |
| 44, 45 | 214, 215 | `range16_2_12` | `range16_pad_7 + range16_pad_8` |
| 46, 47 | 216, 217 | `range16_2_13` | `range16_pad_9 + range16_pad_10` |
| 48, 49 | 218, 219 | `range16_2_14` | `range16_pad_11 + range16_pad_12` |
| 50, 51 | 220, 221 | `range16_2_15` | `range16_pad_13 + range16_pad_14` |
| 52, 53 | 222, 223 | `generic_2_0` | `generic_table + rs1_get_sign` |
| 54, 55 | 224, 225 | `generic_2_1` | `rs2_get_sign + generic_pad_0` |
| 56, 57 | 226, 227 | `decoder_2_0` | `decoder_table + decode_row` |

Seven of the sixteen `range16` nodes here combine two pads, which is the cost of one leaf past 16.

**`L3`, gate list 2, 30 columns, relations 228–257.**

| `L3` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 228 | `read_3_0` | `read_2_0 · read_2_1` |
| 1 | 229 | `write_3_0` | `write_2_0 · write_2_1` |
| 2, 3 | 230, 231 | `timestamp_3_0` | `timestamp_2_0 + timestamp_2_1` |
| 4, 5 | 232, 233 | `timestamp_3_1` | `timestamp_2_2 + timestamp_2_3` |
| 6, 7 | 234, 235 | `timestamp_3_2` | `timestamp_2_4 + timestamp_2_5` |
| 8, 9 | 236, 237 | `timestamp_3_3` | `timestamp_2_6 + timestamp_2_7` |
| 10, 11 | 238, 239 | `range16_3_0` | `range16_2_0 + range16_2_1` |
| 12, 13 | 240, 241 | `range16_3_1` | `range16_2_2 + range16_2_3` |
| 14, 15 | 242, 243 | `range16_3_2` | `range16_2_4 + range16_2_5` |
| 16, 17 | 244, 245 | `range16_3_3` | `range16_2_6 + range16_2_7` |
| 18, 19 | 246, 247 | `range16_3_4` | `range16_2_8 + range16_2_9` |
| 20, 21 | 248, 249 | `range16_3_5` | `range16_2_10 + range16_2_11` |
| 22, 23 | 250, 251 | `range16_3_6` | `range16_2_12 + range16_2_13` |
| 24, 25 | 252, 253 | `range16_3_7` | `range16_2_14 + range16_2_15` |
| 26, 27 | 254, 255 | `generic_3_0` | `generic_2_0 + generic_2_1` |
| 28, 29 | 256, 257 | `decoder_3_0` | copy of `decoder_2_0` |

**`L4`, gate list 3, 18 columns, relations 258–275.**

| `L4` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 258 | `read_4_0` | copy of `read_3_0` |
| 1 | 259 | `write_4_0` | copy of `write_3_0` |
| 2, 3 | 260, 261 | `timestamp_4_0` | `timestamp_3_0 + timestamp_3_1` |
| 4, 5 | 262, 263 | `timestamp_4_1` | `timestamp_3_2 + timestamp_3_3` |
| 6, 7 | 264, 265 | `range16_4_0` | `range16_3_0 + range16_3_1` |
| 8, 9 | 266, 267 | `range16_4_1` | `range16_3_2 + range16_3_3` |
| 10, 11 | 268, 269 | `range16_4_2` | `range16_3_4 + range16_3_5` |
| 12, 13 | 270, 271 | `range16_4_3` | `range16_3_6 + range16_3_7` |
| 14, 15 | 272, 273 | `generic_4_0` | copy of `generic_3_0` |
| 16, 17 | 274, 275 | `decoder_4_0` | copy of `decoder_3_0` |

**`L5`, gate list 4, 12 columns, relations 276–287.**

| `L5` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 276 | `read_5_0` | copy of `read_4_0` |
| 1 | 277 | `write_5_0` | copy of `write_4_0` |
| 2, 3 | 278, 279 | `timestamp_5_0` | `timestamp_4_0 + timestamp_4_1` |
| 4, 5 | 280, 281 | `range16_5_0` | `range16_4_0 + range16_4_1` |
| 6, 7 | 282, 283 | `range16_5_1` | `range16_4_2 + range16_4_3` |
| 8, 9 | 284, 285 | `generic_5_0` | copy of `generic_4_0` |
| 10, 11 | 286, 287 | `decoder_5_0` | copy of `decoder_4_0` |

**`L6`, gate list 5, 10 columns, relations 288–297** — the row-wise top: one value per row per
tree.

| `L6` | relations | node | formula | value at row `y` |
| --- | --- | --- | --- | --- |
| 0 | 288 | `read_6_0` | copy of `read_5_0` | the product of row `y`'s 4 read leaves |
| 1 | 289 | `write_6_0` | copy of `write_5_0` | the product of row `y`'s 4 write leaves |
| 2, 3 | 290, 291 | `timestamp_6_0` | copy of `timestamp_5_0` | the sum of row `y`'s 16 timestamp fractions |
| 4, 5 | 292, 293 | `range16_6_0` | `range16_5_0 + range16_5_1` | the sum of row `y`'s 32 range16 fractions |
| 6, 7 | 294, 295 | `generic_6_0` | copy of `generic_5_0` | the sum of row `y`'s 4 generic fractions |
| 8, 9 | 296, 297 | `decoder_6_0` | copy of `decoder_5_0` | the sum of row `y`'s 2 decoder fractions |

### 6.8 The halving layers and the outputs

Gate list `k`, for `6 ≤ k ≤ n + 5`, halves layer `k` into layer `k + 1`, which has `n + 5 − k`
variables. Its ten gates, relation `r = 298 + 10(k − 6)`, are §5.8's table exactly, node for node
and shape for shape. In the last list, `k = n + 5`, the ten nodes are `read_root`, `write_root`,
`timestamp_num_root`, `timestamp_den_root`, `range16_num_root`, `range16_den_root`,
`generic_num_root`, `generic_den_root`, `decoder_num_root` and `decoder_den_root`. At `n = 20`
the halving lists are 6 to 25 and the top is `L26`; at `n = 22` they are 6 to 27 and the top is
`L28`.

**The outputs**, in output-map order, absorbed as one `GKR_OUTPUTS` message before any challenge
of the backward pass and carried in `ShardProof::outputs`.

| # | address, `n = 20` | node | value | what `verify_shard` does with it |
| --- | --- | --- | --- | --- |
| 0 | `L{26}[0]` | `read_root` | the product of every read leaf of the shard | step 10: must equal `PublicInputs::memory_roots[p][0]`, `p` being the position of `(3, shard_index)` in `verifier_core::statement_shards`, after `INIT_TEARDOWN`'s shard, every `ZERO_WINDOWS` shard and every `ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT` and `SHIFT_BITWISE` shard (`shard-proof.md` §1.2); 4 in S18's statement; a factor of `reconciles` |
| 1 | `L{26}[1]` | `write_root` | the product of every write leaf | step 10: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |
| 2 | `L{26}[2]` | `timestamp_num_root` | as §3.8's output 2 | step 9: must be 0; otherwise `Lookup { channel: 0 }` |
| 3 | `L{26}[3]` | `timestamp_den_root` | as §3.8's output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 0 }` |
| 4 | `L{26}[4]` | `range16_num_root` | as output 2, for `RANGE16` | step 9: must be 0; otherwise `Lookup { channel: 1 }` |
| 5 | `L{26}[5]` | `range16_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 1 }` |
| 6 | `L{26}[6]` | `generic_num_root` | as output 2, for `GENERIC` | step 9: must be 0; otherwise `Lookup { channel: 2 }` |
| 7 | `L{26}[7]` | `generic_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 2 }` |
| 8 | `L{26}[8]` | `decoder_num_root` | as output 2, for `DECODER` | step 9: must be 0; otherwise `Lookup { channel: 3 }` |
| 9 | `L{26}[9]` | `decoder_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 3 }` |

### 6.9 Witness rows

The table shows eight of the 63 live `honest_rows` in `crates/checker/tests/mul_div.rs`, and the
padding row. The catalogue is **every one of the eight kinds over all four sign quadrants** —
`(7, 3)`, `(−7, 3)`, `(7, −3)` and `(−7, −3)` as words, 32 rows — plus the 28 edge cases S18's
acceptance 3 and 4 name: `−2^31 × −2^31`; the asymmetric `mulhsu` corner `−2^31 × (2^32 − 1)`;
`mulhu` just under `2^64`; `DIV(−7, 2)` and `REM(−7, 2)`, the rows a floored quotient would also
satisfy the bare division identity on; division by zero for all four kinds; the one signed
overflow `−2^31 ÷ −1`; unsigned division whose remainder's top bit is set; `mul into x0` and
`div into x0`; and `divu by x0`, whose `rs2` is the `x0` register and whose divisor is therefore
zero. `honest` holds every row's `rd_selected` to `rv32m(bit, a, b)`, the ISA's table written out
again from the unprivileged spec, before the row is used at all; then
`every_row_kind_satisfies_every_gate_and_every_bound` holds the row to every gate, every range
obligation and both table channels in CI.

A row is checked alone: each register query reads a write made eight timestamps before its own
and the pc query the previous cycle's, so every `<q>_gap_hi` is 0; the multiplicities are 0;
`S[0..6]` hold the row's own table entry and `S[6..9]` are 0, and the table below omits them.
Every live row shown has cycle 7, pc `0x1000`, `rs1` `x5`, `rs2` `x6` and `rd` `x7`, and `P` is 0
in every cell.

`A` `mul x7, x5, x6` with `x5 = 7`, `x6 = 3`. `B` `mulh` with `x5 = −7`, `x6 = 3`.
`C` `mulhsu` with `x5 = 0x80000000`, `x6 = 0xffffffff` — the asymmetric corner. `D` `div` with
`x5 = −7`, `x6 = 2`. `E` `rem` on the same pair. `F` `divu x7, x5, x6` with
`x5 = 0xdeadbeef`, `x6 = 0` — division by zero. `G` `div` with `x5 = 0x80000000`,
`x6 = 0xffffffff` — the one signed overflow. `H` `mul x0, x5, x6` with `x5 = −7`, `x6 = 3`.
`P` padding.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[3]` `pc_read_ts` | 24 | 24 | 24 | 24 | 24 | 24 | 24 | 24 | 0 |
| `M[4]` `pc_read_value` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | 0 |
| `M[5]` `pc_write_value` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | 0 |
| `M[6]`, `M[11]`, `M[16]` the three masks | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[7]` `rs1_addr` | 5 | 5 | 5 | 5 | 5 | 5 | 5 | 5 | 0 |
| `M[8]`, `M[13]`, `M[18]` read timestamps | 21, 22, 23 | 21, 22, 23 | 21, 22, 23 | 21, 22, 23 | 21, 22, 23 | 21, 22, 23 | 21, 22, 23 | 21, 22, 23 | 0 |
| `M[9]`, `M[10]` `rs1_read_value`, `rs1_write_value` | 7 | `0xfffffff9` | `0x80000000` | `0xfffffff9` | `0xfffffff9` | `0xdeadbeef` | `0x80000000` | `0xfffffff9` | 0 |
| `M[12]` `rs2_addr` | 6 | 6 | 6 | 6 | 6 | 6 | 6 | 6 | 0 |
| `M[14]`, `M[15]` `rs2_read_value`, `rs2_write_value` | 3 | 3 | `0xffffffff` | 2 | 2 | 0 | `0xffffffff` | 3 | 0 |
| `M[17]` `rd_addr` | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 0 | 0 |
| `M[19]` `rd_read_value` | `0x11111111` | `0x11111111` | `0x22222222` | `0x22222222` | `0x22222222` | `0x22222222` | `0x22222222` | 0 | 0 |
| `M[20]` `rd_write_value` | 21 | `0xffffffff` | `0x80000000` | `0xfffffffd` | `0xffffffff` | `0xffffffff` | `0x80000000` | 0 | 0 |
| `W[0..4]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[4]` `rd_inv` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | 0 | 0 |
| `W[5]` `rd_is_zero` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| `W[6]` `rd_selected` | 21 | `0xffffffff` | `0x80000000` | `0xfffffffd` | `0xffffffff` | `0xffffffff` | `0x80000000` | `0xffffffeb` | 0 |
| `W[7]` `decoded_next_pc` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | 0 |
| `W[8]`, `W[9]` `decoded_rs1`, `decoded_rs2` | 5, 6 | 5, 6 | 5, 6 | 5, 6 | 5, 6 | 5, 6 | 5, 6 | 5, 6 | 0 |
| `W[10]` `decoded_rd` | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 0 | 0 |
| `W[11]` `decoded_mask` | 1 | 2 | 4 | `0x10` | `0x40` | `0x20` | `0x10` | 1 | 0 |
| `W[12..20]` the kind bit set | `mul` | `mulh` | `mulhsu` | `div` | `rem` | `divu` | `div` | `mul` | none |
| `W[20]` `f_div` | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 0 |
| `W[21]` `rs1_hi` | 0 | `0xffff` | `0x8000` | `0xffff` | `0xffff` | `0xdead` | `0x8000` | `0xffff` | 0 |
| `W[22]` `rs1_top` | 0 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `W[23]` `rs2_hi` | 0 | 0 | `0xffff` | 0 | 0 | 0 | `0xffff` | 0 | 0 |
| `W[24]` `rs2_top` | 0 | 0 | 1 | 0 | 0 | 0 | 1 | 0 | 0 |
| `W[25]` `s1` | 0 | 1 | 1 | 1 | 1 | **0** | 1 | 1 | 0 |
| `W[26]` `s2` | 0 | 0 | **0** | 0 | 0 | 0 | 1 | 0 | 0 |
| `W[27]` `mx` | 7 | `−7` | `−2^31` | 2 | 2 | 0 | `−1` | `−7` | 0 |
| `W[28]` `my` | 3 | 3 | `0xffffffff` | `−3` | `−3` | `0xffffffff` | `2^31` | 3 | 0 |
| `W[29]` `p_low` | 21 | `0xffffffeb` | `0x80000000` | `0xfffffffa` | `0xfffffffa` | 0 | `0x80000000` | `0xffffffeb` | 0 |
| `W[31]` `p_high` | 0 | `0xffffffff` | `0x80000000` | `0xffffffff` | `0xffffffff` | 0 | `0xffffffff` | `0xffffffff` | 0 |
| `W[33]` `p_sign` | 0 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 0 |
| `W[34]` `q` | 0 | 0 | 0 | `0xfffffffd` | `0xfffffffd` | `0xffffffff` | `0x80000000` | 0 | 0 |
| `W[36]` `q_sign` | 0 | 0 | 0 | 1 | 1 | **0** | **0** | 0 | 0 |
| `W[37]` `r` | 0 | 0 | 0 | `0xffffffff` | `0xffffffff` | `0xdeadbeef` | 0 | 0 | 0 |
| `W[39]` `r_sign` | 0 | 0 | 0 | 1 | 1 | **0** | 0 | 0 | 0 |
| `W[40]` `r_inv` | 0 | 0 | 0 | `(0xffffffff)⁻¹` | `(0xffffffff)⁻¹` | `(0xdeadbeef)⁻¹` | 0 | 0 | 0 |
| `W[41]` `rz` | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `W[42]` `d1` | 0 | 0 | 0 | 1 | 1 | 0 | 1 | 0 | 0 |
| `W[43]` `d_inv` | 0 | 0 | 0 | `2⁻¹` | `2⁻¹` | 0 | `(0xffffffff)⁻¹` | 0 | 0 |
| `W[44]` `dz` | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `W[45]` `abs_r` | 0 | 0 | 0 | 1 | 1 | `0xdeadbeef` | 0 | 0 | 0 |
| `W[46]` `abs_d` | 3 | 3 | `0xffffffff` | 2 | 2 | 0 | 1 | 3 | 0 |
| `W[47]` `gap` | 0 | 0 | 0 | 0 | 0 | `0x21524110` | 0 | 0 | 0 |
| `W[48]` `gap_hi` | 0 | 0 | 0 | 0 | 0 | `0x2152` | 0 | 0 | 0 |
| `W[49]` `rd_hi` | 0 | `0xffff` | `0x8000` | `0xffff` | `0xffff` | `0xffff` | `0x8000` | `0xffff` | 0 |

`W[30]` `p_low_hi`, `W[32]` `p_high_hi`, `W[35]` `q_hi` and `W[38]` `r_hi` are each the high
halfword of the column above them and are omitted; `mx` and `my` are written as signed integers,
their field values being `p − |v|` where negative.

The four bold cells are where the family's shape is easiest to misread. `C`'s `s2` is **0**
though `rs2_top` is 1: `mulhsu` reads its right operand unsigned, so the adjustment flag is
forced to 0 and `my` is the whole word `0xffffffff` — that one cell is the entire asymmetry, and
`abs_d` is `0xffffffff` beside it because `abs_d_rule` is ungated and nothing reads it on a
multiply row. `F`'s `s1` is **0** though `rs1_top` is 1, `divu` being unsigned, which is why its
`d1` and `r_sign` are 0 and its remainder is the dividend read non-negative; its `dz = 1` puts
`2^32` into the gap, so `gap = 2^32 − 0xdeadbeef − 1 = 0x21524110` is in range for any remainder
and the bound says nothing, which is exactly what a zero divisor must do. `G` is the signed
overflow: `q_adj = +2^31` with `q = 0x80000000`, so `q_sign` is **0** while `q`'s top bit is set
— a circuit taking `q_sign` from a sign lookup would have no witness for this row. `A`, `B` and
`H` are the same multiply under three readings: `B`'s `p_high` is the sign-extended `−1`,
`H` computes `0xffffffeb` into `rd_selected` and writes 0, `rd_inv` being 0 at address 0. `D`
and `E` are the truncated pair: `q = −3` and `r = −1`, not the floored `−4` and `1`, and
`r_sign = 1` is what says so.

### 6.10 What fixes each cell

The per-cell accounting is `crates/checker/tests/mul_div.rs`' own, and it is a committed one.
`each_gate_is_the_one_that_refuses_its_row` carries 30 tampers, each an edit to a named honest
row beside **the exact set** of relations that refuse it, asserted equal — and it ends with a
**completeness assertion**: of the family's 54 enforcing gates, the 10 frame gates and every
`*_boolean` set aside, the remaining **28** must each be named by some tamper above, so a gate
added with no forgery beside it fails the suite. `every_booleanity_gate_refuses_a_value_of_two`
covers the sixteen booleans this family commits — the eight kind bits, `f_div`, both top bits,
both sign adjustments, and the product's, quotient's and remainder's sign flags — and six
further tests take one soundness question each.

| cell moved | on the row | refused by, exactly |
| --- | --- | --- |
| `decoded_mask` | `mul 7 3`, claiming `mulh`'s mask | `decoded_mask_bits` |
| `f_div` → 1 | `mul 7 3` | `f_div_rule`, `mx_rule`, `division_rule`, `rz_inverse`, `dz_inverse`, `gap_rule` — six formulas read it |
| `s1` → 1, whole row recomputed | a `mulhu` reading its `rs1` signed | `s1_rule` |
| `s2` → 1, whole row recomputed | a `mulhsu` reading its `rs2` signed | `s2_rule` |
| an `rs1` query added | padding | `rs1_mask_rule` |
| an `rs2` query added | padding | `rs2_mask_rule` |
| an `rd` query into `x0` added | padding | `rd_mask_rule` |
| an `rd` query rewriting `x10` | padding | `rd_mask_rule`, `rd_addr_rule`, `rd_value_rule` |
| `rs1_addr`, `rs2_addr` `+ 1` | `mul 7 3` | `rs1_addr_rule`, `rs2_addr_rule` |
| `rd_addr` → 5 | `mul 7 3` | `rd_addr_rule` |
| `rs1_read_value` → 5 | padding | `rs1_value_masked` |
| `rs2_read_value` → 5, `abs_d` moved to match | padding | `rs2_value_masked` |
| `pc_write_value` `+ 4` | `mul 7 3` | `next_pc_rule` |
| `mx` → 8 | `mul 7 3` | `mx_rule`, `product_rule` |
| `my` → 4 | `mul 7 3` | `my_rule`, `product_rule` |
| `p_high` `+ 1` | `mul 7 3` | `product_rule` |
| `(q, r)` → `(2, 0)` on `DIV(7, 3)`, whole witness recomputed | a forged division | `division_rule` |
| `rz` → 0 | an exact `divu` | `rz_inverse` |
| `rz` → 1, `r_inv` → 0 | an inexact `divu` | `rz_at_nonzero` |
| `dz` → 0 | `divu 0xdeadbeef 0` | `dz_inverse`, `gap_rule` |
| `dz` → 1, `d_inv` → 0 | `divu 7 3` | `dz_at_nonzero`, `gap_rule`, `zero_divisor_quotient` |
| `d1` → 0 | `div 0x80000000 0xffffffff` | `d1_rule` |
| `(q, r)` → the **floored** `(−4, 1)` on `DIV(−7, 2)` | a forged division | `r_sign_rule` |
| `abs_r` `+ 1` | `divu 7 3` | `abs_r_rule`, `gap_rule` |
| `abs_d` `+ 1` | `divu 7 3` | `abs_d_rule`, `gap_rule` |
| `gap` `+ 1` | `divu 7 3` | `gap_rule` |
| `q` → 0 on a zero divisor, whole witness recomputed | a forged `divu` | `zero_divisor_quotient` |
| `rd_selected` `+ 1` | `mul 7 3` | `rd_value_rule` |
| the `rd` query dropped | `mul 7 3` | `rd_write_masked`, `rd_mask_rule` |

The six further tests, each isolating one thing the accounting above cannot show cell by cell:

- **`the_division_encoding_admits_exactly_one_witness_at_a_reduced_width`** — S18's acceptance 5,
  and the reason `arithmetic_gates` takes a width at all. At a **four-bit** word it enumerates
  every `(dividend, divisor)` pair and each of `DIV`, `DIVU`, `REM`, `REMU`, freely varying `q`,
  `r`, `q_sign`, `rz`, `dz`, `r_sign` and `p_sign` and computing every other column from the gate
  that defines it, and asserts that exactly one `(q, r)` survives and that it is the width-four
  RV32M answer. The two operands' top bits are supplied from the table's semantics rather than
  enumerated, because a lookup and not a gate is what pins them. Where the divisor is zero
  **both** values of `q_sign` survive and nothing else varies — the acceptance item's "exactly
  one witness" is true up to that one freedom, and the check asserts the true statement
  (`mul-div.md` §6).
- **`a_quotient_off_by_one_is_refused_by_the_gap_or_by_the_identity`** — the two gates that
  between them leave no room for a neighbouring quotient.
- **`the_signed_overflow_has_exactly_the_pinned_answer`** — `−2^31 ÷ −1` with no pin of its own:
  the three gates that already hold force `q = 0x80000000` and `r = 0`.
- **`a_forged_operand_sign_is_refused_by_its_lookup_alone`** — a top bit claimed wrong with the
  whole row recomputed around it. No gate sees it; `U16GetSign` over the range-checked halfword
  is the lone refusal, which is why §6.6's key bound is load-bearing.

On a padding row `pc_mask = 0`, every frame mask is 0, every leaf is 1 and every obligation is
vacuous. `f_div` is a **free boolean** there, so a padding row may carry a whole division
witness; it constrains nothing, the `rd` query being absent, and it costs no table multiplicity
either, this family having no selector but `pc_mask` and the frame's masks. With every kind bit 0
the gates hold `s1`, `s2`, `mx`, `my`, `rd_selected` and `pc_write_value − decoded_next_pc` to 0,
tie `p_low + 2^32·p_high − 2^64·p_sign` to 0 through `product_rule`, and — where the claimed
`f_div` is 1 — still hold the whole division identity over a zero dividend and a zero divisor,
which `dz = 1` and the correction make satisfiable. The honest fill writes 0 everywhere.

---

## 7. `MEM_WORD` — family 4

### 7.1 Header

`family_circuit(4, n)` is `mem_word::artifact(n)` with `mem_word::channels()`, built by
`memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` through the private
`family_spec` (`QUERIES`, the `SLOT_*` constants and the per-kind constants `LW` and `SW` are
private to `mem_word.rs`). It uses no S17 or S18 gadget: `is_zero` reaches it only through the
frame's x0 rule, which `memory` builds. Normative spec: `memory-ops.md` §3. Fill:
`prover::family_fill(4)`, the private `fill::mem_word`.

62 committed columns (31 `M`, 24 `W`, 7 `S`) and two virtual tables. Gate list 0 writes 68
leaves and holds 33 enforcing gates. 18 lookups on **three** channels, 8 outputs. At `n = 20`,
the height S19 proves, there are 25 gate lists, the top is `L25`, and the circuit has 298 inner
columns and 331 relations; a shard proof of it is 56,268 bytes. At `n = 22` — the committed
fixture — there are 27 lists, the top is `L27`, and it has 314 inner columns, 347 relations and
60,383 bytes of wire form.

**It reads no generic channel, and it is the second registered family that does not.**
`FamilyCircuit::reads_generic_table` is false, so the setup subtree is the decoded table alone —
seven columns, all of them identity's — and a shard opens 62 commitments and no packed-table
triple (`shard-proof.md` §3, §5.1; `jump-branch-slt.md` §6).
`ADD_SUB_LUI_AUIPC` is the precedent for that shape and the only other one.

`artifact` panics unless the frame is `QUERIES`, the channels carry exactly 12, 5 and 1
obligations, `lookup::check_copowers` finds a direct range pair under the same selector for
`word_index_hi` — the one column it bounds by scaling — and every gate is zero on the all-zero
row. It also panics on every refusal of the assembly, among them `n < 19` (the 19-bit timestamp
table needs 19 variables) and `n > 30` (`MAX_TRACE_VARS`); `family_circuit` returns `None` for
both rather than calling it.

### 7.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::mem_word`, bit `k` being
`W[15 + k]`. The decoded table's `imm` is the load's or store's sign-extended twelve-bit
displacement as a two's-complement `u32`; `next_pc` is the fall-through, and no kind here
computes a pc. The effective address is `rs1 + imm` reduced mod `2^32`, split into
`4·word_index` with a wrap bit (`memory-ops.md` §2). **There are no offset bits**: a word access
takes the whole word, so a misaligned `lw` or `sw` has no witness at all (§7.10).

| row kind | bit (`decoded_mask`) | queries present | what it reads | `rd_selected` | `ram_write_value` | `next_pc` |
| --- | --- | --- | --- | --- | --- | --- |
| `lw` | 0 (1) | pc rs1 load rd | `rs1`, and the word at `4·word_index` | the word it read | 0 — no `ram` query | the fall-through |
| `sw` | 1 (2) | pc rs1 rs2 ram | `rs1`, `rs2`, and the word it overwrites | 0 — no `rd` query | `rs2` | the fall-through |
| padding | none; all 0 | none | nothing | 0 | 0 | 0 |

Both kinds are provable at S19. `rd = x0` is not a kind: on an `lw` row into `x0` the table's
`rd` is 0, the frame's x0 rule writes 0, and `rd_selected` keeps the loaded word, which is what
its own range pair bounds (§7.9's row `C`). `rs1 = x0` is not a kind either — a present query at
address 0 reading 0, so the displacement is the whole address. Both kinds have compressed forms
(`c.lw`, `c.sw`, `c.lwsp`, `c.swsp`), so both fall-through widths occur. A live row at a pc
holding no instruction of the family meets the table's `MINUS_ONE` row, which its decoder tuple
cannot equal.

**What this family does not confine is which word a row may name.** An address in no committed
RAM window is refused by the multiset argument at `verify_shard` step 10 and by nothing here
(`memory-ops.md` §2, `memory.md` §9).

### 7.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §7.4 and §7.6.

**Memory-argument columns, `M[0..31]`** — §2's MEM layout (`w = 6`), the 31 columns
`MEM_SUBWORD` also carries and the same bare frame fixture (`memory_frame_mem.bin`), filled by
`trace::build_memory_columns`; committed in `PublicInputs::memory_commitments`, absorbed at G8
before the memory challenges. The frame's slots in `mem_word.rs` are `SLOT_PC = 0`,
`SLOT_RS1 = 1`, `SLOT_RS2 = 2`, `SLOT_LOAD = 3`, `SLOT_RAM = 4`, `SLOT_RD = 5`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the cycle `c` | leaves `write_*` (all 6); obligations `gap_lo_*` (all 6) |
| `M[1]` | `pc_mask` | `frame(0, FIELD_MASK)` | Row is live | 1 | leaves `read_pc`, `write_pc`; `pc_mask_boolean`, the five mask rules; selector of `gap_hi_pc`, `gap_lo_pc`, all five `RANGE16` obligations and `decode_row` |
| `M[2]` | `pc_addr` | `frame(0, FIELD_ADDR)` | PC address | 0 | leaves `read_pc`, `write_pc` |
| `M[3]` | `pc_read_ts` | `frame(0, FIELD_READ_TS)` | Previous pc write | `4(c − 1)` | leaf `read_pc`; `gap_lo_pc` |
| `M[4]` | `pc_read_value` | `frame(0, FIELD_READ_VALUE)` | Current pc | the instruction's pc | leaf `read_pc`; `decode_row` position 0 |
| `M[5]` | `pc_write_value` | `frame(0, FIELD_WRITE_VALUE)` | Next pc | the fall-through | leaf `write_pc`; `next_pc_rule` |
| `M[6]` | `rs1_mask` | `frame(1, FIELD_MASK)` | rs1 present | 1 on both kinds | leaves `read_rs1`, `write_rs1`; `rs1_mask_boolean`, `rs1_mask_rule`, `rs1_addr_rule`, `rs1_value_masked`; selector of `gap_hi_rs1`, `gap_lo_rs1` |
| `M[7]` | `rs1_addr` | `frame(1, FIELD_ADDR)` | Base register | the decoded `rs1` | leaves `read_rs1`, `write_rs1`; `rs1_addr_rule` |
| `M[8]` | `rs1_read_ts` | `frame(1, FIELD_READ_TS)` | rs1 previous write | | leaf `read_rs1`; `gap_lo_rs1` |
| `M[9]` | `rs1_read_value` | `frame(1, FIELD_READ_VALUE)` | Base address | | leaf `read_rs1`; `rs1_writes_back`, `rs1_value_masked`, `addr_split` |
| `M[10]` | `rs1_write_value` | `frame(1, FIELD_WRITE_VALUE)` | rs1 written back | `rs1_read_value` | leaf `write_rs1`; `rs1_writes_back` |
| `M[11]` | `rs2_mask` | `frame(2, FIELD_MASK)` | rs2 present | 1 on `sw` | leaves `read_rs2`, `write_rs2`; `rs2_mask_boolean`, `rs2_mask_rule`, `rs2_addr_rule`, `rs2_value_masked`; selector of `gap_hi_rs2`, `gap_lo_rs2` |
| `M[12]` | `rs2_addr` | `frame(2, FIELD_ADDR)` | Source register | the decoded `rs2` | leaves `read_rs2`, `write_rs2`; `rs2_addr_rule` |
| `M[13]` | `rs2_read_ts` | `frame(2, FIELD_READ_TS)` | rs2 previous write | | leaf `read_rs2`; `gap_lo_rs2` |
| `M[14]` | `rs2_read_value` | `frame(2, FIELD_READ_VALUE)` | The word a store writes | 0 on an `lw` row | leaf `read_rs2`; `rs2_writes_back`, `rs2_value_masked`, `store_value_rule` |
| `M[15]` | `rs2_write_value` | `frame(2, FIELD_WRITE_VALUE)` | rs2 written back | `rs2_read_value` | leaf `write_rs2`; `rs2_writes_back` |
| `M[16]` | `load_mask` | `frame(3, FIELD_MASK)` | The load's word is present | 1 on `lw` | leaves `read_load`, `write_load`; `load_mask_boolean`, `load_mask_rule`, `load_addr_rule`; selector of `gap_hi_load`, `gap_lo_load` |
| `M[17]` | `load_addr` | `frame(3, FIELD_ADDR)` | The word's byte address | `4·word_index` | leaves `read_load`, `write_load`; `load_addr_rule` |
| `M[18]` | `load_read_ts` | `frame(3, FIELD_READ_TS)` | The word's previous write | | leaf `read_load`; `gap_lo_load` |
| `M[19]` | `load_read_value` | `frame(3, FIELD_READ_VALUE)` | The word loaded | | leaf `read_load`; `load_writes_back`, `rd_value_rule` |
| `M[20]` | `load_write_value` | `frame(3, FIELD_WRITE_VALUE)` | The word written back | `load_read_value` | leaf `write_load`; `load_writes_back` |
| `M[21]` | `ram_mask` | `frame(4, FIELD_MASK)` | The store's word is present | 1 on `sw` | leaves `read_ram`, `write_ram`; `ram_mask_boolean`, `ram_mask_rule`, `ram_addr_rule`, `store_value_rule`; selector of `gap_hi_ram`, `gap_lo_ram` |
| `M[22]` | `ram_addr` | `frame(4, FIELD_ADDR)` | The word's byte address | `4·word_index` | leaves `read_ram`, `write_ram`; `ram_addr_rule` |
| `M[23]` | `ram_read_ts` | `frame(4, FIELD_READ_TS)` | The word's previous write | | leaf `read_ram`; `gap_lo_ram` |
| `M[24]` | `ram_read_value` | `frame(4, FIELD_READ_VALUE)` | The word overwritten | | leaf `read_ram` **and nothing else** (§13) |
| `M[25]` | `ram_write_value` | `frame(4, FIELD_WRITE_VALUE)` | The word stored | `rs2_read_value` | leaf `write_ram`; `store_value_rule` |
| `M[26]` | `rd_mask` | `frame(5, FIELD_MASK)` | rd present | 1 on `lw` | leaves `read_rd`, `write_rd`; `rd_mask_boolean`, `rd_is_zero_inverse`, `rd_mask_rule`, `rd_addr_rule`; selector of `gap_hi_rd`, `gap_lo_rd` |
| `M[27]` | `rd_addr` | `frame(5, FIELD_ADDR)` | rd register | the decoded `rd` | leaves `read_rd`, `write_rd`; `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_addr_rule` |
| `M[28]` | `rd_read_ts` | `frame(5, FIELD_READ_TS)` | rd previous write | | leaf `read_rd`; `gap_lo_rd` |
| `M[29]` | `rd_read_value` | `frame(5, FIELD_READ_VALUE)` | rd old value | | leaf `read_rd` **and nothing else** |
| `M[30]` | `rd_write_value` | `frame(5, FIELD_WRITE_VALUE)` | rd new value | the loaded word, or 0 into `x0` | leaf `write_rd`; `rd_write_masked` |

**Witness columns, `W[0..24]`** — `W[0..8]` filled by `trace::build_frame_witness`, `W[8..21]`
by `fill::mem_word` (`W[8]` in place of S14's), `W[21..24]` by `trace::build_multiplicities`
inside `prover::shard_columns`; committed in `ShardProof::witness_commitments`, absorbed at S3
before `g` and `β`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0]` | `pc_gap_hi` | `memory::gap_hi(0)` | pc gap, high chunk | 0: a pc read's gap is always 3 | `gap_hi_pc`, `gap_lo_pc` |
| `W[1]` | `rs1_gap_hi` | `gap_hi(1)` | rs1 gap, high chunk | `gap >> 19` | `gap_hi_rs1`, `gap_lo_rs1` |
| `W[2]` | `rs2_gap_hi` | `gap_hi(2)` | rs2 gap, high chunk | | `gap_hi_rs2`, `gap_lo_rs2` |
| `W[3]` | `load_gap_hi` | `gap_hi(3)` | Load-word gap, high chunk | | `gap_hi_load`, `gap_lo_load` |
| `W[4]` | `ram_gap_hi` | `gap_hi(4)` | Store-word gap, high chunk | | `gap_hi_ram`, `gap_lo_ram` |
| `W[5]` | `rd_gap_hi` | `gap_hi(5)` | rd gap, high chunk | | `gap_hi_rd`, `gap_lo_rd` |
| `W[6]` | `rd_inv` | `memory::rd_inv(6)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[7]` | `rd_is_zero` | `memory::rd_is_zero(6)` | rd is `x0` | | `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_is_zero_boolean`, `rd_write_masked` |
| `W[8]` | `rd_selected` | `memory::rd_selected(6)`; `sel` in `mem_word.rs` | Loaded value | the word an `lw` read, `rd = x0` included; 0 on a store | `rd_write_masked`, `rd_value_rule`; `rd_lo_range` |
| `W[9]` | `decoded_next_pc` | `mem_word::DECODED[0]`; `SEQ` | Decoded fall-through | the table row's `next_pc` | `next_pc_rule`; `decode_row` position 1 |
| `W[10]` | `decoded_rs1` | `DECODED[1]` | Decoded rs1 | | `rs1_addr_rule`; `decode_row` position 2 |
| `W[11]` | `decoded_rs2` | `DECODED[2]` | Decoded rs2 | | `rs2_addr_rule`; `decode_row` position 3 |
| `W[12]` | `decoded_rd` | `DECODED[3]` | Decoded rd | | `rd_addr_rule`; `decode_row` position 4 |
| `W[13]` | `decoded_imm` | `DECODED[4]`; `IMM` | Decoded displacement | the sign-extended offset | `addr_split`; `decode_row` position 5 |
| `W[14]` | `decoded_mask` | `DECODED[5]` | Decoded kind mask | `1 << bit` | `decoded_mask_bits`; `decode_row` position 6 |
| `W[15]` | `kind_lw` | `KINDS[0]`; `LW` | lw row | | `kind_lw_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `load_mask_rule`, `rd_mask_rule`, `rd_value_rule` |
| `W[16]` | `kind_sw` | `KINDS[1]`; `SW` | sw row | | `kind_sw_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `ram_mask_rule` |
| `W[17]` | `wrap` | `mem_word::WRAP` | Address carry | 1 where `rs1 + imm ≥ 2^32` | `wrap_boolean`, `addr_split` |
| `W[18]` | `word_index` | `WORD_INDEX` | The accessed word's index | `addr / 4` | `load_addr_rule`, `ram_addr_rule`, `addr_split`; `word_index_lo_range` |
| `W[19]` | `word_index_hi` | `WORD_INDEX_HI` | `word_index`, high halfword | `addr >> 18` | `word_index_hi_range`, `word_index_lo_range`, `word_index_hi_scaled` |
| `W[20]` | `rd_hi` | `RD_HI` | Loaded value, high halfword | `rd_selected >> 16` | `rd_hi_range`, `rd_lo_range` |
| `W[21]` | `mult_timestamp` | `MULTIPLICITIES[0]` | Timestamp-table count | per table row `t`: the gated gap chunks equal to `t` | leaf `timestamp_table_num` |
| `W[22]` | `mult_range16` | `MULTIPLICITIES[1]` | 16-bit-table count | per table row `t`: the gated halfwords equal to `t`, all five obligations under `pc_mask` | leaf `range16_table_num` |
| `W[23]` | `mult_decoder` | `MULTIPLICITIES[2]` | Decoder-table count | per table row `t`: the live cycles at pc `2t`; and every padding row's switched-off tuple (`MINUS_ONE` in all seven positions) on the table's lowest non-live row, row 0 | leaf `decoder_table_num` |

**Every `RANGE16` obligation of this family is under `pc_mask`**, so on a live row all five are
on and on a padding row all five are off; there is no second selector anywhere in the circuit.
Row 0 of `mult_timestamp` and `mult_range16` therefore counts the twelve and five switched-off
tuples of every padding row, plus every live chunk or halfword whose value is 0.

**Setup columns, `S[0..7]`** — one table. `S[0..7]` is the family's decoded table,
`program::lookup_tuple(4)` order, filled by `program::FamilyTable::column_poly(j)`; committed in
program identity (`program::setup_commitments`) and carried as `VerifyingKey::setup_commitments`
for the family. There is no second setup group: this is the only S19 family with none.

| address | name | Rust | descriptive name | contents | read by | weight |
| --- | --- | --- | --- | --- | --- | --- |
| `S[0]` | `table_pc` | `mem_word::channels()[2].table[0]` | Table pc | `RowField::Pc` | `decoder_table_den` | 1 |
| `S[1]` | `table_next_pc` | `channels()[2].table[1]` | Table fall-through | `RowField::NextPc` | `decoder_table_den` | `β` |
| `S[2]` | `table_rs1` | `channels()[2].table[2]` | Table rs1 | `RowField::Rs1` | `decoder_table_den` | `β²` |
| `S[3]` | `table_rs2` | `channels()[2].table[3]` | Table rs2 | `RowField::Rs2` | `decoder_table_den` | `β³` |
| `S[4]` | `table_rd` | `channels()[2].table[4]` | Table rd | `RowField::Rd` | `decoder_table_den` | `β⁴` |
| `S[5]` | `table_imm` | `channels()[2].table[5]` | Table displacement | `RowField::Imm` | `decoder_table_den` | `β⁵` |
| `S[6]` | `table_extra_mask` | `channels()[2].table[6]` | Table kind mask | `RowField::ExtraMask` | `decoder_table_den` | `β⁶` |

`mem_word::TABLE_WIDTH` is 7.

**Virtual tables** — never committed, never opened; `gkr_verify::verify` evaluates their closed
forms.

| address | name | Rust | descriptive name | value at row `y` | read by |
| --- | --- | --- | --- | --- | --- |
| `V[range19]` | `range19` | `VirtualKind::Range19`, wire tag 2 | 19-bit range table | `y mod 2^19` | `timestamp_table_den` |
| `V[range16]` | `range16` | `VirtualKind::Range16`, wire tag 3 | 16-bit range table | `y mod 2^16` | `range16_table_den` |

### 7.4 Gate list 0: the 68 leaves

A leaf's relation number equals its `L1` offset, 0 to 67.

**The memory product trees.** The read side is `L1[0..8]` and the write side `L1[8..16]`, each
leaf per §0.6. Six queries fill eight leaves a side, so each side carries **two** pads.

| `L1` | node | mask | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `read_pc` | `M[1]` | 3 | `M[2]` | `M[3]` | `M[4]` |
| 1 | `read_rs1` | `M[6]` | 1 | `M[7]` | `M[8]` | `M[9]` |
| 2 | `read_rs2` | `M[11]` | 1 | `M[12]` | `M[13]` | `M[14]` |
| 3 | `read_load` | `M[16]` | 2 | `M[17]` | `M[18]` | `M[19]` |
| 4 | `read_ram` | `M[21]` | 2 | `M[22]` | `M[23]` | `M[24]` |
| 5 | `read_rd` | `M[26]` | 1 | `M[27]` | `M[28]` | `M[29]` |
| 6, 7 | `read_pad_0`, `read_pad_1` | — | — | — | — | the literal 1 |
| 8 | `write_pc` | `M[1]` | 3 | `M[2]` | `4·M[0] + 0` | `M[5]` |
| 9 | `write_rs1` | `M[6]` | 1 | `M[7]` | `4·M[0] + 1` | `M[10]` |
| 10 | `write_rs2` | `M[11]` | 1 | `M[12]` | `4·M[0] + 2` | `M[15]` |
| 11 | `write_load` | `M[16]` | 2 | `M[17]` | `4·M[0] + 2` | `M[20]` |
| 12 | `write_ram` | `M[21]` | 2 | `M[22]` | `4·M[0] + 3` | `M[25]` |
| 13 | `write_rd` | `M[26]` | 1 | `M[27]` | `4·M[0] + 3` | `M[30]` |
| 14, 15 | `write_pad_0`, `write_pad_1` | — | — | — | — | the literal 1 |

`load` and `ram` are the two RAM-space queries, `AS = 2`, and they are the whole difference
from §3's, §4's, §5's and §6's read sides. Their `Δ`s differ — 2 for the load's word, 3 for the
store's — which is how one cycle can read a word at slot 2 and rewrite one at slot 3
(`execution-trace.md` §7); no row of this family does both.

**The `timestamp` fraction tree**, `L1[16..48]`: 16 fractions, the table's then 12 gap
obligations then 3 pads. Fraction `i` is `(L1[16 + 2i], L1[17 + 2i])`, named `<node>_num` and
`<node>_den`.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 16, 17 | `timestamp_table` | `−mult_timestamp` | `V[range19] + g` |
| 1 | 18, 19 | `gap_hi_pc` | 1 | `g + pc_mask·pc_gap_hi` |
| 2 | 20, 21 | `gap_lo_pc` | 1 | `g − pc_mask + 4·pc_mask·cycle − pc_mask·pc_read_ts − 2^19·pc_mask·pc_gap_hi` |
| 3, 4 | 22–25 | `gap_hi_rs1`, `gap_lo_rs1` | 1 | as 1, 2 over `rs1`, whose `Δ − 1` is 0 |
| 5, 6 | 26–29 | `gap_hi_rs2`, `gap_lo_rs2` | 1 | over `rs2`, `Δ − 1 = 1` |
| 7, 8 | 30–33 | `gap_hi_load`, `gap_lo_load` | 1 | over `load`, `Δ − 1 = 1` |
| 9, 10 | 34–37 | `gap_hi_ram`, `gap_lo_ram` | 1 | over `ram`, `Δ − 1 = 2` |
| 11, 12 | 38–41 | `gap_hi_rd`, `gap_lo_rd` | 1 | over `rd`, `Δ − 1 = 2` |
| 13–15 | 42–47 | `timestamp_pad_0` … `timestamp_pad_2` | 0 | 1 |

**The `range16` fraction tree**, `L1[48..64]`: 8 fractions, the table's then 5 obligations then
2 pads. Every obligation is under `pc_mask`.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 48, 49 | `range16_table` | `−mult_range16` | `V[range16] + g` |
| 1 | 50, 51 | `word_index_hi_range` | 1 | `g + pc_mask·word_index_hi` |
| 2 | 52, 53 | `word_index_lo_range` | 1 | `g + pc_mask·word_index − 2^16·pc_mask·word_index_hi` |
| 3 | 54, 55 | `word_index_hi_scaled` | 1 | `g + 4·pc_mask·word_index_hi` |
| 4 | 56, 57 | `rd_hi_range` | 1 | `g + pc_mask·rd_hi` |
| 5 | 58, 59 | `rd_lo_range` | 1 | `g + pc_mask·rd_selected − 2^16·pc_mask·rd_hi` |
| 6, 7 | 60–63 | `range16_pad_0`, `range16_pad_1` | 0 | 1 |

**The `decoder` fraction tree**, `L1[64..68]`: 2 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 64, 65 | `decoder_table` | `−mult_decoder` | `table_pc + β·table_next_pc + β²·table_rs1 + β³·table_rs2 + β⁴·table_rd + β⁵·table_imm + β⁶·table_extra_mask + g` |
| 1 | 66, 67 | `decode_row` | 1 | `g_dec + (1 + β + β² + β³ + β⁴ + β⁵ + β⁶)·pc_mask + pc_mask·pc_read_value + β·pc_mask·decoded_next_pc + β²·pc_mask·decoded_rs1 + β³·pc_mask·decoded_rs2 + β⁴·pc_mask·decoded_rd + β⁵·pc_mask·decoded_imm + β⁶·pc_mask·decoded_mask` |

`decode_row_den` is §5.4's with the decoded row at `W[9..15]`, address for address; the tuple is
seven wide, so `g_dec` is `g − Σ_{j<7} β^j` and `β⁶` is live (§0.4).

### 7.5 Gate list 0: the 33 enforcing gates

Relations 68–100, in list order, in §3.5's format. The family's 20 come from
`mem_word::family_spec` and its private helpers `booleanity`, `mask_rule`, `addr_rule`,
`word_addr_rule` and `value_masked`.

**A. The frame's gates (68–80)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
68–73   <q>_mask_boolean — each query's presence flag is a bit          Quadratic, degree 2
        code  memory::booleanity(frame(s, FIELD_MASK)), in frame_body

  68 pc_mask_boolean    M[1]      71 load_mask_boolean  M[16]
  69 rs1_mask_boolean   M[6]      72 ram_mask_boolean   M[21]
  70 rs2_mask_boolean   M[11]     73 rd_mask_boolean    M[26]

────────────────────────────────────────────────────────────────────────────────────────────
74–76   <q>_writes_back — a read-only query leaves its cell unchanged   Linear, degree 1
        code  memory::write_back(s), in frame_body

  74 rs1_writes_back    0 = M[10] − M[9]     0 = rs1_write_value  − rs1_read_value
  75 rs2_writes_back    0 = M[15] − M[14]    0 = rs2_write_value  − rs2_read_value
  76 load_writes_back   0 = M[20] − M[19]    0 = load_write_value − load_read_value

  reads as  76 is the one this frame has that §4's, §5's and §6's do not: a load reads a RAM
            word and writes back exactly what it read, so the word's own value survives the
            cycle and only the timestamp moves (memory.md §2.4).

────────────────────────────────────────────────────────────────────────────────────────────
77–80   the x0 rule                                                    Quadratic, degree 2
        code  memory::x0_gates(5, 6), whose first two are
              gadgets::is_zero(&[(1, rd_addr)], rd_inv, rd_is_zero, rd_mask)

  77 rd_is_zero_inverse     0 = W[7] − M[26] + M[27]·W[6]
  78 rd_is_zero_at_nonzero  0 = M[27]·W[7]
  79 rd_is_zero_boolean     0 = W[7] − W[7]·W[7]
  80 rd_write_masked        0 = M[30] − W[8] + W[7]·W[8]
                            0 = rd_write_value − (1 − rd_is_zero)·rd_selected

  reads as (68–80)  §2.3's, over six queries instead of four: the bare frame fixture is
                    memory_frame_mem.bin, which MEM_SUBWORD carries too.
```

**B. What the row is (81–84)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
81–82   kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2
        code  mem_word's private booleanity(KINDS[k])

  81 kind_lw_boolean   0 = W[15] − W[15]·W[15]
  82 kind_sw_boolean   0 = W[16] − W[16]·W[16]

────────────────────────────────────────────────────────────────────────────────────────────
83      decoded_mask_bits — the packed mask is its two bits             Linear, degree 1
        code  mem_word::family_spec, `bits`

  positional  0 = W[15] + 2·W[16] − W[14]
  named       0 = kind_lw + 2·kind_sw − decoded_mask

  reads as  §5.5's 146 over two bits. One-hotness is not here: the decoder table, whose
            masks are single bits, is what enforces it (lookup.md §10), and on a padding
            row, where the lookup is off, the two bits are free.

────────────────────────────────────────────────────────────────────────────────────────────
84      wrap_boolean — the address carry is a bit                       Quadratic, degree 2
        code  booleanity(WRAP)

  84 wrap_boolean  0 = W[17] − W[17]·W[17]    0 = wrap − wrap²

  reads as  the carry is worth 2^32 in 97, so a wrap of two moves the effective address by
            2^33 and the split would still hold over Fr. This gate is what keeps 97 an
            integer statement (§7.10's `an lw claiming a wrap of two`).
```

**C. Which queries a row makes, and where (85–96)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
85–89   <q>_mask_rule — a query is present exactly where its kind uses it   Quadratic, deg 2
        code  mask_rule(frame(s, FIELD_MASK), &[..])

  85 rs1_mask_rule    0 = M[6]  − M[1]·W[15] − M[1]·W[16]
                      0 = rs1_mask  − pc_mask·(kind_lw + kind_sw)
  86 rs2_mask_rule    0 = M[11] − M[1]·W[16]    0 = rs2_mask  − pc_mask·kind_sw
  87 load_mask_rule   0 = M[16] − M[1]·W[15]    0 = load_mask − pc_mask·kind_lw
  88 ram_mask_rule    0 = M[21] − M[1]·W[16]    0 = ram_mask  − pc_mask·kind_sw
  89 rd_mask_rule     0 = M[26] − M[1]·W[15]    0 = rd_mask   − pc_mask·kind_lw

  reads as  the five together are the family's whole statement about presence: a load reads
            rs1 and one RAM word at slot 2 and writes rd; a store reads rs1 and rs2 and
            rewrites one RAM word at slot 3. On a padding row pc_mask = 0 and every mask is
            0 whatever the bits hold — S14's control C8, which §7.10 refuses twice.

────────────────────────────────────────────────────────────────────────────────────────────
90–92   <q>_addr_rule — a present register query's index is the decoded one  Quadratic, deg 2
        code  addr_rule(slot, DECODED_<Q>)

  90 rs1_addr_rule   0 = M[6]·M[7]   − M[6]·W[10]
  91 rs2_addr_rule   0 = M[11]·M[12] − M[11]·W[11]
  92 rd_addr_rule    0 = M[26]·M[27] − M[26]·W[12]

────────────────────────────────────────────────────────────────────────────────────────────
93–94   <q>_addr_rule — a present RAM query names the word, not the byte  Quadratic, degree 2
        code  word_addr_rule(slot)

  93 load_addr_rule  0 = M[16]·M[17] − 4·M[16]·W[18]
                     0 = load_mask·(load_addr − 4·word_index)
  94 ram_addr_rule   0 = M[21]·M[22] − 4·M[21]·W[18]
                     0 = ram_mask·(ram_addr − 4·word_index)

  reads as  the memory tuple's address is the word's byte address and never a byte address
            inside it. A byte-address form here would be a broken memory model — the same
            cell under four names — and it is what §8 relies on when it splices a sub-word
            out of the same word (memory-ops.md §2).

────────────────────────────────────────────────────────────────────────────────────────────
95–96   <q>_value_masked — an absent operand reads 0                   Quadratic, degree 2
        code  value_masked(slot)

  95 rs1_value_masked  0 = M[9]  − M[6]·M[9]
  96 rs2_value_masked  0 = M[14] − M[11]·M[14]

  reads as  96 is what lets `store_value_rule` be one expression: an lw row's rs2 reads 0, so
            the gate writes 0 into a word it has no query for, and the ram mask is 0 anyway.
            There is no value_masked on `load` or `ram`: a RAM query's read value is the word
            the multiset pins, not an operand the row supplies.
```

**D. The address, and the two copies (97–100)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
97      addr_split — the effective address is four times a word index   Linear, degree 1
        code  mem_word::family_spec, the inline `addr_split`

  positional  0 = M[9] + W[13] − 2^32·W[17] − 4·W[18]
  named       0 = rs1_read_value + decoded_imm − 2^32·wrap − 4·word_index

  reads as  over Fr this says nothing: 4 is a unit, so word_index := addr·4⁻¹ solves it for
            any address at all. What makes it base-4 is the three obligations of §7.6 on
            word_index, which hold it below 2^30 and so make both sides integers below 2^34.
            Then `wrap` is pinned in both directions and a misaligned access has no witness
            (memory-ops.md §2; §7.10's two alignment tests).

────────────────────────────────────────────────────────────────────────────────────────────
98      rd_value_rule — a load writes the word it read                 Quadratic, degree 2
        code  family_spec, over LW and the load query's read value

  positional  0 = W[8] − W[15]·M[19]
  named       0 = rd_selected − kind_lw·load_read_value

  reads as  the whole semantics of `lw`. `load_read_value` carries no bound of its own — a
            value read from memory is exempt, on the write-side induction — so what makes it
            a word is the multiset: some earlier write put it there, and that write was
            bounded. `rd_selected`'s own 16+16 pair is what carries the bound into the
            register file (memory-ops.md §5.1).

────────────────────────────────────────────────────────────────────────────────────────────
99      store_value_rule — a store writes rs2 into the word            Quadratic, degree 2
        code  family_spec, over the ram mask and rs2's read value

  positional  0 = M[25] − M[21]·M[14]
  named       0 = ram_write_value − ram_mask·rs2_read_value

  reads as  the whole semantics of `sw`, and the reason the family needs no bound on what it
            stores: a register value is bounded where it was written. Gated by the ram mask
            rather than by `kind_sw`, so a row with no RAM query writes 0 there.

────────────────────────────────────────────────────────────────────────────────────────────
100     next_pc_rule — the next pc is the decoded fall-through         Linear, degree 1
        code  family_spec, the inline `next_pc_rule`

  positional  0 = M[5] − W[9]
  named       0 = pc_write_value − decoded_next_pc

  reads as  §5.5's and §6.5's: no kind here computes a pc, so there is no wrap bit, no bound
            and no evenness check. The decoder lookup binds the table's fall-through exactly
            as it binds rs1, rs2, rd and imm, none of which is range-checked either, and
            S17's rule that a family computing a pc keeps it even does not reach one that
            copies one.
```

### 7.6 The 18 lookups

`CircuitArtifact::lookups`, in order. The frame's 12 come from the private
`memory::gap_lookups`; the rest from `mem_word::family_spec` (its private `range16`, `range32`
and the inline `decode_row`). **Every one of the five `RANGE16` obligations is selected by
`pc_mask`**: this family has no second selector.

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `gap_hi_pc` | `TIMESTAMP` (0) | `M[1]` | `W[0]` | `pc_gap_hi` | `< 2^19` |
| 1 | `gap_lo_pc` | `TIMESTAMP` | `M[1]` | `4·M[0] − M[3] − 2^19·W[0] − 1` | `4·cycle − pc_read_ts − 2^19·pc_gap_hi − 1` | `< 2^19` |
| 2, 3 | `gap_hi_rs1`, `gap_lo_rs1` | `TIMESTAMP` | `M[6]` | `W[1]`; `4·M[0] − M[8] − 2^19·W[1]` | over `rs1` | `< 2^19` |
| 4, 5 | `gap_hi_rs2`, `gap_lo_rs2` | `TIMESTAMP` | `M[11]` | `W[2]`; `4·M[0] − M[13] − 2^19·W[2] + 1` | over `rs2` | `< 2^19` |
| 6, 7 | `gap_hi_load`, `gap_lo_load` | `TIMESTAMP` | `M[16]` | `W[3]`; `4·M[0] − M[18] − 2^19·W[3] + 1` | over the load's word | `< 2^19` |
| 8, 9 | `gap_hi_ram`, `gap_lo_ram` | `TIMESTAMP` | `M[21]` | `W[4]`; `4·M[0] − M[23] − 2^19·W[4] + 2` | over the store's word | `< 2^19` |
| 10, 11 | `gap_hi_rd`, `gap_lo_rd` | `TIMESTAMP` | `M[26]` | `W[5]`; `4·M[0] − M[28] − 2^19·W[5] + 2` | over `rd` | `< 2^19` |
| 12 | `word_index_hi_range` | `RANGE16` (1) | `M[1]` | `W[19]` | `word_index_hi` | `< 2^16` |
| 13 | `word_index_lo_range` | `RANGE16` | `M[1]` | `W[18] − 2^16·W[19]` | `word_index − 2^16·word_index_hi` | `< 2^16` |
| 14 | `word_index_hi_scaled` | `RANGE16` | `M[1]` | `4·W[19]` | `4·word_index_hi` | `< 2^16`, i.e. `word_index_hi < 2^14` |
| 15 | `rd_hi_range` | `RANGE16` | `M[1]` | `W[20]` | `rd_hi` | `< 2^16` |
| 16 | `rd_lo_range` | `RANGE16` | `M[1]` | `W[8] − 2^16·W[20]` | `rd_selected − 2^16·rd_hi` | `< 2^16` |
| 17 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[9], W[10], W[11], W[12], W[13], W[14])` | `(pc_read_value, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_imm, decoded_mask)` | a row of `S[0..7]` |

Read in pairs, as in §3.6 to §6.6: each `gap_hi`/`gap_lo` pair puts a read strictly before its
own write, and `rd_hi_range`/`rd_lo_range` bounds `rd_selected` below `2^32`.

**The three obligations on `word_index` are this family's whole soundness argument about
addressing**, and the third is not a duplicate of the first two. `word_index_hi_scaled` holds
`4·word_index_hi` below `2^16`, so `word_index_hi < 2^14`; with the pair, `word_index < 2^30`
and `4·word_index ≤ 2^32 − 4`. **The bound is exactly tight**: the top word of the address
space, `0xfffffffc`, needs `word_index = 2^30 − 1`, `word_index_hi = 0x3fff` and a scaled value
of `0xfffc`, just inside `2^16` — which is §7.9's row `F`. Scaling by 2 instead of 4 would make
the top quarter of the address space unprovable; dropping the obligation would let
`4·word_index` reach `2^33`, an address no 32-bit query can name and one the multiset would
chain against nothing (§7.10's `a_word_index_above_2_to_the_30_is_refused`).
`lookup::check_copowers` takes `(word_index_hi, pc_mask)`, so an edit that narrows or drops the
direct pair fails the build rather than the argument, and `a_dropped_obligation_fails_the_build`
and `word_index_without_its_direct_bound_fails_the_build` in `mem_word.rs` are those two
refusals.

The channels, `mem_word::channels()`, in output order. **There are three**, and the generic
channel is absent:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[21]` | 12 | 16 |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[22]` | 5 | 8 |
| 6, 7 | `DECODER` | 3 | `S[0..7]` | `W[23]` | 1 | 2 |

`artifact` asserts the three obligation counts. The largest tree is the timestamp's at 16
leaves, so `R = 4` and the circuit is 25 lists deep at `n = 20` — §3's and §4's depth, not §5's
and §6's.

### 7.7 Inner layers `L2`–`L5`: the row-wise reduction

The conventions are §3.7's. There are four row-wise reduction lists.

**`L2`, gate list 1, 34 columns, relations 101–134.**

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 101 | `read_2_0` | `read_pc · read_rs1` |
| 1 | 102 | `read_2_1` | `read_rs2 · read_load` |
| 2 | 103 | `read_2_2` | `read_ram · read_rd` |
| 3 | 104 | `read_2_3` | `read_pad_0 · read_pad_1` |
| 4–7 | 105–108 | `write_2_0` … `write_2_3` | the same over the write side |
| 8, 9 | 109, 110 | `timestamp_2_0` | `timestamp_table + gap_hi_pc` |
| 10, 11 | 111, 112 | `timestamp_2_1` | `gap_lo_pc + gap_hi_rs1` |
| 12, 13 | 113, 114 | `timestamp_2_2` | `gap_lo_rs1 + gap_hi_rs2` |
| 14, 15 | 115, 116 | `timestamp_2_3` | `gap_lo_rs2 + gap_hi_load` |
| 16, 17 | 117, 118 | `timestamp_2_4` | `gap_lo_load + gap_hi_ram` |
| 18, 19 | 119, 120 | `timestamp_2_5` | `gap_lo_ram + gap_hi_rd` |
| 20, 21 | 121, 122 | `timestamp_2_6` | `gap_lo_rd + timestamp_pad_0` |
| 22, 23 | 123, 124 | `timestamp_2_7` | `timestamp_pad_1 + timestamp_pad_2` |
| 24, 25 | 125, 126 | `range16_2_0` | `range16_table + word_index_hi_range` |
| 26, 27 | 127, 128 | `range16_2_1` | `word_index_lo_range + word_index_hi_scaled` |
| 28, 29 | 129, 130 | `range16_2_2` | `rd_hi_range + rd_lo_range` |
| 30, 31 | 131, 132 | `range16_2_3` | `range16_pad_0 + range16_pad_1` |
| 32, 33 | 133, 134 | `decoder_2_0` | `decoder_table + decode_row` |

**`L3`, gate list 2, 18 columns, relations 135–152.**

| `L3` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 135 | `read_3_0` | `read_2_0 · read_2_1` |
| 1 | 136 | `read_3_1` | `read_2_2 · read_2_3` |
| 2, 3 | 137, 138 | `write_3_0`, `write_3_1` | the same over the write side |
| 4, 5 | 139, 140 | `timestamp_3_0` | `timestamp_2_0 + timestamp_2_1` |
| 6, 7 | 141, 142 | `timestamp_3_1` | `timestamp_2_2 + timestamp_2_3` |
| 8, 9 | 143, 144 | `timestamp_3_2` | `timestamp_2_4 + timestamp_2_5` |
| 10, 11 | 145, 146 | `timestamp_3_3` | `timestamp_2_6 + timestamp_2_7` |
| 12, 13 | 147, 148 | `range16_3_0` | `range16_2_0 + range16_2_1` |
| 14, 15 | 149, 150 | `range16_3_1` | `range16_2_2 + range16_2_3` |
| 16, 17 | 151, 152 | `decoder_3_0` | copy of `decoder_2_0` |

**`L4`, gate list 3, 10 columns, relations 153–162.**

| `L4` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 153 | `read_4_0` | `read_3_0 · read_3_1` |
| 1 | 154 | `write_4_0` | `write_3_0 · write_3_1` |
| 2, 3 | 155, 156 | `timestamp_4_0` | `timestamp_3_0 + timestamp_3_1` |
| 4, 5 | 157, 158 | `timestamp_4_1` | `timestamp_3_2 + timestamp_3_3` |
| 6, 7 | 159, 160 | `range16_4_0` | `range16_3_0 + range16_3_1` |
| 8, 9 | 161, 162 | `decoder_4_0` | copy of `decoder_3_0` |

**`L5`, gate list 4, 8 columns, relations 163–170.**

| `L5` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 163 | `read_5_0` | copy of `read_4_0` |
| 1 | 164 | `write_5_0` | copy of `write_4_0` |
| 2, 3 | 165, 166 | `timestamp_5_0` | `timestamp_4_0 + timestamp_4_1` |
| 4, 5 | 167, 168 | `range16_5_0` | copy of `range16_4_0` |
| 6, 7 | 169, 170 | `decoder_5_0` | copy of `decoder_4_0` |

### 7.8 The halving layers and the outputs

Gate list `k`, for `5 ≤ k ≤ n + 4`, halves layer `k` into layer `k + 1`, which has `n + 4 − k`
variables. Its eight gates, relation `r = 171 + 8(k − 5)`, with §3.8's formulas:

| `L{k+1}` | relation | node | shape |
| --- | --- | --- | --- |
| 0 | `r` | `read_{k+1}_0` | `TreeProduct { L{k}[0] }` |
| 1 | `r + 1` | `write_{k+1}_0` | `TreeProduct { L{k}[1] }` |
| 2 | `r + 2` | `timestamp_{k+1}_0_num` | `TreeCross { L{k}[2], L{k}[3] }` |
| 3 | `r + 3` | `timestamp_{k+1}_0_den` | `TreeProduct { L{k}[3] }` |
| 4 | `r + 4` | `range16_{k+1}_0_num` | `TreeCross { L{k}[4], L{k}[5] }` |
| 5 | `r + 5` | `range16_{k+1}_0_den` | `TreeProduct { L{k}[5] }` |
| 6 | `r + 6` | `decoder_{k+1}_0_num` | `TreeCross { L{k}[6], L{k}[7] }` |
| 7 | `r + 7` | `decoder_{k+1}_0_den` | `TreeProduct { L{k}[7] }` |

In the last list, `k = n + 4`, the eight nodes are named `read_root`, `write_root`,
`timestamp_num_root`, `timestamp_den_root`, `range16_num_root`, `range16_den_root`,
`decoder_num_root` and `decoder_den_root`. At `n = 20` the halving lists are 5 to 24, `L6` has
19 variables and `L25` none. At `n = 22` they are 5 to 26, and the top is `L27`.

**The outputs**, in output-map order. All eight are absorbed as one `GKR_OUTPUTS` message before
any challenge of the backward pass, and travel in `ShardProof::outputs`.

| # | address, `n = 20` | node | value | what `verify_shard` does with it |
| --- | --- | --- | --- | --- |
| 0 | `L{25}[0]` | `read_root` | the product of every read leaf of the shard | step 10: must equal `PublicInputs::memory_roots[p][0]`, `p` being the position of `(4, shard_index)` in `verifier_core::statement_shards`; a factor of `reconciles` |
| 1 | `L{25}[1]` | `write_root` | the product of every write leaf | step 10: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |
| 2 | `L{25}[2]` | `timestamp_num_root` | as §3.8's output 2 | step 9: must be 0; otherwise `Lookup { channel: 0 }` |
| 3 | `L{25}[3]` | `timestamp_den_root` | as §3.8's output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 0 }` |
| 4 | `L{25}[4]` | `range16_num_root` | as output 2, for `RANGE16` | step 9: must be 0; otherwise `Lookup { channel: 1 }` |
| 5 | `L{25}[5]` | `range16_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 1 }` |
| 6 | `L{25}[6]` | `decoder_num_root` | as output 2, for `DECODER` | step 9: must be 0; otherwise `Lookup { channel: 3 }` |
| 7 | `L{25}[7]` | `decoder_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 3 }` |

**Eight outputs, not ten.** A shard proof of this family carries `2 + 2·3` (`mem.rs`
acceptance 1), where every other S19 family carries `2 + 2·4`: there is no generic pair.

### 7.9 Witness rows

The table shows eight of the 51 live rows of `guests/mem`'s `MEM_WORD` shard, as
`prover::family_fill(4)` writes them, plus the first padding row after them.
`crates/checker/tests/mem_fill.rs`' `the_mem_word_fill_satisfies_every_gate_and_every_table`
holds exactly these columns to every gate, every range obligation and the decoder channel in
ordinary CI, over every live row, the two padding rows after them and the shard's last row, with
`trace::build_multiplicities` counting every gated tuple against its table. The circuit is also
held to a hand-built catalogue of its own: `crates/checker/tests/mem_word.rs`' `honest_rows`,
twelve live rows and the padding row, built from Rust's own `u32` arithmetic rather than from a
trace — both kinds, an `x0` destination and an `x0` source, a compressed `lw`, the top of the
address space and `RAM_ORIGIN`, a store whose address wraps, a negative displacement with and
without a carry, a load through `x0`, and `lw` at `0xfffffffc + 4`, which is `2^32` exactly and
so wraps to word 0. §7.10's forgeries all start from that catalogue.

`A` `sw` at `0x10018`, storing `x5 = 0x89abcdef` through `x9 = 0x20000` at displacement 0.
`B` the `lw` after it, reading the same word into `x6`. `C` `lw` into `x0`, which reads the
word and writes nothing. `D` `sw` at displacement 4, one word along. `E` `sw` through
`x18 = 0x7ffffef0`, near the top of RAM and in window 8191. `F` a **compressed** `sw`, whose
fall-through is `pc + 2`. `G` the compressed `lw` after it. `H` `lw` from the high window.
`P` the first padding row. Every cell not listed is 0 on all nine; `S[0..7]` hold
`MINUS_ONE` at these rows, the table row being pc `2y`, and are omitted.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 7 | 8 | 22 | 13 | 29 | 37 | 38 | 299 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[3]` `pc_read_ts` | 24 | 28 | 84 | 48 | 112 | 144 | 148 | 1192 | 0 |
| `M[4]` `pc_read_value` | `0x10018` | `0x1001c` | `0x10054` | `0x10030` | `0x10070` | `0x10090` | `0x10092` | `0x104a4` | 0 |
| `M[5]` `pc_write_value` | `0x1001c` | `0x10020` | `0x10058` | `0x10034` | `0x10074` | `0x10092` | `0x10094` | `0x104a8` | 0 |
| `M[6]` `rs1_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[7]` `rs1_addr` | 9 | 9 | 9 | 9 | 18 | 11 | 11 | 14 | 0 |
| `M[9]`, `M[10]` `rs1_read_value`, `rs1_write_value` | `0x20000` | `0x20000` | `0x20000` | `0x20000` | `0x7ffffef0` | `0x20020` | `0x20020` | `0x7fffff00` | 0 |
| `M[11]` `rs2_mask` | 1 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 0 |
| `M[12]` `rs2_addr` | 5 | 0 | 0 | 5 | 5 | 10 | 0 | 0 | 0 |
| `M[14]`, `M[15]` `rs2_read_value`, `rs2_write_value` | `0x89abcdef` | 0 | 0 | `0x0f0f0f0f` | `0x12345678` | `0x0badf00d` | 0 | 0 | 0 |
| `M[16]` `load_mask` | 0 | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 0 |
| `M[17]` `load_addr` | 0 | `0x20000` | `0x20000` | 0 | 0 | 0 | `0x20020` | `0x7fffff00` | 0 |
| `M[19]`, `M[20]` `load_read_value`, `load_write_value` | 0 | `0x89abcdef` | `0x89abcdef` | 0 | 0 | 0 | `0x0badf00d` | `0xd000` | 0 |
| `M[21]` `ram_mask` | 1 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 0 |
| `M[22]` `ram_addr` | `0x20000` | 0 | 0 | `0x20004` | `0x7ffffef0` | `0x20020` | 0 | 0 | 0 |
| `M[24]` `ram_read_value` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `M[25]` `ram_write_value` | `0x89abcdef` | 0 | 0 | `0x0f0f0f0f` | `0x12345678` | `0x0badf00d` | 0 | 0 | 0 |
| `M[26]` `rd_mask` | 0 | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 0 |
| `M[27]` `rd_addr` | 0 | 6 | 0 | 0 | 0 | 0 | 12 | 28 | 0 |
| `M[29]` `rd_read_value` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 10 | 0 |
| `M[30]` `rd_write_value` | 0 | `0x89abcdef` | 0 | 0 | 0 | 0 | `0x0badf00d` | `0xd000` | 0 |
| `W[0..6]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[6]` `rd_inv` | 0 | `6⁻¹` | 0 | 0 | 0 | 0 | `12⁻¹` | `28⁻¹` | 0 |
| `W[7]` `rd_is_zero` | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[8]` `rd_selected` | 0 | `0x89abcdef` | `0x89abcdef` | 0 | 0 | 0 | `0x0badf00d` | `0xd000` | 0 |
| `W[9]` `decoded_next_pc` | `0x1001c` | `0x10020` | `0x10058` | `0x10034` | `0x10074` | `0x10092` | `0x10094` | `0x104a8` | 0 |
| `W[10]` `decoded_rs1` | 9 | 9 | 9 | 9 | 18 | 11 | 11 | 14 | 0 |
| `W[11]` `decoded_rs2` | 5 | 0 | 0 | 5 | 5 | 10 | 0 | 0 | 0 |
| `W[12]` `decoded_rd` | 0 | 6 | 0 | 0 | 0 | 0 | 12 | 28 | 0 |
| `W[13]` `decoded_imm` | 0 | 0 | 0 | 4 | 0 | 0 | 0 | 0 | 0 |
| `W[14]` `decoded_mask` | 2 | 1 | 1 | 2 | 2 | 2 | 1 | 1 | 0 |
| `W[15]`, `W[16]` the kind bit set | `sw` | `lw` | `lw` | `sw` | `sw` | `sw` | `lw` | `lw` | none |
| `W[17]` `wrap` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[18]` `word_index` | `0x8000` | `0x8000` | `0x8000` | `0x8001` | `0x1fffffbc` | `0x8008` | `0x8008` | `0x1fffffc0` | 0 |
| `W[19]` `word_index_hi` | 0 | 0 | 0 | 0 | `0x1fff` | 0 | 0 | `0x1fff` | 0 |
| `W[20]` `rd_hi` | 0 | `0x89ab` | `0x89ab` | 0 | 0 | 0 | `0x0bad` | 0 | 0 |

`E` and `H` are the rows that make RAM window 8191 the statement's one `ZERO_WINDOWS` shard:
their byte addresses `0x7ffffef0` and `0x7fffff00` are `4h·8191 + 4y` at `h = 2^16`. `A` and `D`
are the two stores whose `ram_read_value` is 0 — the word they overwrite has never been written,
so the image's 0 is what the multiset hands them, and no gate of this family looks at it (§13).
`C` is the `x0` destination: `rd_selected` carries the whole loaded word, `rd_hi` bounds it, and
`rd_write_masked` writes 0. `F` and `G` are the compressed pair, `pc + 2` on both sides of
`next_pc_rule`. The multiplicity columns are not shown: on a real shard they are the counts over
the whole `2^20` rows, and row 0 of `mult_timestamp` and `mult_range16` carries the twelve and
five switched-off tuples of each of the `2^20 − 51` padding rows.

### 7.10 What fixes each cell

The per-cell accounting is `crates/checker/tests/mem_word.rs`' own, and it is a committed one:
`each_gate_is_the_one_that_refuses_its_row` carries 21 tampers, each an edit to a named honest
row beside **the exact set** of relations that refuse it, asserted equal — not a membership — so
a gate that stopped being load-bearing on the row shape it exists for fails the suite. It ends
with a **completeness assertion**: of the circuit's 33 enforcing gates the frame's thirteen are
set aside, and each of the remaining **20** must be named by some tamper above, so a gate added
with no forgery beside it fails here rather than silently. The table below is that list read as a
cell-by-cell account. The three booleans this family commits — the two kind bits and the wrap —
carry the `x² = x` gates named above, and four further tests take one question each.

| cell moved | on the row | refused by, exactly |
| --- | --- | --- |
| `kind_lw` → 2, packed mask moved with it | padding | `kind_lw_boolean` |
| `kind_sw` → 2, packed mask moved with it | padding | `kind_sw_boolean` |
| `decoded_mask` → `sw`'s | `lw` | `decoded_mask_bits` |
| `wrap` → 2, `word_index` and the query's address moved so the split and the address rule still hold | `lw` | `wrap_boolean` |
| the `rs1` query dropped | `a load through x0`, whose base register reads 0 | `rs1_mask_rule` |
| an `rs2` query added | `lw` | `rs2_mask_rule` |
| a `load` query added | `sw` | `load_mask_rule` |
| a `ram` query added, writing 0 | `lw` | `ram_mask_rule` |
| an `rd` query into `x0` added | `sw` | `rd_mask_rule` |
| `rs1_addr` `+ 1` | `lw` | `rs1_addr_rule` |
| `rs2_addr` `+ 1` | `sw` | `rs2_addr_rule` |
| `rd_addr` → 5 | `lw` | `rd_addr_rule` |
| `load_addr` `+ 4` | `lw` | `load_addr_rule` |
| `ram_addr` `+ 4` | `sw` | `ram_addr_rule` |
| `rs1_read_value` → 4, `word_index` → 1 | padding | `rs1_value_masked` |
| `rs2_read_value` → 5 | `lw` | `rs2_value_masked` |
| `word_index` `+ 1`, the query's address `+ 4` | `lw` | `addr_split` |
| `rd_selected` `+ 1`, with `rd_write_value` and `rd_hi` moved to match | `lw` | `rd_value_rule` |
| `ram_write_value` `+ 1` | `sw` | `store_value_rule` |
| `pc_write_value` `+ 4` | `lw` | `next_pc_rule` |
| an `rd` query zeroing `x10` | padding | `rd_mask_rule`, `rd_addr_rule` |

What no gate refuses, and what does:

- **A misaligned `lw` or `sw`**: nothing in gate list 0.
  `a_misaligned_word_access_is_unprovable` builds, for each of the three offsets, the exact field
  witness `word_index = addr·4⁻¹` — every gate holds on it, the split included, the query's
  address rule included, both copies included, the decoder included — and finds
  `word_index_lo_range` refusing it alone. `addr·4⁻¹` is not a 32-bit integer and not a 64-bit
  one, and no choice of high chunk rescues it, the three obligations together admitting
  `word_index < 2^30` and nothing above.
- **A `word_index` at `2^30`**: `word_index_hi_scaled` alone.
  `a_word_index_above_2_to_the_30_is_refused` takes the honest `lw` at `0xfffffffc + 4`, which
  carries the wrap and reads word 0, and drops the wrap: the query's address becomes the field
  element `2^32`, a cell no 32-bit address can name. The 16+16 pair accepts it — `0x4000` is a
  halfword and the remainder is 0 — and the scaled obligation is the lone refusal.
- **A loaded value that was never in memory**: `rd_value_rule` ties `rd_selected` to the load
  query's read value, and nothing bounds that value here; the multiset is what pins it, and
  `the_loaded_value_is_the_word_the_memory_argument_pins` is that argument as rows.
- **A store's `ram_read_value`**: **nothing at all**. No gate and no obligation of this family
  reads it (§7.3, §13), which is why it is acceptance 8's tamper target for this family and why
  the refusal genuinely comes from the permutation product, as `MemoryArgument`
  (`memory-ops.md` §9).
- **A decoder tuple that is not the table's**: `each_table_lookup_is_the_one_that_refuses_its_row`,
  which `violated_lookups` cannot see — a table channel is held here to the table itself.

On a padding row `pc_mask = 0`, every frame mask is 0, every leaf is 1 and every obligation is
vacuous, all five `RANGE16` ones included: this family has no selector but `pc_mask` and the
frame's masks, so a padding row costs one table multiplicity per channel and nothing else. The
two kind bits and the wrap are **free booleans** there, and with every kind bit 0 the gates hold
`rd_selected`, `ram_write_value` and `pc_write_value − decoded_next_pc` to 0 and leave
`word_index` free subject to the split over a zero `rs1` and a zero `imm` — that is, to 0. The
honest fill writes 0 everywhere.

---

## 8. `MEM_SUBWORD` — family 5

### 8.1 Header

`family_circuit(5, n)` is `mem_subword::artifact(n)` with `mem_subword::channels()`, built by
`memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` through the private
`family_spec`, whose splice half is the public `mem_subword::splice_gates(BYTE_BITS)` — the
**width seam** S19's exhaustive reduced-width check drives, as `mul_div::arithmetic_gates` is at
S18 and `gadgets::comparison_equation` at S17. `splice_gates` panics outside `1..=8` bits to a
byte. It uses no S17 or S18 gadget: `is_zero` reaches it only through the frame's x0 rule, and
the one sign it needs comes from the packed table's `U16GetSign`, not from
`gadgets::comparison`. Normative spec: `memory-ops.md` §4. Fill: `prover::family_fill(5)`, the
private `fill::mem_subword`.

96 committed columns (31 `M`, 55 `W`, 10 `S`) and two virtual tables. Gate list 0 writes 120
leaves and holds 53 enforcing gates. 36 lookups on four channels, 10 outputs. At `n = 20`, the
height S19 proves, there are 26 gate lists, the top is `L26`, and the circuit has 452 inner
columns and 505 relations; a shard proof of it is 68,116 bytes. At `n = 22` — the committed
fixture — there are 28 lists, the top is `L28`, and it has 472 inner columns, 525 relations and
98,846 bytes of wire form.

**It is one gate list deeper than §7's**, for §6's reason and not §5's: its `range16` tree
carries 22 obligations, which with the table fraction is 23 leaves and pads to 32, where
`MEM_WORD`'s five fit in 8 (§8.6). It reads the generic channel — one lookup, the sign of the
sub-word it loaded — so `FamilyCircuit::reads_generic_table` holds and a shard opens the key's
three packed-table commitments after identity's seven, 96 commitments in all
(`shard-proof.md` §3, §5.1; `jump-branch-slt.md` §6).

`artifact` panics unless the frame is `QUERIES`, the channels carry exactly 12, 22, 1 and 1
obligations, `lookup::check_copowers` finds a direct range pair under the same selector for each
of the five columns it bounds by scaling — `word_index_hi`, `high`, `sub`, `low` and `src_sub` —
and every gate is zero on the all-zero row. It also panics on every refusal of the assembly,
among them `n < 19` and `n > 30`; `family_circuit` returns `None` for both rather than calling
it.

### 8.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::mem_subword`, bit `k` being
`W[15 + k]`. The decoded table's `imm` is the sign-extended twelve-bit displacement;
`next_pc` is the fall-through, and no kind here computes a pc. The effective address is
`rs1 + imm` reduced mod `2^32`, split into `4·word_index + 2·bit1 + bit0` with a wrap bit, and
the two offset bits are the only place a byte position lives: the memory tuple names the word
(`memory-ops.md` §2, §4.1).

**The stage prompt's STORE, BYTE, HALF and SIGNEXT modifiers are linear forms over the six
one-hot bits, not columns** (`memory-ops.md` §1): `LOADK = b_lb + b_lh + b_lbu + b_lhu`,
`STORE = b_sb + b_sh`, `BYTE = b_lb + b_lbu + b_sb`, `HALF = b_lh + b_lhu + b_sh`,
`SIGNEXT = b_lb + b_lh`. Each appears as one product per bit in the gate that reads it, which is
what keeps a product with one at degree 2, and no lookup selects on one, so none needs a
booleanity gate. `w`, the access width, is `2^16 − (2^16 − 2^8)·BYTE`: 256 on a byte row and
65536 on a halfword row.

| row kind | bit (`decoded_mask`) | queries present | `w` | `SIGNEXT` | `rd_selected` | `ram_write_value` |
| --- | --- | --- | --- | --- | --- | --- |
| `lb` | 0 (1) | pc rs1 load rd | 256 | 1 | `sub + (2^32 − 256)·se` | 0 |
| `lh` | 1 (2) | pc rs1 load rd | 65536 | 1 | `sub + (2^32 − 65536)·se` | 0 |
| `lbu` | 2 (4) | pc rs1 load rd | 256 | 0 | `sub` | 0 |
| `lhu` | 3 (8) | pc rs1 load rd | 65536 | 0 | `sub` | 0 |
| `sb` | 4 (16) | pc rs1 rs2 ram | 256 | 0 | 0 | `word + (src_sub − sub)·p` |
| `sh` | 5 (32) | pc rs1 rs2 ram | 65536 | 0 | 0 | `word + (src_sub − sub)·p` |
| padding | none; all 0 | none | — | 0 | 0 | 0 |

All six are provable at S19. The splice power `p = 2^(8·offset)` is 1, 256, `2^16` or `2^24`,
and `half_aligned` forces `bit0 = 0` on the three halfword kinds, so `w·p` is at most `2^32` and
never `2^40` — which is what §8.5's `high_scaled` bound rests on (`memory-ops.md` §2, §4.7). On
a **padding row** every gate of the splice reads `0 = 0`: `p_rule`'s constant is `m_pc`, so
`p = 0` there, and `pcopow`, `wph`, `high`, `sub`, `low`, `src_sub` and `src_high` follow.
`pcopow` is then free of every gate, which is what makes it acceptance 8's negative control
(`memory-ops.md` §9).

`rd = x0` is not a kind. Every kind but a store has a compressed form (`c.lw`'s siblings do not
cover the sub-word loads, but the guest's rows carry both fall-through widths through the
decoded table), and a live row at a pc holding no instruction of the family meets the table's
`MINUS_ONE` row, which its decoder tuple cannot equal.

### 8.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §8.4 and §8.6.

**Memory-argument columns, `M[0..31]`** — §2's MEM layout (`w = 6`), the same 31 columns,
the same slots and the same bare frame fixture (`memory_frame_mem.bin`) as §7.3's, address for
address; `M[0..31]`'s meanings and their frame gates are §7.3's. The "read by" column differs
only where this family's own gates read one:

| address and name | what it holds here | read by, beside the frame |
| --- | --- | --- |
| `M[9]` `rs1_read_value` | the base address | `addr_split` |
| `M[14]` `rs2_read_value` | the value a store truncates, not the word it stores | `src_sub_rule` |
| `M[19]` `load_read_value` | the word a load read, which `word` copies | `word_rule` |
| `M[21]` `ram_mask` | 1 on a store row | `ram_mask_rule`, `ram_addr_rule`, `p_ram_rule`, `store_rule` |
| `M[24]` `ram_read_value` | the word a store is rewriting, which `word` copies | `word_rule` — so unlike §7's, this family **does** read it |
| `M[25]` `ram_write_value` | the spliced word | `store_rule` |
| `M[30]` `rd_write_value` | the sign-extended sub-word, or 0 into `x0` | `rd_write_masked` |

Every other `M` column is read exactly as §7.3 lists it.

**Witness columns, `W[0..55]`** — `W[0..8]` filled by `trace::build_frame_witness`, `W[8..51]`
by `fill::mem_subword` (`W[8]` in place of S14's), `W[51..55]` by
`trace::build_multiplicities` inside `prover::shard_columns`; committed in
`ShardProof::witness_commitments`, absorbed at S3 before `g` and `β`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0..6]` | `pc_gap_hi` … `rd_gap_hi` | `memory::gap_hi(s)` | the six gap chunks | `gap >> 19` | `gap_hi_<q>`, `gap_lo_<q>` |
| `W[6]` | `rd_inv` | `memory::rd_inv(6)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[7]` | `rd_is_zero` | `memory::rd_is_zero(6)` | rd is `x0` | | the three x0 gates |
| `W[8]` | `rd_selected` | `memory::rd_selected(6)`; `sel` | Loaded sub-word, extended | `sub + (2^32 − w)·se`; 0 on a store | `rd_write_masked`, `rd_value_rule`; `rd_lo_range` |
| `W[9..15]` | `decoded_next_pc` … `decoded_mask` | `mem_subword::DECODED` | the claimed decoded row | the table row after `pc` | `next_pc_rule`, `rs1_addr_rule`, `rs2_addr_rule`, `rd_addr_rule`, `addr_split`, `decoded_mask_bits`; `decode_row` positions 1–6 |
| `W[15]` | `kind_lb` | `KINDS[0]`; `LB` | lb row | | `kind_lb_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `load_mask_rule`, `rd_mask_rule`, `word_rule`, `se_rule`, `wph_rule`, `sub_scaled_rule`, `src_sub_rule`, `src_sub_scaled_rule`, `sign_in_rule`, `rd_value_rule` |
| `W[16]` | `kind_lh` | `KINDS[1]`; `LH` | lh row | | `kind_lh_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `load_mask_rule`, `rd_mask_rule`, `half_aligned`, `word_rule`, `se_rule`, `rd_value_rule` |
| `W[17]` | `kind_lbu` | `KINDS[2]`; `LBU` | lbu row | | as `kind_lb` without `se_rule` |
| `W[18]` | `kind_lhu` | `KINDS[3]`; `LHU` | lhu row | | as `kind_lh` without `se_rule` |
| `W[19]` | `kind_sb` | `KINDS[4]`; `SB` | sb row | | `kind_sb_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `ram_mask_rule`, `word_rule`, `wph_rule`, `sub_scaled_rule`, `src_sub_rule`, `src_sub_scaled_rule`, `sign_in_rule`, `rd_value_rule` |
| `W[20]` | `kind_sh` | `KINDS[5]`; `SH` | sh row | | `kind_sh_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `ram_mask_rule`, `half_aligned`, `word_rule` |
| `W[21]` | `wrap` | `mem_subword::WRAP` | Address carry | 1 where `rs1 + imm ≥ 2^32` | `wrap_boolean`, `addr_split` |
| `W[22]` | `word_index` | `WORD_INDEX` | The accessed word's index | `addr / 4` | `load_addr_rule`, `ram_addr_rule`, `addr_split`; `word_index_lo_range` |
| `W[23]` | `word_index_hi` | `WORD_INDEX_HI` | `word_index`, high halfword | | `word_index_hi_range`, `word_index_lo_range`, `word_index_hi_scaled` |
| `W[24]` | `bit0` | `BIT0` | Address bit 0 | | `bit0_boolean`, `addr_split`, `half_aligned`, `p_rule` |
| `W[25]` | `bit1` | `BIT1` | Address bit 1 | | `bit1_boolean`, `addr_split`, `p_rule` |
| `W[26]` | `p` | `P` | Splice power `2^(8·offset)` | 1, 256, `2^16` or `2^24`; 0 on a padding row | `p_rule`, `pcopow_rule`, `wph_rule`, `splice_rule`, `p_ram_rule` |
| `W[27]` | `pcopow` | `PCOPOW` | Halved copower `2^31/p` | | `pcopow_rule`, `low_scaled_rule` |
| `W[28]` | `wph` | `WPH` | Halved `w·p` | | `wph_rule`, `high_scaled_rule` |
| `W[29]` | `p_ram` | `P_RAM` | `p` on a store row | 0 on a load and on padding | `p_ram_rule`, `store_rule` |
| `W[30]` | `word` | `WORD` | The word this row splices | what a load read, or what a store is rewriting | `word_rule`, `splice_rule`, `store_rule` |
| `W[31]` | `high` | `HIGH` | The bytes above the sub-word | `word div (w·p)` | `high_scaled_rule`; `high_lo_range` |
| `W[32]` | `high_hi` | `HIGH_HI` | `high`, high halfword | | `high_hi_range`, `high_lo_range` |
| `W[33]` | `high_scaled` | `HIGH_SCALED` | `high·(w·p)` | | `splice_rule`, `high_scaled_rule`; `high_scaled_lo_range` |
| `W[34]` | `high_scaled_hi` | `HIGH_SCALED_HI` | its high halfword | | `high_scaled_hi_range`, `high_scaled_lo_range` |
| `W[35]` | `sub` | `SUB` | The accessed sub-word | `(word div p) mod w` | `splice_rule`, `sub_scaled_rule`, `sign_in_rule`, `rd_value_rule`, `store_rule`; `sub_range` |
| `W[36]` | `sub_scaled` | `SUB_SCALED` | `sub·(2^32/w)` | | `sub_scaled_rule`; `sub_scaled_lo_range` |
| `W[37]` | `sub_scaled_hi` | `SUB_SCALED_HI` | its high halfword | | `sub_scaled_hi_range`, `sub_scaled_lo_range` |
| `W[38]` | `low` | `LOW` | The bytes below the sub-word | `word mod p` | `splice_rule`, `low_scaled_rule`; `low_lo_range` |
| `W[39]` | `low_hi` | `LOW_HI` | `low`, high halfword | | `low_hi_range`, `low_lo_range` |
| `W[40]` | `low_scaled` | `LOW_SCALED` | `low·(2^32/p)` | | `low_scaled_rule`; `low_scaled_lo_range` |
| `W[41]` | `low_scaled_hi` | `LOW_SCALED_HI` | its high halfword | | `low_scaled_hi_range`, `low_scaled_lo_range` |
| `W[42]` | `src_sub` | `SRC_SUB` | `rs2` truncated to the width | `rs2 mod w` | `src_sub_rule`, `src_sub_scaled_rule`, `store_rule`; `src_sub_range` |
| `W[43]` | `src_sub_scaled` | `SRC_SUB_SCALED` | `src_sub·(2^32/w)` | | `src_sub_scaled_rule`; `src_sub_scaled_lo_range` |
| `W[44]` | `src_sub_scaled_hi` | `SRC_SUB_SCALED_HI` | its high halfword | | `src_sub_scaled_hi_range`, `src_sub_scaled_lo_range` |
| `W[45]` | `src_high` | `SRC_HIGH` | The rest of `rs2` | `rs2 div w` | `src_sub_rule`; `src_high_lo_range` |
| `W[46]` | `src_high_hi` | `SRC_HIGH_HI` | its high halfword | | `src_high_hi_range`, `src_high_lo_range` |
| `W[47]` | `sign_in` | `SIGN_IN` | The sub-word with its sign at bit 15 | `256·sub` on a byte row, `sub` on a halfword one | `sign_in_rule`; `sign_in_range`, `sub_get_sign` position 0 |
| `W[48]` | `sign` | `SIGN` | That sign bit, from the packed table | | `se_rule`; `sub_get_sign` position 1 |
| `W[49]` | `se` | `SE` | The sign-extension term | `SIGNEXT·sign` | `se_rule`, `rd_value_rule` |
| `W[50]` | `rd_hi` | `RD_HI` | The written value, high halfword | | `rd_hi_range`, `rd_lo_range` |
| `W[51]` | `mult_timestamp` | `MULTIPLICITIES[0]` | Timestamp-table count | | leaf `timestamp_table_num` |
| `W[52]` | `mult_range16` | `MULTIPLICITIES[1]` | 16-bit-table count | all 22 obligations under `pc_mask` | leaf `range16_table_num` |
| `W[53]` | `mult_generic` | `MULTIPLICITIES[2]` | Generic-table count | a live row's one tuple lands on `U16GetSign`'s row `2^16 + 1 + sign_in`; a padding row's on the `ZeroEntry`, row 0 | leaf `generic_table_num` |
| `W[54]` | `mult_decoder` | `MULTIPLICITIES[3]` | Decoder-table count | | leaf `decoder_table_num` |

**Like §7 and unlike §5, every obligation and every lookup of this family is under `pc_mask`.**
There is no second selector: the one generic lookup runs on a store row too, where `SIGNEXT` is
0 and it buys nothing, which is S17's shape and deliberate — a narrower selector would have to
be a committed column with a booleanity gate of its own, and the key bound would have to move
with it (`memory-ops.md` §4.5).

**Setup columns, `S[0..10]`** — two tables. `S[0..7]` is the family's decoded table,
`program::lookup_tuple(5)` order, filled by `program::FamilyTable::column_poly(j)`, committed in
program identity. `S[7..10]` is the packed generic table (§0.3), filled by
`program::lookup_tables::generic_table(n)`, carried in every key as
`VerifyingKey::generic_table` and covered by the key's SRS digest, not by identity. The layout
is §5.3's, name for name — `table_pc` … `table_extra_mask` at weights 1 to `β⁶`, then
`generic_key`, `generic_value`, `generic_result` at 1, `β`, `β²` — and each is read only by its
table's denominator. `mem_subword::TABLE_WIDTH` is 7 and `constants::generic_table::WIDTH` is 3.

**Virtual tables** — `V[range19]` and `V[range16]`, §7.3's, read by `timestamp_table_den` and
`range16_table_den`.

### 8.4 Gate list 0: the 120 leaves

A leaf's relation number equals its `L1` offset, 0 to 119.

**The memory product trees**, `L1[0..16]`: §7.4's, address for address — the frame is the same
six queries, and the bare frame fixture `memory_frame_mem.bin` is the same file. Two pads a
side.

**The `timestamp` fraction tree**, `L1[16..48]`: §7.4's list unchanged, 16 fractions — the
table's, then `gap_hi`/`gap_lo` for `pc`, `rs1`, `rs2`, `load`, `ram` and `rd`, then three pads.

**The `range16` fraction tree**, `L1[48..112]`: **32 fractions**, the table's then 22
obligations then 9 pads. This is the tree that makes the circuit a list deeper than §7's. Every
obligation is under `pc_mask`, so the selector column is omitted.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 48, 49 | `range16_table` | `−mult_range16` | `V[range16] + g` |
| 1 | 50, 51 | `word_index_hi_range` | 1 | `g + pc_mask·word_index_hi` |
| 2 | 52, 53 | `word_index_lo_range` | 1 | `g + pc_mask·word_index − 2^16·pc_mask·word_index_hi` |
| 3 | 54, 55 | `word_index_hi_scaled` | 1 | `g + 4·pc_mask·word_index_hi` |
| 4, 5 | 56–59 | `high_hi_range`, `high_lo_range` | 1 | the 16+16 pair on `high` |
| 6, 7 | 60–63 | `high_scaled_hi_range`, `high_scaled_lo_range` | 1 | the pair on `high_scaled` |
| 8 | 64, 65 | `sub_range` | 1 | `g + pc_mask·sub` — a **single** halfword obligation |
| 9, 10 | 66–69 | `sub_scaled_hi_range`, `sub_scaled_lo_range` | 1 | the pair on `sub_scaled` |
| 11, 12 | 70–73 | `low_hi_range`, `low_lo_range` | 1 | the pair on `low` |
| 13, 14 | 74–77 | `low_scaled_hi_range`, `low_scaled_lo_range` | 1 | the pair on `low_scaled` |
| 15 | 78, 79 | `src_sub_range` | 1 | `g + pc_mask·src_sub` — a single obligation again |
| 16, 17 | 80–83 | `src_sub_scaled_hi_range`, `src_sub_scaled_lo_range` | 1 | the pair on `src_sub_scaled` |
| 18, 19 | 84–87 | `src_high_hi_range`, `src_high_lo_range` | 1 | the pair on `src_high` |
| 20 | 88, 89 | `sign_in_range` | 1 | `g + pc_mask·sign_in` — the generic key's own bound, single |
| 21, 22 | 90–93 | `rd_hi_range`, `rd_lo_range` | 1 | the pair on `rd_selected` |
| 23–31 | 94–111 | `range16_pad_0` … `range16_pad_8` | 0 | 1 |

**The `generic` fraction tree**, `L1[112..116]`: 2 fractions, the table's and one lookup — the
narrowest generic tree of any registered circuit.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 112, 113 | `generic_table` | `−mult_generic` | `generic_key + β·generic_value + β²·generic_result + g` |
| 1 | 114, 115 | `sub_get_sign` | 1 | `g + 257·pc_mask + pc_mask·sign_in + β·pc_mask·sign` |

```text
L{1}[115]  sub_get_sign_den
  positional  lookup_g + 257·M[1] + 1·M[1]·W[47] + lookup_beta·M[1]·W[48]
  reads as    g + m_pc·(e_0 + 1) + β·m_pc·e_1,
              e = (sign_in + SIGN_BASE, sign, 0), SIGN_BASE = 256:
              the key sign_in + 257 and the sub-word's sign bit at m_pc = 1,
              the ZeroEntry at 0. The third tuple position is the constant 0,
              so it adds no β² term (§0.4).
```

**The `decoder` fraction tree**, `L1[116..120]`: 2 fractions, §7.4's with the decoded row at
`W[9..15]`, address for address; the tuple is seven wide, so `β⁶` is live and `g_dec` is
`g − Σ_{j<7} β^j`.

### 8.5 Gate list 0: the 53 enforcing gates

Relations 120–172, in list order, in §3.5's format. The frame's thirteen (120–132) are §7.5's
A, address for address. The family's 40 come from `mem_subword::family_spec`, its private
`booleanity`, `form_times`, `mask_rule`, `addr_rule`, `word_addr_rule` and `value_masked`, and
the public `splice_gates(8)`, which builds **twelve** of them (160–171).

**A. What the row is (133–142)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
133–138 kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2

  133 kind_lb_boolean   W[15]    136 kind_lhu_boolean  W[18]
  134 kind_lh_boolean   W[16]    137 kind_sb_boolean   W[19]
  135 kind_lbu_boolean  W[17]    138 kind_sh_boolean   W[20]

────────────────────────────────────────────────────────────────────────────────────────────
139     decoded_mask_bits — the packed mask is its six bits             Linear, degree 1

  positional  0 = W[15] + 2·W[16] + 4·W[17] + 8·W[18] + 16·W[19] + 32·W[20] − W[14]
  named       0 = Σ_k 2^k·kind_k − decoded_mask,  k in extra_mask::mem_subword order

  reads as  §5.5's 146 over six bits. The stage prompt's modifier-bit masks {0,1,2,3,4,6}
            are not the encoding: S11 froze this table one-hot per mnemonic and append-only
            (memory-ops.md §1).

────────────────────────────────────────────────────────────────────────────────────────────
140–142 wrap_boolean, bit0_boolean, bit1_boolean                        Quadratic, degree 2

  140 wrap_boolean  0 = W[21] − W[21]·W[21]
  141 bit0_boolean  0 = W[24] − W[24]·W[24]
  142 bit1_boolean  0 = W[25] − W[25]·W[25]

  reads as  the two offset bits are read by the address split, by half_aligned and by p_rule,
            each of which is a different statement at a value of two; these three gates are
            what make the split an integer statement and p a function of the offset.
```

**B. Which queries a row makes, and where (143–154)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
143–147 <q>_mask_rule — a query is present exactly where its kind uses it   Quadratic, deg 2

  143 rs1_mask_rule   0 = M[6]  − M[1]·(W[15] + … + W[20])      all six bits
  144 rs2_mask_rule   0 = M[11] − M[1]·W[19] − M[1]·W[20]       STORE
  145 load_mask_rule  0 = M[16] − M[1]·(W[15] + W[16] + W[17] + W[18])   LOADK
  146 ram_mask_rule   0 = M[21] − M[1]·W[19] − M[1]·W[20]       STORE
  147 rd_mask_rule    0 = M[26] − M[1]·(W[15] + W[16] + W[17] + W[18])   LOADK

  reads as  every kind reads rs1; a load reads a word at slot 2 and writes rd; a store reads
            rs2 and rewrites a word at slot 3. LOADK and STORE appear here as sums of bits
            and nowhere as columns (§8.2). On a padding row pc_mask = 0 and every mask is 0
            — S14's control C8, which §8.10 refuses twice.

────────────────────────────────────────────────────────────────────────────────────────────
148–150 <q>_addr_rule — a present register query's index is the decoded one  Quadratic, deg 2

  148 rs1_addr_rule   0 = M[6]·M[7]   − M[6]·W[10]
  149 rs2_addr_rule   0 = M[11]·M[12] − M[11]·W[11]
  150 rd_addr_rule    0 = M[26]·M[27] − M[26]·W[12]

────────────────────────────────────────────────────────────────────────────────────────────
151–152 <q>_addr_rule — a present RAM query names the word, not the byte  Quadratic, degree 2

  151 load_addr_rule  0 = M[16]·M[17] − 4·M[16]·W[22]
  152 ram_addr_rule   0 = M[21]·M[22] − 4·M[21]·W[22]

  reads as  §7.5's 93–94, and the whole reason this family works: `lb` at a word's four
            offsets names one cell, and a byte an `sb` writes is visible to a later `lw`.
            The byte position lives only in the splice (memory-ops.md §2).

────────────────────────────────────────────────────────────────────────────────────────────
153–154 <q>_value_masked — an absent operand reads 0                   Quadratic, degree 2

  153 rs1_value_masked  0 = M[9]  − M[6]·M[9]
  154 rs2_value_masked  0 = M[14] − M[11]·M[14]
```

**C. The address and the offset (155–156)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
155     addr_split — the address is a word index and two offset bits    Linear, degree 1

  positional  0 = M[9] + W[13] − 2^32·W[21] − 4·W[22] − 2·W[25] − W[24]
  named       0 = rs1_read_value + decoded_imm − 2^32·wrap − 4·word_index
                  − 2·bit1 − bit0

  reads as  §7.5's 97 with the two low bits kept. The three obligations on word_index hold
            it below 2^30, so both sides are integers below 2^34 and the field equality is
            an integer one: `wrap` is the true carry, and bit1, bit0 are the address's true
            low two bits — which is what pins the offset the splice then uses
            (memory-ops.md §2, §4.2).

────────────────────────────────────────────────────────────────────────────────────────────
156     half_aligned — a halfword access has bit 0 clear               Quadratic, degree 2

  positional  0 = W[16]·W[24] + W[18]·W[24] + W[20]·W[24]
  named       0 = HALF·bit0,  HALF = kind_lh + kind_lhu + kind_sh

  reads as  not only alignment. At BYTE = 0 with bit0 = 1 the product w·p would be 2^40,
            and §8.7's bound on what a store writes needs w·p to divide 2^32. This gate is
            what removes that case (memory-ops.md §2).
```

**D. The splice (157–171)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
157     word_rule — the word this row splices                          Quadratic, degree 2
        code  family_spec, over LOADK and STORE

  positional  0 = W[30] − (W[15] + W[16] + W[17] + W[18])·M[19]
                        − (W[19] + W[20])·M[24]
  named       0 = word − LOADK·load_read_value − STORE·ram_read_value

  reads as  one decomposition serves both directions: `word` is the word a load read, or the
            word a store is rewriting. It is the only gate of this family that reads
            ram_read_value, which §7's does not read at all.

────────────────────────────────────────────────────────────────────────────────────────────
158     p_ram_rule — the splice power, gated to a store row            Quadratic, degree 2

  positional  0 = W[29] − M[21]·W[26]       named  0 = p_ram − ram_mask·p

  reads as  exists so that store_rule stays degree 2, and so that a row with no RAM query
            writes 0 there (memory-ops.md §4.1).

────────────────────────────────────────────────────────────────────────────────────────────
159     se_rule — the sign-extension term                              Quadratic, degree 2

  positional  0 = W[49] − W[15]·W[48] − W[16]·W[48]
  named       0 = se − SIGNEXT·sign,  SIGNEXT = kind_lb + kind_lh

  reads as  `se` is boolean by construction — a one-hot sum times a table bit — and carries
            no booleanity gate, as S17's `eq` does not (memory-ops.md §4.5).

────────────────────────────────────────────────────────────────────────────────────────────
160–171 splice_gates(8) — the twelve gates whose literals are the width
        code  mem_subword::splice_gates(BYTE_BITS), BYTE_BITS = 8

  160 p_rule              0 = W[26] − M[1] − 255·W[24] − 65535·W[25]
                              − 16711425·W[24]·W[25]
                          0 = p − m_pc − 255·bit0 − 65535·bit1 − K·bit0·bit1,
                              K = 2^24 − 2^16 − 2^8 + 1 = 16711425
      the unique degree-2 form taking the four offsets to 1, 256, 2^16, 2^24;
      m_pc stands where a constant would, so the gate is 0 on the all-zero row

  161 pcopow_rule         0 = W[26]·W[27] − 2^31·M[1]
                          0 = p·pcopow − 2^31·m_pc
      pcopow is the halved copower 2^31/p, so the column fits u32 at p = 1 where
      the copower itself is 2^32; 166 carries the compensating factor 2

  162 wph_rule            0 = W[28] − 32768·W[26] + 32640·(W[15] + W[17] + W[19])·W[26]
                          0 = wph − (w·p)/2,  w = 2^16 − (2^16 − 2^8)·BYTE
      halved for the same reason: w·p is the whole word at offset 3 of a byte
      access and at offset 2 of a halfword one

  163 splice_rule         0 = W[30] − W[33] − W[38] − W[35]·W[26]
                          0 = word − high_scaled − low − sub·p

  164 high_scaled_rule    0 = W[33] − 2·W[31]·W[28]      0 = high_scaled − high·(w·p)
  165 sub_scaled_rule     0 = W[36] − 65536·W[35] − 16711680·BYTE·W[35]
                          0 = sub_scaled − sub·(2^32/w)
  166 low_scaled_rule     0 = W[40] − 2·W[38]·W[27]      0 = low_scaled − low·(2^32/p)
  167 src_sub_rule        0 = M[14] − W[42] − 65536·W[45] + 65280·BYTE·W[45]
                          0 = rs2_read_value − src_sub − w·src_high
  168 src_sub_scaled_rule 0 = W[43] − 65536·W[42] − 16711680·BYTE·W[42]
  169 sign_in_rule        0 = W[47] − W[35] − 255·BYTE·W[35]
                          0 = sign_in − sub·(1 + 255·BYTE)
      256·sub on a byte row and sub on a halfword one, so bit 15 of sign_in is the
      sub-word's sign bit at either width and one U16GetSign lookup serves both

  170 rd_value_rule       0 = W[8] − LOADK·W[35] − (2^32 − 2^16)·W[49]
                              − 65280·BYTE·W[49]
                          0 = rd_selected − LOADK·sub − (2^32 − w)·se
      the 32-bit sign extension: at se = 1 it is sub − w + 2^32, the two's-complement
      word, so lb of 0x88 gives 0xffffff88 and lh of 0x8000 gives 0xffff8000

  171 store_rule          0 = M[25] − M[21]·W[30] − W[42]·W[29] + W[35]·W[29]
                          0 = ram_write_value − ram_mask·word − (src_sub − sub)·p_ram
      exactly `new = old + (src_sub − old_sub)·p` on a store row, and
      ram_write_value = 0 on every other

  reads as  164–169 are where the scaled bounds of §8.6 do their work: sub_scaled < 2^32 is
            sub < w, low_scaled < 2^32 is low < p, and with high < 2^32 directly the
            decomposition is the unique base-(p, w) one. A scaled bound alone would not do
            it — p is a unit in Fr, so a "low" of s·p⁻¹ passes the scaled check while being
            no small integer at all, which is S18's residue hole and what check_copowers
            exists to refuse (memory-ops.md §4.4).

────────────────────────────────────────────────────────────────────────────────────────────
172     next_pc_rule — the next pc is the decoded fall-through         Linear, degree 1

  positional  0 = M[5] − W[9]       named  0 = pc_write_value − decoded_next_pc

  reads as  §7.5's 100.
```

### 8.6 The 36 lookups

`CircuitArtifact::lookups`, in order. The frame's 12 come from the private
`memory::gap_lookups`; the rest from `mem_subword::family_spec` (its private `range16`,
`range32`, the inline `sub_get_sign` and the inline `decode_row`). **Every one of the 36 is
selected by `pc_mask`**: this family has no second selector anywhere.

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0–11 | `gap_hi_pc` … `gap_lo_rd` | `TIMESTAMP` (0) | each query's mask | §7.6's 0–11, address for address | | `< 2^19` |
| 12 | `word_index_hi_range` | `RANGE16` (1) | `M[1]` | `W[23]` | `word_index_hi` | `< 2^16` |
| 13 | `word_index_lo_range` | `RANGE16` | `M[1]` | `W[22] − 2^16·W[23]` | `word_index − 2^16·word_index_hi` | `< 2^16` |
| 14 | `word_index_hi_scaled` | `RANGE16` | `M[1]` | `4·W[23]` | `4·word_index_hi` | `word_index_hi < 2^14` |
| 15, 16 | `high_hi_range`, `high_lo_range` | `RANGE16` | `M[1]` | `W[32]`; `W[31] − 2^16·W[32]` | the pair on `high` | `high < 2^32` |
| 17, 18 | `high_scaled_hi_range`, `high_scaled_lo_range` | `RANGE16` | `M[1]` | `W[34]`; `W[33] − 2^16·W[34]` | the pair on `high_scaled` | `high_scaled < 2^32` |
| 19 | `sub_range` | `RANGE16` | `M[1]` | `W[35]` | `sub` | `< 2^16` |
| 20, 21 | `sub_scaled_hi_range`, `sub_scaled_lo_range` | `RANGE16` | `M[1]` | `W[37]`; `W[36] − 2^16·W[37]` | the pair on `sub_scaled` | `sub < w` |
| 22, 23 | `low_hi_range`, `low_lo_range` | `RANGE16` | `M[1]` | `W[39]`; `W[38] − 2^16·W[39]` | the pair on `low` | `low < 2^32` |
| 24, 25 | `low_scaled_hi_range`, `low_scaled_lo_range` | `RANGE16` | `M[1]` | `W[41]`; `W[40] − 2^16·W[41]` | the pair on `low_scaled` | `low < p` |
| 26 | `src_sub_range` | `RANGE16` | `M[1]` | `W[42]` | `src_sub` | `< 2^16` |
| 27, 28 | `src_sub_scaled_hi_range`, `src_sub_scaled_lo_range` | `RANGE16` | `M[1]` | `W[44]`; `W[43] − 2^16·W[44]` | the pair on `src_sub_scaled` | `src_sub < w` |
| 29, 30 | `src_high_hi_range`, `src_high_lo_range` | `RANGE16` | `M[1]` | `W[46]`; `W[45] − 2^16·W[46]` | the pair on `src_high` | `src_high < 2^32` |
| 31 | `sign_in_range` | `RANGE16` | `M[1]` | `W[47]` | `sign_in` | `< 2^16` — the generic key's bound |
| 32, 33 | `rd_hi_range`, `rd_lo_range` | `RANGE16` | `M[1]` | `W[50]`; `W[8] − 2^16·W[50]` | the pair on `rd_selected` | `rd_selected < 2^32` |
| 34 | `sub_get_sign` | `GENERIC` (2) | `M[1]` | `(W[47] + 256, W[48], 0)` | `(sign_in + SIGN_BASE, sign, 0)` | the gated tuple `(sign_in + 257, sign, 0)` is a row of `S[7..10]` |
| 35 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[9], W[10], W[11], W[12], W[13], W[14])` | the seven decoded columns | a row of `S[0..7]` |

**Every part of the splice carries both bounds, and the reason is not symmetry.** `high`,
`low`, `src_high` and each of the four `_scaled` columns carry a 16+16 pair; `sub` and
`src_sub` carry a single halfword obligation, which is their **exact** direct bound, each being
below the access width and so below `2^16`, so a pair there would be two obligations saying the
same thing. The scaled bounds are what make the row-varying widths fixed: `sub_scaled < 2^32`
is `sub < w`, `low_scaled < 2^32` is `low < p`. `lookup::check_copowers` takes
`(word_index_hi, m_pc)`, `(high, m_pc)`, `(sub, m_pc)`, `(low, m_pc)` and `(src_sub, m_pc)` and
refuses the circuit if any of them loses its direct bound or has it moved under a narrower
selector. **`src_high` needs no scaled bound**: `rs2 = src_sub + w·src_high` with `src_sub < w`
and `w·src_high < 2^48` is an integer equation, so `rs2 < 2^32` forces `src_high < 2^32/w` with
no obligation of its own (`memory-ops.md` §4.4).

**`sign_in_range` is the one place in the VM where a bare `RANGE16` obligation, and not a pair,
is the right answer.** `sign_in < 2^16` puts the gated key in `[SIGN_BASE + 1, SIGN_BASE + 2^16]`,
which is `U16GetSign`'s range exactly — never the `ZeroEntry`, never an AND key, never a
`ShiftPowers` key — because that sub-table's key range is exactly a halfword wide. With three
sub-tables packed into one channel an unbounded key does not *miss* the table, it lands on
another sub-table's row (`lookup.md` §4; `shift-bitwise.md` §3.3), and
`the_generic_key_stays_inside_its_sub_table` in `mem_subword.rs` is that bound as rows.

The channels, `mem_subword::channels()`, in output order:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[51]` | 12 | 16 |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[52]` | **22** | **32** |
| 6, 7 | `GENERIC` | 2 | `S[7..10]` | `W[53]` | 1 | 2 |
| 8, 9 | `DECODER` | 3 | `S[0..7]` | `W[54]` | 1 | 2 |

`artifact` asserts the four obligation counts. The `RANGE16` row is why this circuit is 26 gate
lists deep at `n = 20` where §7's is 25: 22 obligations plus one table fraction is 23 leaves,
which pads to 32 and takes five row-wise levels instead of four. Nine of the 32 leaves are pads,
the widest padding of any registered circuit's `range16` tree.

### 8.7 Inner layers `L2`–`L6`: the row-wise reduction

The conventions are §3.7's. There are **five** row-wise reduction lists here.

**`L2`, gate list 1, 60 columns, relations 173–232.** `read_2_0` … `read_2_3` and
`write_2_0` … `write_2_3` pair the eight leaves a side as §7.7's do; `timestamp_2_0` …
`timestamp_2_7` are §7.7's; `decoder_2_0` is `decoder_table + decode_row`. The two that differ:

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 24, 25 | 197, 198 | `range16_2_0` | `range16_table + word_index_hi_range` |
| 26, 27 | 199, 200 | `range16_2_1` | `word_index_lo_range + word_index_hi_scaled` |
| 28, 29 | 201, 202 | `range16_2_2` | `high_hi_range + high_lo_range` |
| 30, 31 | 203, 204 | `range16_2_3` | `high_scaled_hi_range + high_scaled_lo_range` |
| 32, 33 | 205, 206 | `range16_2_4` | `sub_range + sub_scaled_hi_range` |
| 34, 35 | 207, 208 | `range16_2_5` | `sub_scaled_lo_range + low_hi_range` |
| 36, 37 | 209, 210 | `range16_2_6` | `low_lo_range + low_scaled_hi_range` |
| 38, 39 | 211, 212 | `range16_2_7` | `low_scaled_lo_range + src_sub_range` |
| 40, 41 | 213, 214 | `range16_2_8` | `src_sub_scaled_hi_range + src_sub_scaled_lo_range` |
| 42, 43 | 215, 216 | `range16_2_9` | `src_high_hi_range + src_high_lo_range` |
| 44, 45 | 217, 218 | `range16_2_10` | `sign_in_range + rd_hi_range` |
| 46, 47 | 219, 220 | `range16_2_11` | `rd_lo_range + range16_pad_0` |
| 48–55 | 221–228 | `range16_2_12` … `range16_2_15` | the remaining eight pads in pairs |
| 56, 57 | 229, 230 | `generic_2_0` | `generic_table + sub_get_sign` |
| 58, 59 | 231, 232 | `decoder_2_0` | `decoder_table + decode_row` |

The tree does not know that a 16+16 pair belongs together: `range16_2_4` adds `sub`'s single
obligation to the high half of `sub_scaled`'s pair, and `range16_2_5` its low half to `low`'s
high half. Only the leaves and the root mean anything.

**`L3`, gate list 2, 32 columns, relations 233–264.** `read_3_0`, `read_3_1`, `write_3_0`,
`write_3_1`; `timestamp_3_0` … `timestamp_3_3`; `range16_3_0` … `range16_3_7`, each the sum of
two `L2` nodes in order; `generic_3_0` and `decoder_3_0`, each a **copy** of its `L2` node.

**`L4`, gate list 3, 18 columns, relations 265–282.** `read_4_0`, `write_4_0`;
`timestamp_4_0`, `timestamp_4_1`; `range16_4_0` … `range16_4_3`; `generic_4_0` and
`decoder_4_0`, copies.

**`L5`, gate list 4, 12 columns, relations 283–294.** `read_5_0` and `write_5_0`, copies;
`timestamp_5_0` = `timestamp_4_0 + timestamp_4_1`; `range16_5_0` and `range16_5_1`;
`generic_5_0` and `decoder_5_0`, copies.

**`L6`, gate list 5, 10 columns, relations 295–304.** `read_6_0`, `write_6_0`,
`timestamp_6_0`, `generic_6_0` and `decoder_6_0` are copies; `range16_6_0` =
`range16_5_0 + range16_5_1` is the one real node of the list — the level the `range16` tree
alone pays for.

### 8.8 The halving layers and the outputs

Gate list `k`, for `6 ≤ k ≤ n + 5`, halves layer `k` into layer `k + 1`, which has `n + 5 − k`
variables. Its ten gates, relation `r = 305 + 10(k − 6)`, are §5.8's, node for node:
`read_{k+1}_0`, `write_{k+1}_0`, then the `num`/`den` pair of each of `timestamp`, `range16`,
`generic` and `decoder`. In the last list, `k = n + 5`, the ten nodes are `read_root`,
`write_root`, `timestamp_num_root`, `timestamp_den_root`, `range16_num_root`,
`range16_den_root`, `generic_num_root`, `generic_den_root`, `decoder_num_root` and
`decoder_den_root`. At `n = 20` the halving lists are 6 to 25, `L7` has 19 variables and `L26`
none. At `n = 22` they are 6 to 27, and the top is `L28`.

**The outputs**, in output-map order, are §5.8's with this family's channel ids: outputs 0 and 1
the memory roots, read at `verify_shard` step 10 against `memory_roots[p]` for `p` the position
of `(5, shard_index)` in `verifier_core::statement_shards`; 2–9 the four channels' `num`/`den`
pairs, read at step 9, each failure `Lookup { channel }` for channel 0, 1, 2 and 3 in turn.

### 8.9 Witness rows

The table shows eight of the 20 live rows of `guests/mem`'s `MEM_SUBWORD` shard, as
`prover::family_fill(5)` writes them, plus the first padding row after them.
`crates/checker/tests/mem_fill.rs`' `the_mem_subword_fill_satisfies_every_gate_and_every_table`
holds exactly these columns to every gate, every range obligation and both table channels in
ordinary CI, over every live row, the two padding rows after them and the shard's last row. The
circuit is also held to a hand-built catalogue of its own: `crates/checker/tests/mem_subword.rs`'
`honest_rows`, **25 rows** — every kind at every offset its width allows, both signs at both
widths over one word whose bytes are `0x01`, `0x7f`, `0xfe` and `0x88`, a store whose source
byte is the byte already there, `lb` into `x0`, a base of `x0`, a wrapping address, a negative
displacement, a compressed `lh`, and the padding row. §8.10's forgeries all start from that
catalogue.

Every live row below reads or rewrites one word: `0x88776655` at `0x20010` for the loads,
`0x11223344` at `0x20018` or `0x2001c` for the stores. `A` `lbu` at offset 0. `B` `lbu` at
offset 3. `C` `lb` at offset 3, the same byte sign-extended. `D` `lhu` at offset 2. `E` `lh` at
offset 2, sign-extended. `F` `sb` at offset 0 from `x6 = 0xdeadbeef`. `G` `sb` at offset 3.
`H` `sh` at offset 2 from `x6 = 0xcafebabe`. `P` the first padding row. Every cell not listed is
0 on all nine; `S[0..7]` hold `MINUS_ONE` at these rows and `S[7..10]` the packed table's rows
0 to 8, and both are omitted.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 44 | 56 | 72 | 81 | 91 | 106 | 139 | 161 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[4]` `pc_read_value` | `0x100a8` | `0x100d8` | `0x10118` | `0x1013c` | `0x10164` | `0x101a0` | `0x10224` | `0x1027c` | 0 |
| `M[5]` `pc_write_value` | `0x100ac` | `0x100dc` | `0x1011c` | `0x10140` | `0x10168` | `0x101a4` | `0x10228` | `0x10280` | 0 |
| `M[7]` `rs1_addr` | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 0 |
| `M[9]` `rs1_read_value` | `0x20000` | `0x20000` | `0x20000` | `0x20000` | `0x20000` | `0x20000` | `0x20000` | `0x20000` | 0 |
| `M[11]` `rs2_mask` | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 0 |
| `M[14]` `rs2_read_value` | 0 | 0 | 0 | 0 | 0 | `0xdeadbeef` | `0xdeadbeef` | `0xcafebabe` | 0 |
| `M[16]` `load_mask` | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |
| `M[17]` `load_addr` | `0x20010` | `0x20010` | `0x20010` | `0x20010` | `0x20010` | 0 | 0 | 0 | 0 |
| `M[19]` `load_read_value` | `0x88776655` | `0x88776655` | `0x88776655` | `0x88776655` | `0x88776655` | 0 | 0 | 0 | 0 |
| `M[21]` `ram_mask` | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 0 |
| `M[22]` `ram_addr` | 0 | 0 | 0 | 0 | 0 | `0x20018` | `0x20018` | `0x2001c` | 0 |
| `M[24]` `ram_read_value` | 0 | 0 | 0 | 0 | 0 | `0x11223344` | `0x11223344` | `0x11223344` | 0 |
| `M[25]` `ram_write_value` | 0 | 0 | 0 | 0 | 0 | `0x112233ef` | `0xef223344` | `0xbabe3344` | 0 |
| `M[26]` `rd_mask` | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |
| `M[27]` `rd_addr` | 6 | 6 | 6 | 6 | 6 | 0 | 0 | 0 | 0 |
| `M[30]` `rd_write_value` | `0x55` | `0x88` | `0xffffff88` | `0x8877` | `0xffff8877` | 0 | 0 | 0 | 0 |
| `W[0..6]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[8]` `rd_selected` | `0x55` | `0x88` | `0xffffff88` | `0x8877` | `0xffff8877` | 0 | 0 | 0 | 0 |
| `W[13]` `decoded_imm` | 16 | 19 | 19 | 18 | 18 | 24 | 27 | 30 | 0 |
| `W[14]` `decoded_mask` | 4 | 4 | 1 | 8 | 2 | 16 | 16 | 32 | 0 |
| `W[15..21]` the kind bit set | `lbu` | `lbu` | `lb` | `lhu` | `lh` | `sb` | `sb` | `sh` | none |
| `W[21]` `wrap` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[22]` `word_index` | `0x8004` | `0x8004` | `0x8004` | `0x8004` | `0x8004` | `0x8006` | `0x8006` | `0x8007` | 0 |
| `W[24]` `bit0` | 0 | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 |
| `W[25]` `bit1` | 0 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 0 |
| `W[26]` `p` | 1 | `2^24` | `2^24` | `2^16` | `2^16` | 1 | `2^24` | `2^16` | 0 |
| `W[27]` `pcopow` | `2^31` | 128 | 128 | `2^15` | `2^15` | `2^31` | 128 | `2^15` | 0 |
| `W[28]` `wph` | 128 | `2^31` | `2^31` | `2^31` | `2^31` | 128 | `2^31` | `2^31` | 0 |
| `W[29]` `p_ram` | 0 | 0 | 0 | 0 | 0 | 1 | `2^24` | `2^16` | 0 |
| `W[30]` `word` | `0x88776655` | `0x88776655` | `0x88776655` | `0x88776655` | `0x88776655` | `0x11223344` | `0x11223344` | `0x11223344` | 0 |
| `W[31]` `high` | `0x887766` | 0 | 0 | 0 | 0 | `0x112233` | 0 | 0 | 0 |
| `W[33]` `high_scaled` | `0x88776600` | 0 | 0 | 0 | 0 | `0x11223300` | 0 | 0 | 0 |
| `W[35]` `sub` | `0x55` | `0x88` | `0x88` | `0x8877` | `0x8877` | `0x44` | `0x11` | `0x1122` | 0 |
| `W[36]` `sub_scaled` | `0x55000000` | `0x88000000` | `0x88000000` | `0x88770000` | `0x88770000` | `0x44000000` | `0x11000000` | `0x11220000` | 0 |
| `W[38]` `low` | 0 | `0x776655` | `0x776655` | `0x6655` | `0x6655` | 0 | `0x223344` | `0x3344` | 0 |
| `W[40]` `low_scaled` | 0 | `0x77665500` | `0x77665500` | `0x66550000` | `0x66550000` | 0 | `0x22334400` | `0x33440000` | 0 |
| `W[42]` `src_sub` | 0 | 0 | 0 | 0 | 0 | `0xef` | `0xef` | `0xbabe` | 0 |
| `W[43]` `src_sub_scaled` | 0 | 0 | 0 | 0 | 0 | `0xef000000` | `0xef000000` | `0xbabe0000` | 0 |
| `W[45]` `src_high` | 0 | 0 | 0 | 0 | 0 | `0xdeadbe` | `0xdeadbe` | `0xcafe` | 0 |
| `W[47]` `sign_in` | `0x5500` | `0x8800` | `0x8800` | `0x8877` | `0x8877` | `0x4400` | `0x1100` | `0x1122` | 0 |
| `W[48]` `sign` | 0 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |
| `W[49]` `se` | 0 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 |
| `W[50]` `rd_hi` | 0 | 0 | `0xffff` | 0 | `0xffff` | 0 | 0 | 0 | 0 |

`W[32]` `high_hi`, `W[34]` `high_scaled_hi`, `W[37]` `sub_scaled_hi`, `W[39]` `low_hi`,
`W[41]` `low_scaled_hi`, `W[44]` `src_sub_scaled_hi` and `W[46]` `src_high_hi` are each the high
halfword of the column above them and are omitted; so are the four multiplicity columns, which
on a real shard are counts over all `2^20` rows.

`B` and `C` are the same byte read two ways: `sub = 0x88`, `sign = 1` from the packed table, and
`se` is 1 only on `C`, where `rd = 0x88 − 256 + 2^32`. `D` and `E` are the same halfword. `A`
and `F` are the offset-0 rows, where `p = 1`, `low = 0` and `pcopow` is `2^31`, its largest
value — the halving is what keeps the column inside a word there. `G` is the offset-3 byte
store, where `wph` is `2^31` and `high` is 0, the sub-word being the top byte. `H` is the
halfword store, where `src_sub = 0xbabe` is a genuine truncation of `0xcafebabe` and
`src_high = 0xcafe` carries the rest.

### 8.10 What fixes each cell

The per-cell accounting is `crates/checker/tests/mem_subword.rs`' own, and it is a committed
one: `each_gate_is_the_one_that_refuses_its_row` carries 32 tampers, each an edit to a named
honest row beside **the exact set** of relations that refuse it, asserted equal. It ends with a
completeness assertion: of the circuit's 53 enforcing gates the frame's thirteen and every
`*_boolean` are set aside, and each of the remaining **31** must be named by some tamper above.
`every_booleanity_gate_refuses_a_value_of_two` covers the nine booleans this family commits —
the six kind bits, the wrap and the two offset bits — and eight further tests take one question
each.

| cell moved | on the row | refused by, exactly |
| --- | --- | --- |
| `decoded_mask` → `lb`'s | `lbu at 0` | `decoded_mask_bits` |
| the `rs1` query dropped | `lbu through x0` | `rs1_mask_rule` |
| an `rs2` query added | `lbu at 0` | `rs2_mask_rule` |
| a `load` query added | `sb at 0` | `load_mask_rule` |
| a `ram` query added, with `p_ram` and the written word dressed to match | `lbu at 0` | `ram_mask_rule` |
| `rs1_addr` `+ 1` | a load | `rs1_addr_rule` |
| `rs2_addr` `+ 1` | a store | `rs2_addr_rule` |
| `rd_addr` moved | `lbu at 0` | `rd_addr_rule` |
| `load_addr` `+ 4` | `lbu at 0` | `load_addr_rule` |
| `ram_addr` `+ 4` | `sb at 0` | `ram_addr_rule` |
| `rs1_read_value` → 4 | padding | `rs1_value_masked` |
| `rs2_read_value` → 5 | `lbu at 0` | `rs2_value_masked` |
| `word_index` one word too high, the query's address with it | `lbu at 0` | `addr_split` |
| `bit0` set at halfword width | an `lhu` | `half_aligned` |
| `word` → something other than the word read, `low` moved so the splice still holds | `lbu at 0` | `word_rule` |
| `p_ram` → 0 | `sb at 0` | `p_ram_rule` |
| `se` → 1 | `lbu at 0` | `se_rule` |
| `p` → offset 0's value | `lbu at 1` | `p_rule` |
| `pcopow` halved | `lbu at 0` | `pcopow_rule` |
| `wph` moved | `lbu at 3` | `wph_rule` |
| the three parts no longer summing to `word` | `lbu at 0` | `splice_rule` |
| a unit moved from `low` into `high` | `lbu at 0` | `high_scaled_rule` |
| `sub_scaled` `+ 1` | `lbu at 0` | `sub_scaled_rule` |
| `low_scaled` `+ 1` | `lbu at 0` | `low_scaled_rule` |
| `src_sub_scaled` `+ 1` | `sb at 0` | `src_sub_scaled_rule` |
| `src_sub` unrelated to `rs2` | `sb at 0` | `src_sub_rule` |
| `sign_in` not the sub-word's | `lbu at 0` | `sign_in_rule` |
| `rd_selected` `+ 1` | `lbu at 0` | `rd_value_rule` |
| `ram_write_value` `+ 1` | `sb at 0` | `store_rule` |
| `pc_write_value` `+ 4` | `lbu at 0` | `next_pc_rule` |
| an `rd` query rewriting `x10` | padding | `rd_mask_rule`, `rd_addr_rule`, `rd_value_rule` |
| the same, dressed as `lbu` with `decoded_rd = 10` | padding | `rd_mask_rule` |

The eight further tests, each isolating one thing the accounting above cannot show cell by cell:

- **`the_splice_admits_exactly_one_witness_at_a_reduced_width`** — S19's reduced-width
  acceptance, and the reason `splice_gates` takes a width at all. At a **one-bit byte** it
  enumerates the witness space and asserts that the decomposition of a word into
  `high·(w·p) + sub·p + low` is unique, over the family's own gates rather than a transcription
  of them.
- **`a_halfword_at_an_odd_address_is_unprovable`** — `half_aligned` as a row, and the statement
  that `w·p` never reaches `2^40`.
- **`an_lbu_that_yields_more_than_a_byte_is_refused`** — `sub_scaled`'s pair, which is what
  makes `sub < w` rather than `sub < 2^16`.
- **`a_free_high_is_refused`** — `high`'s own pair against the scaled one, S18's residue hole in
  this family's shape.
- **`a_store_source_unrelated_to_rs2_is_refused`** — `src_sub_rule` with its bounds: without it
  `sb` could store a byte no register holds.
- **`the_generic_key_stays_inside_its_sub_table`** — the sign lookup's key bound, which is the
  half of §8.6's argument a test still carries.

On a padding row `pc_mask = 0`, every frame mask is 0, every leaf is 1 and every obligation is
vacuous — all 22 `RANGE16` ones and the generic one included, this family having no selector but
`pc_mask` and the frame's masks. `p_rule` then reads `p = 0`, and with `p` zero `pcopow_rule`,
`wph_rule`, `splice_rule` and `store_rule` all read `0 = 0`: **`pcopow` is free there**, which is
what makes it acceptance 8's negative control (`memory-ops.md` §9). The six kind bits, the wrap
and the two offset bits are free booleans, and with every kind bit 0 the gates hold `word`,
`se`, `rd_selected`, `ram_write_value` and `pc_write_value − decoded_next_pc` to 0. The honest
fill writes 0 everywhere.

---

## 9. `ATOMICS` — family 6

### 9.1 Header

`family_circuit(6, n)` is `atomics::artifact(n)` with `atomics::channels()`, built by
`memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` through the private
`family_spec` (`QUERIES`, the `SLOT_*` constants and the per-kind constants `AMOADD` … `AMOMAXU`
are private to `atomics.rs`). It uses **S17's comparison gadget** — `gadgets::comparison` over
the private `the_comparison()` — beside the frame's x0 rule, and **S18's byte AND table**, from
which `or` and `xor` are derived by linearity with no table of their own. Normative spec:
`memory-ops.md` §6. Fill: `prover::family_fill(6)`, the private `fill::atomics`.

89 committed columns (26 `M`, 54 `W`, **9** `S`) and two virtual tables. Gate list 0 writes 132
leaves and holds 46 enforcing gates. 36 lookups on four channels, 10 outputs. At `n = 20`, the
height S19 proves, there are 26 gate lists, the top is `L26`, and the circuit has 472 inner
columns and 518 relations; a shard proof of it is 68,468 bytes. At `n = 22` — the committed
fixture — there are 28 lists, the top is `L28`, and it has 492 inner columns, 538 relations and
102,965 bytes of wire form, the largest of any registered circuit.

**This family's decoded tuple has no immediate, and that is visible everywhere.** Every A
instruction is R-type and an atomic's address is `rs1` alone, so `program::lookup_tuple(6)` is
`pc next_pc rs1 rs2 rd extra_mask` — **six columns, not seven** — which makes
`atomics::TABLE_WIDTH` 6, the claimed decoded row five columns (`W[8..13]`), the decoder tuple
six wide, the setup subtree **nine** columns, the packed generic table `S[6..9]` rather than
`S[7..10]`, and the decoder denominator's top `β` power `β⁵` rather than `β⁶` (§0.4). It is the
second registered circuit whose `g_dec` is `g − Σ_{j<6} β^j`, `MUL_DIV` being the first.

**`DEFAULT_HEIGHTS[ATOMICS]` was `2^16` from S11 until this stage and is `2^20` now**
(`memory-ops.md` §7.1). A circuit carrying a timestamp gap obligation needs 19 variables and a
Mercury opening needs an even count, so `2^20` is the floor for every family that runs cycles;
this was the family the frozen defaults placed below it, and S16 answer 7 deferred the raise to
the stage that gave it a circuit. `family_circuit`'s `trace_vars < 19 ⇒ None` arm now names all
seven execution families, so a key naming this one at `2^16` fails to load rather than panicking
inside `lookup::channel_trees` (`memory-ops.md` §7.2).

`artifact` panics unless the frame is `QUERIES`, the comparison's four parameters are the ones
`assemble` asserts — selector `pc_mask`, `lhs` the RAM query's read value, `rhs` `rs2`'s, and
`signed` exactly `[amomin, amomax]` — the channels carry exactly 10, 19, 6 and 1 obligations,
`lookup::check_copowers` finds a direct range pair under the same selector for the five columns
it bounds by scaling — `word_index_hi` under `pc_mask` and the four `byte_a` keys under
`f_bitwise` — and every gate is zero on the all-zero row. It also panics on every refusal of the
assembly, among them `n < 19` and `n > 30`; `family_circuit` returns `None` for both.

### 9.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::atomics`, bit `k` being
`W[13 + k]`. The order is **ascending `funct5`** — `amoadd`, `amoswap`, `lr`, `sc`, `amoxor`,
`amoor`, `amoand`, `amomin`, `amomax`, `amominu`, `amomaxu` — which is not the stage prompt's
listing order; every arm of `ram_value_rule` indexes `KINDS` through its `extra_mask` constant
and never by position, and `the_kind_bits_are_the_extra_mask_constants` in
`crates/checker/tests/atomics.rs` holds each of the eleven `Instr` variants to the bit its arm
uses (`memory-ops.md` §1). `aq` and `rl` are not recorded: on one hart they order nothing, so
`lr.w.aq` and `lr.w` are one kind.

**One row is one read-modify-write.** The RAM query at slot 3 carries the old word as its read
and the new word as its write, and the `rd` query at the same `Δ = 3` takes the old word, at a
different address space; this is the one family with **two queries in one `Δ` slot**, so one
of its rows makes five (`execution-trace.md` §4). A `lw` fills all four slots as well — pc,
`rs1`, its word and `rd` — so what is unique here is the sharing. There is no `load` query: the whole extension keeps its RAM query at
slot 3, `lr.w` included, though `lr.w` is a plain word load and a load's word is at slot 2 for
every other family (`execution-trace.md` §7, frozen at S12).

`old` below is the RAM query's read value, `src` is `rs2`'s, and
`A = Σ_j 2^(8j)·byte_and_j` is the AND accumulator, a linear form and never a column.

| row kind | bit (`decoded_mask`) | `rs2` query | `f_bitwise` | `ram_write_value` | `rd_selected` |
| --- | --- | --- | --- | --- | --- |
| `amoadd` | 0 (1) | yes | 0 | `sum` | `old` |
| `amoswap` | 1 (2) | yes | 0 | `src` | `old` |
| `lr` | 2 (4) | **no** | 0 | `old` | `old` |
| `sc` | 3 (8) | yes | 0 | `src` | **0** |
| `amoxor` | 4 (16) | yes | 1 | `old + src − 2A` | `old` |
| `amoor` | 5 (32) | yes | 1 | `old + src − A` | `old` |
| `amoand` | 6 (64) | yes | 1 | `A` | `old` |
| `amomin` | 7 (128) | yes | 0 | `lo`, ordered signed | `old` |
| `amomax` | 8 (256) | yes | 0 | `old + src − lo`, signed | `old` |
| `amominu` | 9 (512) | yes | 0 | `lo`, ordered unsigned | `old` |
| `amomaxu` | 10 (1024) | yes | 0 | `old + src − lo`, unsigned | `old` |
| padding | none; all 0 | none | a free boolean | 0 | 0 |

All eleven are provable at S19. `next_pc` is the fall-through on every row — no kind computes a
pc, and the A extension has no compressed form, so the fall-through is always `pc + 4`.
`rd = x0` is not a kind: the row still reads and rewrites the word and computes `rd_selected`,
and the frame's x0 rule writes 0.

**`lr.w` has no `rs2` register in its form**, so `m_rs2` is `m_pc` times the other ten bits —
keyed on `b_lr`, never on `is_zero(decoded_rs2)`, which `amoadd.w rd, x0, (rs1)` would also
satisfy (`memory-ops.md` §6.1).

**`sc.w` always succeeds**, storing `rs2` and writing `rd = 0` with no reservation state anywhere
in the machine. That is a conformance deviation and not a soundness one — the verifier still
knows exactly which program ran and what it computed — and it is the emulator's semantics too,
so emulator and circuit agree (`memory-ops.md` §6.6); a machine that keeps a reservation
set may fail an unpaired `sc.w` where this one succeeds, and nothing compares the two, there being no oracle for
what a guest computes and never for how this emulator computes it. `sc_w_always_succeeds` in the row suite refuses both halves of failure:
a nonzero code by `rd_value_rule`, and the word left alone by `ram_value_rule`.

### 9.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §9.4 and §9.6.

**Memory-argument columns, `M[0..26]`** — §2's ATOMICS layout (`w = 5`), the only family with
it, and the bare frame fixture `memory_frame_atomics.bin`; filled by
`trace::build_memory_columns`, committed in `PublicInputs::memory_commitments`, absorbed at G8
before the memory challenges. The frame's slots in `atomics.rs` are `SLOT_PC = 0`,
`SLOT_RS1 = 1`, `SLOT_RS2 = 2`, `SLOT_RAM = 3`, `SLOT_RD = 4`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the cycle `c` | leaves `write_*` (all 5); obligations `gap_lo_*` (all 5) |
| `M[1]` | `pc_mask` | `frame(0, FIELD_MASK)` | Row is live | 1 | leaves `read_pc`, `write_pc`; `pc_mask_boolean`, the four mask rules; selector of `gap_hi_pc`, `gap_lo_pc`, the eleven `m_pc` `RANGE16` obligations, both sign lookups and `decode_row` |
| `M[2]` | `pc_addr` | `frame(0, FIELD_ADDR)` | PC address | 0 | leaves `read_pc`, `write_pc` |
| `M[3]` | `pc_read_ts` | `frame(0, FIELD_READ_TS)` | Previous pc write | `4(c − 1)` | leaf `read_pc`; `gap_lo_pc` |
| `M[4]` | `pc_read_value` | `frame(0, FIELD_READ_VALUE)` | Current pc | the instruction's pc | leaf `read_pc`; `decode_row` position 0 |
| `M[5]` | `pc_write_value` | `frame(0, FIELD_WRITE_VALUE)` | Next pc | `pc + 4` | leaf `write_pc`; `next_pc_rule` |
| `M[6]` | `rs1_mask` | `frame(1, FIELD_MASK)` | rs1 present | 1 on every kind | leaves `read_rs1`, `write_rs1`; `rs1_mask_boolean`, `rs1_mask_rule`, `rs1_addr_rule`, `rs1_value_masked`; selector of `gap_hi_rs1`, `gap_lo_rs1` |
| `M[7]` | `rs1_addr` | `frame(1, FIELD_ADDR)` | Address register | the decoded `rs1` | leaves `read_rs1`, `write_rs1`; `rs1_addr_rule` |
| `M[8]` | `rs1_read_ts` | `frame(1, FIELD_READ_TS)` | rs1 previous write | | leaf `read_rs1`; `gap_lo_rs1` |
| `M[9]` | `rs1_read_value` | `frame(1, FIELD_READ_VALUE)` | The word's byte address | `4·word_index` | leaf `read_rs1`; `rs1_writes_back`, `rs1_value_masked`, `addr_word` |
| `M[10]` | `rs1_write_value` | `frame(1, FIELD_WRITE_VALUE)` | rs1 written back | `rs1_read_value` | leaf `write_rs1`; `rs1_writes_back` |
| `M[11]` | `rs2_mask` | `frame(2, FIELD_MASK)` | rs2 present | 1 on every kind but `lr` | leaves `read_rs2`, `write_rs2`; `rs2_mask_boolean`, `rs2_mask_rule`, `rs2_addr_rule`, `rs2_value_masked`; selector of `gap_hi_rs2`, `gap_lo_rs2` |
| `M[12]` | `rs2_addr` | `frame(2, FIELD_ADDR)` | Source register | the decoded `rs2` | leaves `read_rs2`, `write_rs2`; `rs2_addr_rule` |
| `M[13]` | `rs2_read_ts` | `frame(2, FIELD_READ_TS)` | rs2 previous write | | leaf `read_rs2`; `gap_lo_rs2` |
| `M[14]` | `rs2_read_value` | `frame(2, FIELD_READ_VALUE)` | The second operand, `src` | 0 on an `lr` row | leaf `read_rs2`; `rs2_writes_back`, `rs2_value_masked`, `add_rule`, `src_bytes_rule`, `cmp_order`, `lo_rule`, `ram_value_rule`; `cmp_rhs_lo_range` |
| `M[15]` | `rs2_write_value` | `frame(2, FIELD_WRITE_VALUE)` | rs2 written back | `rs2_read_value` | leaf `write_rs2`; `rs2_writes_back` |
| `M[16]` | `ram_mask` | `frame(3, FIELD_MASK)` | The word is present | 1 on every kind | leaves `read_ram`, `write_ram`; `ram_mask_boolean`, `ram_mask_rule`, `ram_addr_rule`; selector of `gap_hi_ram`, `gap_lo_ram` |
| `M[17]` | `ram_addr` | `frame(3, FIELD_ADDR)` | The word's byte address | `4·word_index` | leaves `read_ram`, `write_ram`; `ram_addr_rule` |
| `M[18]` | `ram_read_ts` | `frame(3, FIELD_READ_TS)` | The word's previous write | | leaf `read_ram`; `gap_lo_ram` |
| `M[19]` | `ram_read_value` | `frame(3, FIELD_READ_VALUE)` | The old word, `old` | | leaf `read_ram`; `add_rule`, `old_bytes_rule`, `cmp_order`, `lo_rule`, `ram_value_rule`, `rd_value_rule`; `cmp_lhs_lo_range` |
| `M[20]` | `ram_write_value` | `frame(3, FIELD_WRITE_VALUE)` | The new word | the kind's arm | leaf `write_ram`; `ram_value_rule` |
| `M[21]` | `rd_mask` | `frame(4, FIELD_MASK)` | rd present | 1 on every kind | leaves `read_rd`, `write_rd`; `rd_mask_boolean`, `rd_is_zero_inverse`, `rd_mask_rule`, `rd_addr_rule`; selector of `gap_hi_rd`, `gap_lo_rd` |
| `M[22]` | `rd_addr` | `frame(4, FIELD_ADDR)` | rd register | the decoded `rd` | leaves `read_rd`, `write_rd`; `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_addr_rule` |
| `M[23]` | `rd_read_ts` | `frame(4, FIELD_READ_TS)` | rd previous write | | leaf `read_rd`; `gap_lo_rd` |
| `M[24]` | `rd_read_value` | `frame(4, FIELD_READ_VALUE)` | rd old value | | leaf `read_rd` **and nothing else** |
| `M[25]` | `rd_write_value` | `frame(4, FIELD_WRITE_VALUE)` | rd new value | the old word, or 0 into `x0` | leaf `write_rd`; `rd_write_masked` |

**`ram_read_value` is read by six of this family's gates**, where §7's is read by none: it is
both the value handed back in `rd` and the left operand of every arithmetic, bitwise and ordering
arm. That is what makes the `rd` old-value cell, `M[24]`, the family's tamper target instead
(`memory-ops.md` §9).

**Witness columns, `W[0..54]`** — `W[0..7]` filled by `trace::build_frame_witness`, `W[7..50]`
by `fill::atomics` (`W[7]` in place of S14's), `W[50..54]` by `trace::build_multiplicities`
inside `prover::shard_columns`; committed in `ShardProof::witness_commitments`, absorbed at S3
before `g` and `β`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0..5]` | `pc_gap_hi` … `rd_gap_hi` | `memory::gap_hi(s)` | the five gap chunks | `gap >> 19` | `gap_hi_<q>`, `gap_lo_<q>` |
| `W[5]` | `rd_inv` | `memory::rd_inv(5)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[6]` | `rd_is_zero` | `memory::rd_is_zero(5)` | rd is `x0` | | the three x0 gates |
| `W[7]` | `rd_selected` | `memory::rd_selected(5)`; `sel` | The word handed back | `old`, or 0 on `sc.w` | `rd_write_masked`, `rd_value_rule` |
| `W[8..13]` | `decoded_next_pc` … `decoded_mask` | `atomics::DECODED` | the claimed decoded row — **five** | the table row after `pc` | `next_pc_rule`, `rs1_addr_rule`, `rs2_addr_rule`, `rd_addr_rule`, `decoded_mask_bits`; `decode_row` positions 1–5 |
| `W[13..24]` | `kind_amoadd` … `kind_amomaxu` | `KINDS[k]` | the eleven kind bits | one-hot on a live row | `kind_<k>_boolean`, `decoded_mask_bits`, the four mask rules, `f_bitwise_rule` (three of them), `ram_value_rule`, `rd_value_rule` (ten of them) |
| `W[24]` | `word_index` | `atomics::WORD_INDEX` | The word's index | `rs1 / 4` | `ram_addr_rule`, `addr_word`; `word_index_lo_range` |
| `W[25]` | `word_index_hi` | `WORD_INDEX_HI` | its high halfword | | `word_index_hi_range`, `word_index_lo_range`, `word_index_hi_scaled` |
| `W[26]` | `sum` | `SUM` | `old + src` reduced | on **every** live row | `add_rule`, `ram_value_rule`; `sum_lo_range` |
| `W[27]` | `sum_hi` | `SUM_HI` | `sum`, high halfword | | `sum_hi_range`, `sum_lo_range` |
| `W[28]` | `add_wrap` | `ADD_WRAP` | the addition's carry | | `add_wrap_boolean`, `add_rule` |
| `W[29]` | `f_bitwise` | `F_BITWISE` | Row is `and`, `or` or `xor` | | `f_bitwise_rule`, `f_bitwise_boolean`; **selector** of the eight `byte_a*` bounds and the four `and_byte_*` lookups |
| `W[30..34]` | `byte_a0` … `byte_a3` | `BYTES_A[j]` | the old word's bytes, low first | `(old >> 8j) & 255` | `old_bytes_rule`; `byte_a{j}_range`, `byte_a{j}_scaled`, `and_byte_{j}` position 0 |
| `W[34..38]` | `byte_b0` … `byte_b3` | `BYTES_B[j]` | `rs2`'s bytes, low first | `(src >> 8j) & 255` | `src_bytes_rule`; `and_byte_{j}` position 1 |
| `W[38..42]` | `byte_and0` … `byte_and3` | `BYTES_AND[j]` | the bytewise AND | `byte_a_j & byte_b_j` | `ram_value_rule`; `and_byte_{j}` position 2 |
| `W[42]` | `old_hi` | `OLD_HI` | `old`, high halfword | | no enforcing gate: `cmp_lhs_hi_range`, `cmp_lhs_lo_range`, `cmp_lhs_get_sign` position 0 |
| `W[43]` | `old_sign` | `OLD_SIGN` | `old`, bit 31 | | `cmp_order`; `cmp_lhs_get_sign` position 1 |
| `W[44]` | `src_hi` | `SRC_HI` | `src`, high halfword | | no enforcing gate: `cmp_rhs_hi_range`, `cmp_rhs_lo_range`, `cmp_rhs_get_sign` position 0 |
| `W[45]` | `src_sign` | `SRC_SIGN` | `src`, bit 31 | | `cmp_order`; `cmp_rhs_get_sign` position 1 |
| `W[46]` | `lt` | `LT` | `old` is the smaller | under the row's ordering | `cmp_order`, `cmp_lt_boolean`, `lo_rule` |
| `W[47]` | `cmp_gap` | `CMP_GAP` | the comparison's gap | `old − src + 2^32·lt` | `cmp_order`; `cmp_gap_lo_range` |
| `W[48]` | `cmp_gap_hi` | `CMP_GAP_HI` | its high halfword | | `cmp_gap_hi_range`, `cmp_gap_lo_range` |
| `W[49]` | `lo` | `LO` | the smaller of the two | | `lo_rule`, `ram_value_rule` |
| `W[50]` | `mult_timestamp` | `MULTIPLICITIES[0]` | Timestamp-table count | | leaf `timestamp_table_num` |
| `W[51]` | `mult_range16` | `MULTIPLICITIES[1]` | 16-bit-table count | 11 obligations under `pc_mask`, 8 under `f_bitwise` | leaf `range16_table_num` |
| `W[52]` | `mult_generic` | `MULTIPLICITIES[2]` | Generic-table count | a live row's two sign lookups land on `U16GetSign`'s rows `2^16 + 1 + old_hi` and `2^16 + 1 + src_hi`; a bitwise row's four AND lookups on rows `1 + byte_a_j`; every switched-off tuple on the `ZeroEntry`, row 0 | leaf `generic_table_num` |
| `W[53]` | `mult_decoder` | `MULTIPLICITIES[3]` | Decoder-table count | per table row `t`: the live cycles at pc `2t`; and every padding row's switched-off tuple (`MINUS_ONE` in all six positions) on the table's lowest non-live row, row 0 | leaf `decoder_table_num` |

`f_bitwise` is this family's **one** second selector, and it is a column for exactly the reason
§5's two halves are: it selects lookups, and `validate` refuses a selector without a booleanity
gate. Eight of the 19 `RANGE16` obligations and four of the six generic lookups sit under it, so
a non-bitwise live row switches twelve tuples off and a bitwise row switches none.

**Setup columns, `S[0..9]`** — two tables, and **nine** columns rather than ten. `S[0..6]` is
the family's decoded table, `program::lookup_tuple(6)` order — `table_pc`, `table_next_pc`,
`table_rs1`, `table_rs2`, `table_rd`, `table_extra_mask`, at weights 1 to `β⁵` — filled by
`program::FamilyTable::column_poly(j)` and committed in program identity. `S[6..9]` is the
packed generic table (§0.3) — `generic_key`, `generic_value`, `generic_result` at 1, `β`, `β²` —
filled by `program::lookup_tables::generic_table(n)`, carried in every key as
`VerifyingKey::generic_table` and covered by the key's SRS digest, not by identity. Each is read
only by its table's denominator. `atomics::TABLE_WIDTH` is 6 and
`constants::generic_table::WIDTH` is 3. A shard opens 89 commitments: 26, 54, the six of
identity's list, then the table's three (`shard-proof.md` §3, §5.1; `jump-branch-slt.md` §6).

**Virtual tables** — `V[range19]` and `V[range16]`, §7.3's, read by `timestamp_table_den` and
`range16_table_den`.

### 9.4 Gate list 0: the 132 leaves

A leaf's relation number equals its `L1` offset, 0 to 131.

**The memory product trees.** The read side is `L1[0..8]` and the write side `L1[8..16]`, each
leaf per §0.6. Five queries fill eight leaves a side, so each side carries **three** pads — the
widest memory padding of any registered family.

| `L1` | node | mask | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `read_pc` | `M[1]` | 3 | `M[2]` | `M[3]` | `M[4]` |
| 1 | `read_rs1` | `M[6]` | 1 | `M[7]` | `M[8]` | `M[9]` |
| 2 | `read_rs2` | `M[11]` | 1 | `M[12]` | `M[13]` | `M[14]` |
| 3 | `read_ram` | `M[16]` | 2 | `M[17]` | `M[18]` | `M[19]` |
| 4 | `read_rd` | `M[21]` | 1 | `M[22]` | `M[23]` | `M[24]` |
| 5–7 | `read_pad_0` … `read_pad_2` | — | — | — | — | the literal 1 |
| 8 | `write_pc` | `M[1]` | 3 | `M[2]` | `4·M[0] + 0` | `M[5]` |
| 9 | `write_rs1` | `M[6]` | 1 | `M[7]` | `4·M[0] + 1` | `M[10]` |
| 10 | `write_rs2` | `M[11]` | 1 | `M[12]` | `4·M[0] + 2` | `M[15]` |
| 11 | `write_ram` | `M[16]` | 2 | `M[17]` | `4·M[0] + 3` | `M[20]` |
| 12 | `write_rd` | `M[21]` | 1 | `M[22]` | `4·M[0] + 3` | `M[25]` |
| 13–15 | `write_pad_0` … `write_pad_2` | — | — | — | — | the literal 1 |

`write_ram` and `write_rd` share `Δ = 3` at address spaces 2 and 1, which is what lets one row
be one read-modify-write (`memory-ops.md` §6.1).

**The `timestamp` fraction tree**, `L1[16..48]`: 16 fractions, the table's then 10 gap
obligations then **5** pads — the table's, then `gap_hi`/`gap_lo` for `pc`, `rs1`, `rs2`, `ram`
and `rd`, with `Δ − 1` of `−1`, 0, 1, 2 and 2 in the low chunks' constants.

**The `range16` fraction tree**, `L1[48..112]`: **32 fractions**, the table's then 19
obligations then 12 pads. Eleven obligations are under `pc_mask` and eight under `f_bitwise`.

| fraction | `L1` | node | numerator | denominator (named) | selector |
| --- | --- | --- | --- | --- | --- |
| 0 | 48, 49 | `range16_table` | `−mult_range16` | `V[range16] + g` | — |
| 1, 2 | 50–53 | `cmp_lhs_hi_range`, `cmp_lhs_lo_range` | 1 | the 16+16 pair on `ram_read_value` | `pc_mask` |
| 3, 4 | 54–57 | `cmp_rhs_hi_range`, `cmp_rhs_lo_range` | 1 | the pair on `rs2_read_value` | `pc_mask` |
| 5, 6 | 58–61 | `cmp_gap_hi_range`, `cmp_gap_lo_range` | 1 | the pair on `cmp_gap` | `pc_mask` |
| 7 | 62, 63 | `word_index_hi_range` | 1 | `g + pc_mask·word_index_hi` | `pc_mask` |
| 8 | 64, 65 | `word_index_lo_range` | 1 | `g + pc_mask·word_index − 2^16·pc_mask·word_index_hi` | `pc_mask` |
| 9 | 66, 67 | `word_index_hi_scaled` | 1 | `g + 4·pc_mask·word_index_hi` | `pc_mask` |
| 10, 11 | 68–71 | `sum_hi_range`, `sum_lo_range` | 1 | the pair on `sum` | `pc_mask` |
| 12 | 72, 73 | `byte_a0_range` | 1 | `g + f_bitwise·byte_a0` | `f_bitwise` |
| 13 | 74, 75 | `byte_a0_scaled` | 1 | `g + 256·f_bitwise·byte_a0` | `f_bitwise` |
| 14–19 | 76–87 | `byte_a1_range` … `byte_a3_scaled` | 1 | the same pair per byte | `f_bitwise` |
| 20–31 | 88–111 | `range16_pad_0` … `range16_pad_11` | 0 | 1 | — |

**The `generic` fraction tree**, `L1[112..128]`: 8 fractions, the table's then 6 lookups then 1
pad.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 112, 113 | `generic_table` | `−mult_generic` | `generic_key + β·generic_value + β²·generic_result + g` |
| 1 | 114, 115 | `cmp_lhs_get_sign` | 1 | `g + 257·pc_mask + pc_mask·old_hi + β·pc_mask·old_sign` |
| 2 | 116, 117 | `cmp_rhs_get_sign` | 1 | `g + 257·pc_mask + pc_mask·src_hi + β·pc_mask·src_sign` |
| 3 | 118, 119 | `and_byte_0` | 1 | `g + f_bitwise + f_bitwise·byte_a0 + β·f_bitwise·byte_b0 + β²·f_bitwise·byte_and0` |
| 4–6 | 120–125 | `and_byte_1` … `and_byte_3` | 1 | as fraction 3 over byte `j` |
| 7 | 126, 127 | `generic_pad_0` | 0 | 1 |

The two literals are `constants::generic_table`'s gated key bases, `SIGN_BASE + 1 = 257` and
`AND_BASE + 1 = 1`. A sign lookup's third tuple position is the constant 0, so it adds no `β²`
term; an `and_byte` lookup's is a column, so it does (§0.4).

**The `decoder` fraction tree**, `L1[128..132]`: 2 fractions, and **six** wide.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 128, 129 | `decoder_table` | `−mult_decoder` | `table_pc + β·table_next_pc + β²·table_rs1 + β³·table_rs2 + β⁴·table_rd + β⁵·table_extra_mask + g` |
| 1 | 130, 131 | `decode_row` | 1 | `g_dec + (1 + β + β² + β³ + β⁴ + β⁵)·pc_mask + pc_mask·pc_read_value + β·pc_mask·decoded_next_pc + β²·pc_mask·decoded_rs1 + β³·pc_mask·decoded_rs2 + β⁴·pc_mask·decoded_rd + β⁵·pc_mask·decoded_mask` |

`β⁶` appears nowhere in this circuit, and `g_dec` is `g − Σ_{j<6} β^j` (§0.4, §6.1).

### 9.5 Gate list 0: the 46 enforcing gates

Relations 132–177, in list order, in §3.5's format. The frame's eleven (132–142) are §7.5's A
over five queries: five mask booleanity gates, **two** write-backs (`rs1` and `rs2` — the RAM
query is not read-only here, and there is no `load` query), and the four x0 gates. The family's
35 come from `atomics::family_spec`, its private helpers, and `gadgets::comparison`.

**A. What the row is (143–154)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
143–153 kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2

  143 kind_amoadd_boolean   W[13]    149 kind_amoand_boolean   W[19]
  144 kind_amoswap_boolean  W[14]    150 kind_amomin_boolean   W[20]
  145 kind_lr_boolean       W[15]    151 kind_amomax_boolean   W[21]
  146 kind_sc_boolean       W[16]    152 kind_amominu_boolean  W[22]
  147 kind_amoxor_boolean   W[17]    153 kind_amomaxu_boolean  W[23]
  148 kind_amoor_boolean    W[18]

────────────────────────────────────────────────────────────────────────────────────────────
154     decoded_mask_bits — the packed mask is its eleven bits          Linear, degree 1

  positional  0 = W[13] + 2·W[14] + 4·W[15] + 8·W[16] + 16·W[17] + 32·W[18] + 64·W[19]
                  + 128·W[20] + 256·W[21] + 512·W[22] + 1024·W[23] − W[12]
  named       0 = Σ_k 2^k·kind_k − decoded_mask,  k in extra_mask::atomics order

  reads as  §5.5's 146 over eleven bits, and W[12] is the fifth decoded column, not the
            sixth: this family's tuple has no imm. One-hotness is the decoder table's
            (lookup.md §10).
```

**B. Which queries a row makes, and where (155–164)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
155–158 <q>_mask_rule — a query is present exactly where its kind uses it   Quadratic, deg 2

  155 rs1_mask_rule  0 = M[6]  − M[1]·(W[13] + … + W[23])     all eleven bits
  156 rs2_mask_rule  0 = M[11] − M[1]·(every bit but W[15])   ten bits: not lr
  157 ram_mask_rule  0 = M[16] − M[1]·(W[13] + … + W[23])     all eleven
  158 rd_mask_rule   0 = M[21] − M[1]·(W[13] + … + W[23])     all eleven

  reads as  every kind reads rs1, rewrites the word and writes rd; only `lr.w` skips rs2,
            keyed on its own bit and never on is_zero(decoded_rs2), which
            `amoadd.w rd, x0, (rs1)` would also satisfy (memory-ops.md §6.1). On a padding
            row pc_mask = 0 and every mask is 0 — S14's control C8, which §9.10 refuses
            three times, once on the RAM query.

────────────────────────────────────────────────────────────────────────────────────────────
159–161 <q>_addr_rule — a present register query's index is the decoded one  Quadratic, deg 2

  159 rs1_addr_rule  0 = M[6]·M[7]   − M[6]·W[9]
  160 rs2_addr_rule  0 = M[11]·M[12] − M[11]·W[10]
  161 rd_addr_rule   0 = M[21]·M[22] − M[21]·W[11]

────────────────────────────────────────────────────────────────────────────────────────────
162     ram_addr_rule — the RAM query names the word                   Quadratic, degree 2

  positional  0 = M[16]·M[17] − 4·M[16]·W[24]
  named       0 = ram_mask·(ram_addr − 4·word_index)

────────────────────────────────────────────────────────────────────────────────────────────
163–164 <q>_value_masked — an absent operand reads 0                   Quadratic, degree 2

  163 rs1_value_masked  0 = M[9]  − M[6]·M[9]
  164 rs2_value_masked  0 = M[14] − M[11]·M[14]

  reads as  164 is what makes `lr.w`'s second operand 0 rather than free: its rs2 query is
            absent, so every arm and every comparison on that row reads a zero `src`.
```

**C. The address (165)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
165     addr_word — the address is four times a word index             Linear, degree 1

  positional  0 = M[9] − 4·W[24]       named  0 = rs1_read_value − 4·word_index

  reads as  an atomic's address is rs1 alone: the A extension has no immediate, so there is
            no wrap bit and no offset bits. §9.6's three obligations hold word_index below
            2^30, which makes this an integer equation — so a misaligned atomic has no
            witness (§9.10), and `rs1 < 2^32` is **derived** here rather than assumed, which
            is what the write-side induction needs (memory-ops.md §5.2).
```

**D. The eleven arms (166–177)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
166–167 add_wrap_boolean, add_rule — the addition             Quadratic/Linear, degrees 2, 1

  166 add_wrap_boolean  0 = W[28] − W[28]·W[28]
  167 add_rule          0 = M[19] + M[14] − W[26] − 2^32·W[28]
                        0 = old + src − sum − 2^32·add_wrap

  reads as  **ungated**, so `sum` is the true reduced sum on every live row and its 16+16
            pair sits under pc_mask. Gating either to the amoadd bit would leave `sum`
            unbounded on the other ten kinds and ram_write_value pinned by nothing on an
            add row (memory-ops.md §6.3). Both operands are below 2^32 by the comparison's
            own pairs, so one boolean wrap holds the carry and (sum, add_wrap) is unique.

────────────────────────────────────────────────────────────────────────────────────────────
168–169 f_bitwise_boolean, f_bitwise_rule — the bitwise half   Quadratic/Linear, degrees 2, 1

  168 f_bitwise_boolean  0 = W[29] − W[29]·W[29]
  169 f_bitwise_rule     0 = W[29] − W[19] − W[18] − W[17]
                         0 = f_bitwise − (kind_amoand + kind_amoor + kind_amoxor)

  reads as  the **three** bitwise kinds, not amoand alone: gating the lookups by one bit
            would leave amoor and amoxor reading free byte_and columns and writing an
            arbitrary field element into RAM. It is a column because it selects lookups,
            and then it carries the booleanity gate validate refuses a selector without.

────────────────────────────────────────────────────────────────────────────────────────────
170–171 old_bytes_rule, src_bytes_rule — both operands' bytes         Linear, degree 1

  170 old_bytes_rule  0 = M[19] − W[30] − 256·W[31] − 2^16·W[32] − 2^24·W[33]
  171 src_bytes_rule  0 = M[14] − W[34] − 256·W[35] − 2^16·W[36] − 2^24·W[37]

  reads as  ungated, like 167: the decompositions hold on every live row, and it is the key
            bounds under f_bitwise that make the bytes bytes where the table is read.

────────────────────────────────────────────────────────────────────────────────────────────
172–173 cmp_order, cmp_lt_boolean — the comparison               Quadratic, degree 2
        code  gadgets::comparison(&the_comparison()), whose equation is
              gadgets::comparison_equation(c, 32)

  positional  0 = M[19] − M[14] + 2^32·W[46] − W[47]
                  − 2^32·W[20]·W[43] + 2^32·W[20]·W[45]
                  − 2^32·W[21]·W[43] + 2^32·W[21]·W[45]
  named       0 = old − src − 2^32·sc·(old_sign − src_sign) + 2^32·lt − cmp_gap,
              sc = kind_amomin + kind_amomax
  173 cmp_lt_boolean  0 = W[46] − W[46]·W[46]

  reads as  §4's one ungated degree-2 comparison, unchanged: `sc` is the signed half, the
            signs come from U16GetSign over range-checked halfwords, and cmp_gap's own range
            pair carries the soundness. **The gadget's four parameters are asserted at
            construction** — selector, signed, lhs and rhs — because each wrong choice is a
            silent, total break of four of the eleven kinds with nothing else in the circuit
            to catch it (memory-ops.md §6.4), and `the_comparison_is_over_the_old_word_and_rs2`
            reads all four back off the artifact.

────────────────────────────────────────────────────────────────────────────────────────────
174     lo_rule — the smaller of the two                              Quadratic, degree 2

  positional  0 = W[49] − M[14] − W[46]·M[19] + W[46]·M[14]
  named       0 = lo − src − lt·(old − src)

  reads as  `lo` is the smaller under whichever ordering `lt` settled. The larger is the
            linear form old + src − lo, exact in both orderings because {lo, old + src − lo}
            is {old, src} as a set — so amomax and amomaxu need no second column.

────────────────────────────────────────────────────────────────────────────────────────────
175     ram_value_rule — the new word, all eleven arms                Quadratic, degree 2

  named  0 = ram_write_value
             − kind_lr·old − (kind_sc + kind_amoswap)·src − kind_amoadd·sum
             − kind_amoand·A − kind_amoor·(old + src − A) − kind_amoxor·(old + src − 2A)
             − (kind_amomin + kind_amominu)·lo
             − (kind_amomax + kind_amomaxu)·(old + src − lo)
         with A = Σ_j 2^(8j)·byte_and_j inlined as a linear form, 28 products in all

  reads as  the largest gate in the manifest by product count. `or` and `xor` are derived
            from the one AND accumulator by linearity, exact over the integers because no
            carry crosses a byte, and there is no OR table and no XOR table. Each arm is a
            kind bit times a column or a linear form, so the whole gate is degree 2. On a
            row with no kind bit — a padding row — every product vanishes and the gate holds
            ram_write_value to 0, which is one of the three refusals of §9.10's RAM C8.

────────────────────────────────────────────────────────────────────────────────────────────
176     rd_value_rule — the word handed back                          Quadratic, degree 2

  positional  0 = W[7] − (every kind bit but W[16])·M[19]      ten products
  named       0 = rd_selected − (Σ_{k ≠ sc} kind_k)·old

  reads as  every kind but `sc.w` hands back the word it found; `sc.w` writes its success
            code, which is always 0 (§9.2). This is the whole of the family's return value:
            rd_selected is the frame's and the x0 gadget masks it, so this gate is the only
            thing tying it to memory.

────────────────────────────────────────────────────────────────────────────────────────────
177     next_pc_rule — the next pc is the decoded fall-through         Linear, degree 1

  positional  0 = M[5] − W[8]       named  0 = pc_write_value − decoded_next_pc

  reads as  §7.5's 100; the A extension has no compressed form, so the fall-through is
            always pc + 4.
```

### 9.6 The 36 lookups

`CircuitArtifact::lookups`, in order. The frame's 10 come from the private
`memory::gap_lookups`; the comparison's 8 from `gadgets::comparison`; the rest from
`atomics::family_spec` (its private `range16`, `range32`, `byte_key_bound`, `generic` and the
inline `decode_row`). Eleven `RANGE16` obligations are selected by `pc_mask` and eight by
`f_bitwise`; four of the six generic lookups are under `f_bitwise` too.

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0–9 | `gap_hi_pc` … `gap_lo_rd` | `TIMESTAMP` (0) | each query's mask | over `pc`, `rs1`, `rs2`, `ram`, `rd` | | `< 2^19` |
| 10 | `cmp_lhs_hi_range` | `RANGE16` (1) | `M[1]` | `W[42]` | `old_hi` | `< 2^16` |
| 11 | `cmp_lhs_lo_range` | `RANGE16` | `M[1]` | `M[19] − 2^16·W[42]` | `ram_read_value − 2^16·old_hi` | `< 2^16` |
| 12 | `cmp_rhs_hi_range` | `RANGE16` | `M[1]` | `W[44]` | `src_hi` | `< 2^16` |
| 13 | `cmp_rhs_lo_range` | `RANGE16` | `M[1]` | `M[14] − 2^16·W[44]` | `rs2_read_value − 2^16·src_hi` | `< 2^16` |
| 14 | `cmp_gap_hi_range` | `RANGE16` | `M[1]` | `W[48]` | `cmp_gap_hi` | `< 2^16` |
| 15 | `cmp_gap_lo_range` | `RANGE16` | `M[1]` | `W[47] − 2^16·W[48]` | `cmp_gap − 2^16·cmp_gap_hi` | `< 2^16` |
| 16 | `word_index_hi_range` | `RANGE16` | `M[1]` | `W[25]` | `word_index_hi` | `< 2^16` |
| 17 | `word_index_lo_range` | `RANGE16` | `M[1]` | `W[24] − 2^16·W[25]` | `word_index − 2^16·word_index_hi` | `< 2^16` |
| 18 | `word_index_hi_scaled` | `RANGE16` | `M[1]` | `4·W[25]` | `4·word_index_hi` | `word_index_hi < 2^14` |
| 19 | `sum_hi_range` | `RANGE16` | `M[1]` | `W[27]` | `sum_hi` | `< 2^16` |
| 20 | `sum_lo_range` | `RANGE16` | `M[1]` | `W[26] − 2^16·W[27]` | `sum − 2^16·sum_hi` | `< 2^16` |
| 21 | `byte_a0_range` | `RANGE16` | `W[29]` | `W[30]` | `byte_a0` | `< 2^16` |
| 22 | `byte_a0_scaled` | `RANGE16` | `W[29]` | `256·W[30]` | `2^8·byte_a0` | `< 2^16`, i.e. `byte_a0 < 2^8` |
| 23–28 | `byte_a1_range` … `byte_a3_scaled` | `RANGE16` | `W[29]` | `W[31]`, `256·W[31]`, `W[32]`, `256·W[32]`, `W[33]`, `256·W[33]` | the same pair per byte | `byte_a_j < 2^8` |
| 29 | `cmp_lhs_get_sign` | `GENERIC` (2) | `M[1]` | `(W[42] + 256, W[43], 0)` | `(old_hi + SIGN_BASE, old_sign, 0)` | the gated tuple `(old_hi + 257, old_sign, 0)` is a row of `S[6..9]` |
| 30 | `cmp_rhs_get_sign` | `GENERIC` | `M[1]` | `(W[44] + 256, W[45], 0)` | `(src_hi + SIGN_BASE, src_sign, 0)` | as 29 |
| 31 | `and_byte_0` | `GENERIC` | `W[29]` | `(W[30], W[34], W[38])` | `(byte_a0 + AND_BASE, byte_b0, byte_and0)` | the gated tuple `(byte_a0 + 1, byte_b0, byte_and0)` is a row of `S[6..9]` |
| 32–34 | `and_byte_1` … `and_byte_3` | `GENERIC` | `W[29]` | `(W[31], W[35], W[39])`, `(W[32], W[36], W[40])`, `(W[33], W[37], W[41])` | the same per byte | as 31 |
| 35 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[8], W[9], W[10], W[11], W[12])` | `(pc_read_value, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_mask)` | a row of `S[0..6]` — **six** wide |

Read in pairs: each `gap_hi`/`gap_lo` puts a read strictly before its own write, and each
`_hi_range`/`_lo_range` bounds `ram_read_value`, `rs2_read_value`, `cmp_gap`, `word_index` and
`sum` below `2^32`. **The comparison's two operand pairs are under `pc_mask`, so `old` and `src`
are bounded on every live row, whatever the kind** — which is what the whole write-side chain of
`memory-ops.md` §6.5 rests on: `sum` by its own pair, `A`, `or` and `xor` by the AND table's
domain, `lo` and `old + src − lo` by being `old` and `src` in some order. There is no direct
range check on `ram_write_value` anywhere, and none of the eight arms needs one.

**The four byte keys carry S18's pair, and this family inherits S18's hole with the table.**
With `byte_a0` unbounded the gated key `65_824` is `ShiftPowers`' row for `s = 31`,
`(65_824, 2^31, 1)`, so `byte_b0 = 2^31` and `byte_and0 = 1` satisfy the lookup, and an
`amoand.w` of `65_823` with `2^31` proves `and = 1` where the answer is 0 — and `or` and `xor`,
derived from the same accumulator, are wrong with it. The pair under `f_bitwise` is what refuses
it, `lookup::check_copowers` takes all four keys with that selector, and
`a_byte_key_outside_the_and_table_is_refused` is the attack as a row
(`shift-bitwise.md` §3.3; `memory-ops.md` §6.5).

The channels, `atomics::channels()`, in output order:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[50]` | 10 | 16 |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[51]` | **19** | **32** |
| 6, 7 | `GENERIC` | 2 | `S[6..9]` | `W[52]` | 6 | 8 |
| 8, 9 | `DECODER` | 3 | `S[0..6]` | `W[53]` | 1 | 2 |

`artifact` asserts the four obligation counts. The `RANGE16` row is why this circuit is 26 gate
lists deep at `n = 20`: 19 obligations plus one table fraction is 20 leaves, which pads to 32
and takes five row-wise levels instead of four. Twelve of the 32 leaves are pads.

### 9.7 Inner layers `L2`–`L6`: the row-wise reduction

The conventions are §3.7's. There are **five** row-wise reduction lists here.

**`L2`, gate list 1, 66 columns, relations 178–243.** `read_2_0` … `read_2_3` and
`write_2_0` … `write_2_3` pair the eight leaves a side; `timestamp_2_0` … `timestamp_2_7` pair
the sixteen timestamp fractions — `timestamp_2_0` = `timestamp_table + gap_hi_pc`, then the five
`gap_lo`/`gap_hi` seams in query order, `timestamp_2_5` = `gap_lo_rd + timestamp_pad_0`, and two
pad pairs. The rest:

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 24, 25 | 202, 203 | `range16_2_0` | `range16_table + cmp_lhs_hi_range` |
| 26, 27 | 204, 205 | `range16_2_1` | `cmp_lhs_lo_range + cmp_rhs_hi_range` |
| 28, 29 | 206, 207 | `range16_2_2` | `cmp_rhs_lo_range + cmp_gap_hi_range` |
| 30, 31 | 208, 209 | `range16_2_3` | `cmp_gap_lo_range + word_index_hi_range` |
| 32, 33 | 210, 211 | `range16_2_4` | `word_index_lo_range + word_index_hi_scaled` |
| 34, 35 | 212, 213 | `range16_2_5` | `sum_hi_range + sum_lo_range` |
| 36, 37 | 214, 215 | `range16_2_6` | `byte_a0_range + byte_a0_scaled` |
| 38–43 | 216–221 | `range16_2_7` … `range16_2_9` | the remaining three byte pairs |
| 44–55 | 222–233 | `range16_2_10` … `range16_2_15` | the twelve pads in pairs |
| 56, 57 | 234, 235 | `generic_2_0` | `generic_table + cmp_lhs_get_sign` |
| 58, 59 | 236, 237 | `generic_2_1` | `cmp_rhs_get_sign + and_byte_0` |
| 60, 61 | 238, 239 | `generic_2_2` | `and_byte_1 + and_byte_2` |
| 62, 63 | 240, 241 | `generic_2_3` | `and_byte_3 + generic_pad_0` |
| 64, 65 | 242, 243 | `decoder_2_0` | `decoder_table + decode_row` |

`range16_2_6` through `range16_2_9` are the one place where a 16+16 pair lands in one node: a
byte key's direct and scaled halves are adjacent in artifact order, so each byte's pair is added
as a single fraction node. The tree does not know that, and nothing depends on it.

**`L3`, gate list 2, 34 columns, relations 244–277.** `read_3_0`, `read_3_1`, `write_3_0`,
`write_3_1`; `timestamp_3_0` … `timestamp_3_3`; `range16_3_0` … `range16_3_7`;
`generic_3_0` and `generic_3_1`, each the sum of two `L2` generic nodes; `decoder_3_0`, a copy.

**`L4`, gate list 3, 18 columns, relations 278–295.** `read_4_0`, `write_4_0`;
`timestamp_4_0`, `timestamp_4_1`; `range16_4_0` … `range16_4_3`;
`generic_4_0` = `generic_3_0 + generic_3_1`; `decoder_4_0`, a copy.

**`L5`, gate list 4, 12 columns, relations 296–307.** `read_5_0` and `write_5_0`, copies;
`timestamp_5_0` = `timestamp_4_0 + timestamp_4_1`; `range16_5_0` and `range16_5_1`;
`generic_5_0` and `decoder_5_0`, copies.

**`L6`, gate list 5, 10 columns, relations 308–317.** `read_6_0`, `write_6_0`,
`timestamp_6_0`, `generic_6_0` and `decoder_6_0` are copies; `range16_6_0` =
`range16_5_0 + range16_5_1` is the one real node of the list.

### 9.8 The halving layers and the outputs

Gate list `k`, for `6 ≤ k ≤ n + 5`, halves layer `k` into layer `k + 1`, which has `n + 5 − k`
variables. Its ten gates, relation `r = 318 + 10(k − 6)`, are §5.8's, node for node. In the last
list, `k = n + 5`, the ten nodes are `read_root`, `write_root`, `timestamp_num_root`,
`timestamp_den_root`, `range16_num_root`, `range16_den_root`, `generic_num_root`,
`generic_den_root`, `decoder_num_root` and `decoder_den_root`. At `n = 20` the halving lists are
6 to 25, `L7` has 19 variables and `L26` none, and the roots are relations 508–517. At `n = 22`
they are 6 to 27, the top is `L28`, and the roots are 528–537.

**The outputs**, in output-map order, are §5.8's with this family's position: outputs 0 and 1 the
memory roots, read at `verify_shard` step 10 against `memory_roots[p]` for `p` the position of
`(6, shard_index)` in `verifier_core::statement_shards` — last of the seven shards in S19's
statement; 2–9 the four channels' `num`/`den` pairs, read at step 9, each failure
`Lookup { channel }` for channel 0, 1, 2 and 3 in turn.

### 9.9 Witness rows

The table shows eight of the 15 live rows of `guests/mem`'s `ATOMICS` shard, as
`prover::family_fill(6)` writes them, plus the first padding row after them.
`crates/checker/tests/mem_fill.rs`' `the_atomics_fill_satisfies_every_gate_and_every_table`
holds exactly these columns to every gate, every range obligation and both table channels in
ordinary CI. The circuit is also held to a hand-built catalogue of its own:
`crates/checker/tests/atomics.rs`' `honest_rows`, **25 live rows and the padding row** — every
one of the eleven kinds, a sum past `2^32`, an `x0` destination, the sign boundary in both
operand orders for all four min/max kinds, the bitwise trio over a second pattern, a row at word
zero and a row at the top of the addressable window. §9.10's forgeries all start from that
catalogue.

Every live row below names the word at `0x20020` through `x13`. `A` `amoadd.w` where the sum
carries: `0xffffffff + 1` is 0 with `add_wrap = 1`. `B` `amoswap.w`. `C` `amoand.w` and `D`
`amoxor.w`, over the same operand pair, the two bitwise rows. `E` `amomin.w` and `F`
`amominu.w`, over `0x7fffffff` and `0x80000000` — the one operand pair where the signed and the
unsigned orderings disagree, and they answer differently. `G` `lr.w`, which makes no `rs2`
query. `H` `sc.w`, which stores `rs2` and returns 0. `P` the first padding row. Every cell not
listed is 0 on all nine; `S[0..6]` hold `MINUS_ONE` at these rows and `S[6..9]` the packed
table's rows 0 to 8, and both are omitted.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 192 | 183 | 219 | 234 | 244 | 251 | 268 | 273 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[4]` `pc_read_value` | `0x102f8` | `0x102d4` | `0x10364` | `0x103a0` | `0x103c8` | `0x103e4` | `0x10428` | `0x1043c` | 0 |
| `M[5]` `pc_write_value` | `0x102fc` | `0x102d8` | `0x10368` | `0x103a4` | `0x103cc` | `0x103e8` | `0x1042c` | `0x10440` | 0 |
| `M[7]` `rs1_addr` | 13 | 13 | 13 | 13 | 13 | 13 | 13 | 13 | 0 |
| `M[9]` `rs1_read_value` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | 0 |
| `M[11]` `rs2_mask` | 1 | 1 | 1 | 1 | 1 | 1 | **0** | 1 | 0 |
| `M[12]` `rs2_addr` | 6 | 6 | 6 | 6 | 6 | 6 | 0 | 7 | 0 |
| `M[14]` `rs2_read_value` | 1 | `0x0f0f0f0f` | `0x0ff0f00f` | `0x0ff0f00f` | `0x80000000` | `0x80000000` | 0 | `0x33334444` | 0 |
| `M[16]` `ram_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[17]` `ram_addr` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | 0 |
| `M[19]` `ram_read_value` (`old`) | `0xffffffff` | `0x5a5a5a5a` | `0xf0f00ff0` | `0xf0f00ff0` | `0x7fffffff` | `0x7fffffff` | `0x11112222` | `0x11112222` | 0 |
| `M[20]` `ram_write_value` | 0 | `0x0f0f0f0f` | `0x00f00000` | `0xff00ffff` | `0x80000000` | `0x7fffffff` | `0x11112222` | `0x33334444` | 0 |
| `M[21]` `rd_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[22]` `rd_addr` | 7 | 7 | 7 | 7 | 7 | 7 | 6 | 28 | 0 |
| `M[25]` `rd_write_value` | `0xffffffff` | `0x5a5a5a5a` | `0xf0f00ff0` | `0xf0f00ff0` | `0x7fffffff` | `0x7fffffff` | `0x11112222` | **0** | 0 |
| `W[0..5]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[7]` `rd_selected` | `0xffffffff` | `0x5a5a5a5a` | `0xf0f00ff0` | `0xf0f00ff0` | `0x7fffffff` | `0x7fffffff` | `0x11112222` | 0 | 0 |
| `W[12]` `decoded_mask` | 1 | 2 | 64 | 16 | 128 | 512 | 4 | 8 | 0 |
| `W[13..24]` the kind bit set | `amoadd` | `amoswap` | `amoand` | `amoxor` | `amomin` | `amominu` | `lr` | `sc` | none |
| `W[24]` `word_index` | `0x8008` | `0x8008` | `0x8008` | `0x8008` | `0x8008` | `0x8008` | `0x8008` | `0x8008` | 0 |
| `W[26]` `sum` | 0 | `0x69696969` | `0x00e0ffff` | `0x00e0ffff` | `0xffffffff` | `0xffffffff` | `0x11112222` | `0x44446666` | 0 |
| `W[28]` `add_wrap` | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| `W[29]` `f_bitwise` | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| `W[30..34]` `byte_a0..3` | `ff ff ff ff` | `5a 5a 5a 5a` | `f0 0f f0 f0` | `f0 0f f0 f0` | `ff ff ff 7f` | `ff ff ff 7f` | `22 22 11 11` | `22 22 11 11` | 0 |
| `W[34..38]` `byte_b0..3` | `01 00 00 00` | `0f 0f 0f 0f` | `0f f0 f0 0f` | `0f f0 f0 0f` | `00 00 00 80` | `00 00 00 80` | `00 00 00 00` | `44 44 33 33` | 0 |
| `W[38..42]` `byte_and0..3` | `01 00 00 00` | `0a 0a 0a 0a` | `00 00 f0 00` | `00 00 f0 00` | `00 00 00 00` | `00 00 00 00` | `00 00 00 00` | `00 00 11 11` | 0 |
| `W[42]` `old_hi` | `0xffff` | `0x5a5a` | `0xf0f0` | `0xf0f0` | `0x7fff` | `0x7fff` | `0x1111` | `0x1111` | 0 |
| `W[43]` `old_sign` | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| `W[44]` `src_hi` | 0 | `0x0f0f` | `0x0ff0` | `0x0ff0` | `0x8000` | `0x8000` | 0 | `0x3333` | 0 |
| `W[45]` `src_sign` | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 0 |
| `W[46]` `lt` | 0 | 0 | 0 | 0 | **0** | **1** | 0 | 1 | 0 |
| `W[47]` `cmp_gap` | `0xfffffffe` | `0x4b4b4b4b` | `0xe0ff1fe1` | `0xe0ff1fe1` | `0xffffffff` | `0xffffffff` | `0x11112222` | `0xddddddde` | 0 |
| `W[49]` `lo` | 1 | `0x0f0f0f0f` | `0x0ff0f00f` | `0x0ff0f00f` | `0x80000000` | `0x7fffffff` | 0 | `0x11112222` | 0 |

`W[25]` `word_index_hi`, `W[27]` `sum_hi` and `W[48]` `cmp_gap_hi` are the high halfwords of the
columns above them and are omitted, as are the four multiplicity columns.

`E` and `F` are the whole of acceptance 5 in two rows: the same `old` and `src`, the same
`cmp_gap` of `0xffffffff`, and `lt` differing because `sc` is 1 on `E` and 0 on `F`, so the
signed row calls `0x80000000` the smaller and the unsigned row calls `0x7fffffff` the smaller.
`C` and `D` share every byte column and differ only in which arm of `ram_value_rule` is live:
`A = 0x00f00000` is the AND, and `xor` is `old + src − 2A = 0xff00ffff`. `A`'s sum carries, so
`add_wrap` is 1 and the stored word is 0. `G` is the one row with no `rs2` query, and its `src`
reads 0 through `rs2_value_masked`, which is why its comparison compares `old` against 0 and its
`lo` is 0. `H` is the `sc.w`: it stores `rs2` and its `rd_selected` is 0, the one kind where the
returned word is not `old`. `sum`, `cmp_gap`, `lo` and the twelve byte columns are computed on
**every** live row, bitwise or not, because `add_rule`, `old_bytes_rule`, `src_bytes_rule`,
`cmp_order` and `lo_rule` are all ungated — the same shape as §4's comparison and §6's `abs_d`.

### 9.10 What fixes each cell

The per-cell accounting is `crates/checker/tests/atomics.rs`' own, and it is a committed one:
`each_gate_is_the_one_that_refuses_its_row` carries 24 tampers, each an edit to a named honest
row beside **the exact set** of relations that refuse it, asserted equal. It ends with a
completeness assertion: of the circuit's 46 enforcing gates the frame's eleven and every
`*_boolean` are set aside, and each of the remaining **21** must be named by some tamper above.
`every_booleanity_gate_refuses_a_value_of_two` covers the fourteen booleans this family commits
— the eleven kind bits, the carry, the bitwise flag and the ordering bit — and seven further
tests take one question each.

| cell moved | on the row | refused by, exactly |
| --- | --- | --- |
| `decoded_mask` → `amoswap`'s | `amoadd` | `decoded_mask_bits` |
| the `rs1` query dropped | `amoswap at word zero`, whose `rs1` reads 0 | `rs1_mask_rule` |
| an `rs2` query added | `lr.w` | `rs2_mask_rule` |
| the `ram` query dropped | `amoswap at word zero` | `ram_mask_rule` |
| the `rd` query dropped | `amoswap at word zero` | `rd_mask_rule` |
| `rs1_addr` `+ 1` | `amoswap` | `rs1_addr_rule` |
| `rs2_addr` `+ 1` | `amoswap` | `rs2_addr_rule` |
| `rd_addr` → 5 | `amoswap` | `rd_addr_rule` |
| `ram_addr` `+ 4` | `amoswap` | `ram_addr_rule` |
| `rs1_read_value` → 4, `word_index` → 1 | padding | `rs1_value_masked` |
| `rs2_read_value` → 4, with `byte_b0`, `sum`, `cmp_gap` and `lo` moved to match | `lr.w` | `rs2_value_masked` |
| `rs1_read_value` `+ 4`, `word_index` left alone | `amoswap` | `addr_word` |
| `sum` `+ 1`, carried into the stored word | `amoadd` | `add_rule` |
| `f_bitwise` → 0 | `amoand` | `f_bitwise_rule` |
| `byte_a0` `+ 1` | `amoand` | `old_bytes_rule` |
| `byte_b0` `+ 1` | `amoand` | `src_bytes_rule` |
| `lt` → 1 with `lo` moved to match | `amoadd`, whose value rule does not read `lo` | `cmp_order` |
| `lo` → the larger, with the stored word moved to match | `amomin` | `lo_rule` |
| `ram_write_value` → the AND accumulator | `amoor` | `ram_value_rule` |
| `rd_selected` → the word it stored | `amoswap` | `rd_value_rule` |
| `pc_write_value` `+ 4` | `amoadd` | `next_pc_rule` |
| a `ram` query storing 42 into a stack word | padding | `ram_mask_rule`, `ram_addr_rule`, `ram_value_rule` |
| an `rd` query zeroing `x10` | padding | `rd_mask_rule`, `rd_addr_rule` |
| the same, dressed with `decoded_rd = 10` and a zero mask | padding | `rd_mask_rule` |

The seven further tests, each isolating one thing the accounting above cannot show cell by cell:

- **`the_comparison_is_over_the_old_word_and_rs2`** — the gadget's four parameters read back off
  the artifact, because they are **not derivable from anything else in it**: `signed` widened to
  all four min/max kinds makes `amominu` order signed; `lhs` and `rhs` swapped turns every
  `amomin` into a max; a narrowed selector drops both operands' 32-bit bounds on the other seven
  kinds (`memory-ops.md` §6.4).
- **`the_kind_bits_are_the_extra_mask_constants`** — each of the eleven `Instr` variants held to
  the bit its arm uses. A transposition of `amoor` and `amoand` would be silent: the decoded
  table is built from the same constants, so both sides would agree on the number and the machine
  proved would be one where `amoor.w` computes AND.
- **`the_min_and_max_kinds_disagree_across_the_sign_boundary`** — each of the four answers over
  `(0x7fffffff, 0x80000000)` proved, and each row claiming the other kind's answer refused. The
  refusal is always the gap's range pair: `lo` is free, so a forged answer fixes `lt` through
  `lo_rule` and `lt` fixes the gap through the one comparison equation, and swapping the ordering
  moves the gap to `2^33 − 1` or to `−1`, neither of which is a word.
- **`a_byte_key_outside_the_and_table_is_refused`** — §9.6's key bound as a row, with both halves
  of `byte_a0`'s pair firing at 65,823.
- **`a_misaligned_atomic_is_unprovable`** — the exact field witness `word_index = rs1·4⁻¹`,
  which every gate accepts and `word_index_lo_range` alone refuses, as §7.10's is for `MEM_WORD`.
- **`an_amo_whose_rd_is_not_the_old_word_is_refused`** and **`sc_w_always_succeeds`** — the
  return value, which `rd_value_rule` alone ties to memory, and the one conformance deviation
  stated as a property of the proved statement: a row claiming a nonzero success code is refused
  by `rd_value_rule`, and one leaving the word alone by `ram_value_rule`.

On a padding row `pc_mask = 0`, every frame mask is 0, every leaf is 1 and every obligation under
`pc_mask` is vacuous. **`f_bitwise` is a free boolean there**, so a padding row may look the byte
table up four times; it consumes table multiplicities, which the honest prover's recount covers,
and changes nothing, the RAM and `rd` queries being absent. With every kind bit 0 the gates hold
`ram_write_value`, `rd_selected` and `pc_write_value − decoded_next_pc` to 0, tie
`old + src − sum − 2^32·add_wrap` to 0 over a zero `old` and a zero `src`, and leave `lt` and
`cmp_gap` free together — `cmp_order` holds on every row, but `cmp_gap`'s range pair is off where
`pc_mask = 0`, so `lt = 1` with `cmp_gap = 2^32` breaks nothing there, exactly as in §4. The
honest fill writes 0 everywhere.

---

## 10. `INIT_TEARDOWN` — family 7

### 10.1 Header

`family_circuit(7, n)` is `memory::image_window_artifact(n)` with no channels. RAM window 0,
the image window: exactly one shard, window id 0. Spec: `memory.md` §3. Fill:
`prover::family_fill(7)`, the private `fill::window`, which is
`trace::build_init_teardown_columns(log, image, 0, h)`. Three committed columns, two virtual
tables, two leaves, no enforcing gate, no lookup, two outputs. At `n = 16`, S16's statement:
17 gate lists, top `L17`, 34 inner columns and relations.

### 10.2 Columns

| address | name | Rust | descriptive name | row `y` holds | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `teardown_ts` | `PolyAddress::Memory(0)` | Last write time | the timestamp of the last write to the word at `4y`; 0 if the word is untouched or `y < 2^14` | leaf `teardown` |
| `M[1]` | `teardown_value` | `PolyAddress::Memory(1)` | Final word | the last value written; the image word if untouched; 0 if `y < 2^14` | leaf `teardown` |
| `S[0]` | `init_value` | `PolyAddress::Setup(0)` | Image word | `image.initial_word(4y)`: `program::image_init_column(image, h)` | leaf `init` |
| `V[row]` | `row` | `VirtualKind::RowIndex`, wire tag 0 | Row index | `y` | both leaves |
| `V[ram_live]` | `ram_live` | `VirtualKind::RamLive`, wire tag 1 | Row is RAM | 1 if `y ≥ 2^14`, else 0 | both leaves, as their mask |

`M[0]` and `M[1]` are committed in `PublicInputs::memory_commitments`, whose `INIT_TEARDOWN`
group G8 absorbs first. `S[0]` is identity's `cm(image column)` and is opened against it
(`shard-proof.md` §5.2). Rows `y < 2^14` are the addresses below `RAM_ORIGIN`, which
`V[ram_live]` masks off.

### 10.3 Leaves and layers

| `L1` | relation | node | positional | named |
| --- | --- | --- | --- | --- |
| 0 | 0 | `teardown` (read side) | `1 + WC·V[ram_live] − V[ram_live] + α_addr·V[row]·V[ram_live] ×4 + α_ts·M[0]·V[ram_live] + α_val·M[1]·V[ram_live]` | `ram_live·T(RAM, 4·row, teardown_ts, teardown_value) + 1 − ram_live` |
| 1 | 1 | `init` (write side) | `1 + WC·V[ram_live] − V[ram_live] + α_addr·V[row]·V[ram_live] ×4 + α_val·S[0]·V[ram_live]` | `ram_live·T(RAM, 4·row, 0, init_value) + 1 − ram_live` |

Here `WC = γ_M + 2`, the window constant at `w = 0`. Both leaves are `Quadratic`; code: the
private `memory::leaf` over `window_tuple`. `check_memory` admits `V[ram_live]` as a mask
because it is 0 or 1 on every row by construction.

Halving list `k`, for `1 ≤ k ≤ n`, writes `L{k+1}` (`n − k` variables):

| `L{k+1}` | relation | node | shape |
| --- | --- | --- | --- |
| 0 | `2k` | `read_{k+1}_0` | `TreeProduct { L{k}[0] }` |
| 1 | `2k + 1` | `write_{k+1}_0` | `TreeProduct { L{k}[1] }` |

In the last list, `k = n`, the two nodes are `read_root` and `write_root`.

| output | address, `n = 16` | node | value | verifier |
| --- | --- | --- | --- | --- |
| 0 | `L{17}[0]` | `read_root` | the product of every row's teardown leaf | step 10 |
| 1 | `L{17}[1]` | `write_root` | the product of every row's init leaf | step 10 |

### 10.4 Rows

A window shard has no padding: every row is an address.

| row | `teardown_ts` | `teardown_value` | `init_value` | leaves |
| --- | --- | --- | --- | --- |
| `y < 2^14`, below `RAM_ORIGIN` | 0 | 0 | 0 | both 1 |
| a word no cycle touched | 0 | the image word `v` | `v` | both `T(RAM, 4y, 0, v)`: they cancel |
| a word some cycle touched, by a read or a write (a read writes back what it read) | the last query's write timestamp `t` | the value it wrote, `v'` (`v` itself for a word only read) | the image word `v` | `T(RAM, 4y, t, v')` read against `T(RAM, 4y, 0, v)` written |

Nothing in this circuit checks a row alone. On rows `y ≥ 2^14` both `M` columns are fixed by
the memory argument alone. On rows `y < 2^14` every leaf term but the constant 1 carries
`V[ram_live] = 0`, so `M[0]` and `M[1]` there reach no leaf, gate or output, and nothing fixes
them; the honest fill writes 0. `S[0]` is fixed on every row by the opening against identity.

---

## 11. `ZERO_WINDOWS` — family 8

### 11.1 Header

`family_circuit(8, n)` is `memory::zero_window_artifact(n)` with no channels. One shard per RAM
window above 0 that the execution touches, `trace::init_windows(log, h)`; shard `i` is window
`windows[i]`, and `WC` is `γ_M + 2 + α_addr·4h·windows[i]`. Spec: `memory.md` §3. Fill:
`fill::window`, `build_init_teardown_columns(log, image, w, h)`. Two committed columns, one
virtual table, two unmasked leaves, no enforcing gate, no lookup, two outputs. S16's statement
has no shard of this family.

### 11.2 Columns

| address | name | Rust | descriptive name | row `y` holds | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `teardown_ts` | `PolyAddress::Memory(0)` | Last write time | the last write's timestamp to the word at `4h·w + 4y`, or 0 | leaf `teardown` |
| `M[1]` | `teardown_value` | `PolyAddress::Memory(1)` | Final word | the last value written, or 0 | leaf `teardown` |
| `V[row]` | `row` | `VirtualKind::RowIndex`, wire tag 0 | Row index | `y` | both leaves |

### 11.3 Leaves and layers

| `L1` | relation | node | positional | named |
| --- | --- | --- | --- | --- |
| 0 | 0 | `teardown` (read side) | `α_addr·V[row] ×4 + α_ts·M[0] + α_val·M[1] + WC` | `T(RAM, 4h·w + 4·row, teardown_ts, teardown_value)` |
| 1 | 1 | `init` (write side) | `α_addr·V[row] ×4 + WC` | `T(RAM, 4h·w + 4·row, 0, 0)` |

Both are `Linear` and carry no mask: every row of a window above 0 is a RAM word, since
`4h ≥ RAM_ORIGIN` at every window height a `VmConfig` may carry. That is the menu's `2^16` and
up, and not the menu as a whole: `verifier_core::window_height` requires
`4h ≥ PUBLIC_OUTPUT_ORIGIN + PUBLIC_WINDOW_BYTES` = `0x10000`, so neither `2^8` nor S-STREAM's
`2^12` is a window height, whatever else they are heights for (§26 observation 1). The halving
lists and outputs are §10.3's, with the same names, relation numbers and addresses.

### 11.4 Rows

| row | `teardown_ts` | `teardown_value` | leaves |
| --- | --- | --- | --- |
| a word no cycle touched | 0 | 0 | both `T(RAM, 4h·w + 4y, 0, 0)`: they cancel |
| a word some cycle touched, by a read or a write (a read writes back what it read) | the last query's write timestamp | the value it wrote (0 for a word only read) | the final tuple read against the zero tuple written |

---

## 12. `KECCAK_F` — family 9

| | |
| --- | --- |
| id, constant | 9, `constants::family::KECCAK_F` |
| constructor | `constraints::keccak::artifact(n)` |
| channels | `keccak::channels()`: **`RANGE16`** and **`XOR8`**, in that order |
| fill | the private `prover::fill::keccak_f` |
| normative spec | `docs/spec/delegation.md` §6 |
| committed | 208 `M`, 1,556 `W`, 0 `S` — 1,764 |
| virtual | 4: `V[range16]`, `V[xor8_a]`, `V[xor8_b]`, `V[xor8_out]` |
| obligations | 1,230: **210** on `RANGE16`, **1,020** on `XOR8` |
| enforcing gates | 385, all on gate list 0 |
| outputs | 6 |
| at `n = 18` | depth 29 (11 row-wise + 18 halving), 5,490 inner columns, 5,875 relations, 1,900,468 wire bytes, 381,100 proof bytes (derived, §1.2) |

### 12.1 What one row is, and the height

**One row is one Keccak round**, and a whole keccak-f[1600] permutation is **24
consecutive invocations** glued by the frame being ordinary RAM — the same
decomposition `EC_ADD` makes with three (§20). `docs/spec/delegation.md` §6.0 is
the accounting of why; the short form is that S21's row was a whole permutation at
354,762 inner columns, which forced `2^8`, 256 permutations a shard and 46,406
proof bytes a permutation, and five such shards were 97% of a measured
mini-block's proof.

`DEFAULT_HEIGHTS[KECCAK_F]` is `2^18`, and **16 is the floor while 18 is a
choice above it**: `family_circuit` returns `None` below 16 variables, because
`RANGE16`'s table needs 16 variables and so does `XOR8`'s; Mercury's even
variable count is what makes 16 rather than 17 the first usable height. But
`2^16` stays legal, `family_circuit(KECCAK_F, n)` being `Some`
for `16 ≤ n ≤ 30`, and every gate and obligation below is the same at both, the
halving phase alone differing. Both tables are 65,536 rows at every height, so
at `2^18` each **tiles** four times, exactly as `V[range16]` already does at an
execution family's `2^20`: the closed forms are multilinear and agree with the
table on the whole cube, so they are the tiled table's own extension, and a
duplicate table row carries multiplicity 0 and contributes the neutral
`(0, T + g)` (`docs/spec/lookup.md` §14). `HEIGHT_MENU` still opens with `2^8`
— for `POSEIDON2` and `FR_ARITH`, not for this family any more, nor since S26e
for `SHA256_COMP`.

**What the extra menu entry buys is fewer, fatter shards.** A delegation
shard's cost is its **height and not its occupancy**, and proof bytes a shard
barely move with height — 381,100 against `2^16`'s 373,276, the sumcheck rounds
growing logarithmically where the rows grow fourfold — so four times the shard
holds four times the permutations, 10,922 against 2,730, for **34.9** proof
bytes a permutation against 137. The price is **~60 GB** a shard against
`2^16`'s ~15 GB: 46.05 GB of forward pass (5,490 inner columns at 262,144 rows
and 32 bytes), 2.23 GB of committed base and 11.27 GB of transition 0's first
bind, 59.56 GB in all. That makes this the **peak-setting delegation family of
a block**, ahead of `EC_ADD`'s 20.5 GB at `2^16` (§20.1).

**It buys the mini-block nothing**: its 1,080 permutations were one shard at
`2^16` and are one 9.9%-occupied shard now. It is aimed at the stateless full
block, where `docs/handoff/S-BATCH-miniblock-gate.md` §11's 45,000–103,000
permutations — 16,000–37,000 trie nodes at 2.786 each — fall from 17–38
keccak shards to **5–10**, and from 6.3–14.2 MB of keccak proof to 1.9–3.8 MB.

**This circuit is flat.** Every relation is an obligation or a degree-≤2 enforcing
gate over base columns; nothing above gate list 0 is anything but the two memory
product trees, the two channels' fraction trees and the halving phase. That is
why §12.7 is eleven lines and not 168.

**There is no bit in it** but the 24 round selectors and `live`. The committed unit
is a **byte**, and every Boolean operation of the round is one `XOR8` obligation;
`AND`, `ANDN` and a top-bit mask are then *linear forms* over the result
(`docs/spec/lookup.md` §14).

### 12.2 Row kinds

There is one kind and a padding row: this family is invoked, not decoded, so there
is no instruction word, no pc, no `family_extra_mask` bit and no decoded table.

| row | `live` | what the fill writes | tuples |
| --- | --- | --- | --- |
| an **invocation** | 1 | the requesting cycle, the frame base, the 51 words read and written, the round selector, the round constant's four bytes, the round's nine byte-wide stages, and two `RANGE16` chunks a frame read | 52 read tuples and 52 write tuples: the 51 frame words at `(RAM, base + 4j)`, and the anchor pair at `(DELEGATION_KECCAK_F, base)` |
| **padding** | 0 | zeros in every column | each leaf is the literal 1; each obligation's gated tuple is the all-zero one, which is a real entry of both tables |

**Not provable**: a round word at or above 24, which has no one-hot selector —
`emulator::keccak_frame` refuses it rather than answering, so no honest trace
contains one.

### 12.3 The base layer

**`M`, 208 columns.** `constraints::delegation`'s shared layout over 51 frame
words, so `docs/spec/delegation.md` §4 and §5 are normative for all of it.

| `PolyAddress` | name | Rust | what the fill writes | read by |
| --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `keccak::CYCLE` | the requesting cycle | every leaf's timestamp, every gap obligation |
| `M[1]` | `live` | `keccak::LIVE` | 1 on an invocation | every leaf's mask, every obligation's selector, `live_boolean`, `addr_w{j}`, `base_aligned`, `base_in_window`, `one_round_a_live_row`, `rho_pi_l{i}_b{j}` |
| `M[2]` | `base` | `keccak::BASE` | the frame base `a0` carried | `addr_w{j}`, `base_aligned`, `base_in_window`, the anchor's two leaves |
| `M[3]` | `anchor_value` | `keccak::ANCHOR_VALUE` | 0 | `read_anchor` |
| `M[4 + 4j + f]` | `w{j}_{addr,read_ts,read_value,write_value}` | `keccak::word(j, f)` | word `j`'s address, the timestamp of the write its read consumed, its value before the round and after it | `read_w{j}`, `write_w{j}`, `addr_w{j}`, `gap{j}_*`, and — for `j = 0` — `round_rule` and `writes_back_w0`, or — for a state word — `input_w{j}` and `output_w{j}` |

**`W`, 1,556 columns**, in layout order. Every byte column holds an integer in
`[0, 256)`, and what bounds it is the `XOR8` obligation that reads it: membership
of a three-wide tuple bounds each position individually.

| `PolyAddress` | name | Rust | what the fill writes | read by |
| --- | --- | --- | --- | --- |
| `W[2j + c]`, `j < 51`, `c < 2` | `gap{j}_c{c}` | `keccak::gap_chunk(j, c)` | chunk `c + 1` of `4·cycle − read_ts − 1` | `gap{j}_c{c}_range`, `gap{j}_top_scaled` (`c = 1`), `gap{j}_lo_range` |
| `W[102]`, `W[103]` | `base_low`, `base_low_hi` | `keccak::base_low()`, `base_low_hi()` | `(base − RAM_ORIGIN)/4` and its high halfword | `base_aligned`, `base_low_*` |
| `W[104]`, `W[105]` | `base_room`, `base_room_hi` | `keccak::base_room()`, `base_room_hi()` | `2^31 − 204 − base` and its high halfword | `base_in_window`, `base_room_*` |
| `W[106 + r]`, `r < 24` | `round_sel{r}` | `keccak::round_sel(r)` | 1 on the row's own round | `round{r}_boolean`, `round_rule`, `one_round_a_live_row`, `rc{t}_rule` |
| `W[130 + t]`, `t < 4` | `rc_b{b}`, `b` = `IOTA_BYTES[t]` | `keccak::rc(t)` | byte `b` of `ROUND_CONSTANTS[round]` | `rc{t}_rule`, `iota_out_b{b}_xor` |
| `W[134 + 8i + b]` | `state_in_l{i}_b{b}` | `keccak::state_in(i, b)` | byte `b` of input lane `i` | `input_w{j}`, `parity_x{x}_b{b}_s{s}_xor`, `theta_a_l{i}_b{b}_xor` |
| `W[334 + 4(8x + b) + s]` | `parity_x{x}_b{b}_s{s}` | `keccak::parity(x, b, s)` | `s + 2` lanes of column `x` folded; `s = 3` is `C[x]` | `parity_*_xor`, and at `s = 3` also `c_mask_*_xor` and `theta_d_*_xor` |
| `W[494 + 8x + b]` | `c_mask_x{x}_b{b}` | `keccak::c_mask(x, b)` | `C[x]`'s byte `b` XOR `0x80` | `c_mask_*_xor`, `theta_d_*_xor` |
| `W[534 + 8x + b]` | `theta_d_x{x}_b{b}` | `keccak::theta_d(x, b)` | `D[x]`'s byte `b` | `theta_d_*_xor`, `theta_a_*_xor` |
| `W[574 + 8i + b]` | `theta_a_l{i}_b{b}` | `keccak::theta_a(i, b)` | `A'[i]`'s byte `b` | `theta_a_*_xor`, `rho_mask_*_xor`, `rho_pi_l{·}_b{·}` |
| `W[774 + 8·slot + b]`, 22 lanes | `rho_mask_l{i}_b{b}` | `keccak::rho_mask(i, b)` | `A'[i]`'s byte `b` XOR `mask(s_i)` | `rho_mask_*_xor`, `rho_pi_l{·}_b{·}` |
| `W[950 + 8i + b]` | `rho_out_l{i}_b{b}` | `keccak::rho_out(i, b)` | `B[i]`'s byte `b` | `rho_pi_l{i}_b{b}`, `chi_and_*_xor`, `chi_out_*_xor` |
| `W[1150 + 8i + b]` | `chi_and_l{i}_b{b}` | `keccak::chi_and(i, b)` | `B1[i] ^ B2[i]`'s byte `b` | `chi_and_*_xor`, `chi_out_*_xor` |
| `W[1350 + 8i + b]` | `chi_out_l{i}_b{b}` | `keccak::chi_out(i, b)` | chi's output byte | `chi_out_*_xor`, `output_w{j}`, and for lane 0's four iota bytes `iota_out_b{b}_xor` |
| `W[1550 + t]`, `t < 4` | `iota_out_b{b}` | `keccak::iota_out(t)` | `chi_out[0]`'s byte `b` XOR `rc[t]` | `iota_out_b{b}_xor`, `output_w{j}` |
| `W[1554]`, `W[1555]` | `range16_multiplicity`, `xor8_multiplicity` | `keccak::range16_multiplicity()`, `xor8_multiplicity()` | `crates/trace`'s counts | `range16_table_num`, `xor8_table_num` — **and no gate** |

**`S`: none.** Both channels' tables are closed forms, so nothing here needs
binding by identity or by the SRS digest.

**The `rho_mask` block is 22 lanes and not 25**, which is the one place this
circuit's blocks are not uniform: three lanes rotate by 0, 8 and 56 — a whole
number of bytes — so their rotation is a byte permutation and needs no split.

### 12.4 Gate list 0, the leaves

2,688 producing columns, in tree order. Relation `i` defines `L1[i]`.

| relations | columns | what |
| --- | --- | --- |
| 0–51 | 52 | the read side: `read_w{j}` per frame word, then `read_anchor` |
| 52–63 | 12 | `read_pad{i}`, the literal 1, to 64 leaves |
| 64–115 | 52 | the write side: `write_w{j}`, then `write_anchor` |
| 116–127 | 12 | `write_pad{i}` |
| 128–129 | 2 | `range16_table_{num,den}` |
| 130–537 | 408 | the 51 gaps' four obligations, `(num, den)` each |
| 538–549 | 12 | `base_low`'s three and `base_room`'s three |
| 550–639 | 90 | `range16_pad_{i}`, 45 neutral fractions to 256 |
| 640–641 | 2 | `xor8_table_{num,den}` |
| 642–961 | 320 | `parity_x{x}_b{b}_s{s}_xor`, 160 obligations |
| 962–1041 | 80 | `c_mask_x{x}_b{b}_xor`, 40 |
| 1042–1121 | 80 | `theta_d_x{x}_b{b}_xor`, 40 |
| 1122–1521 | 400 | `theta_a_l{i}_b{b}_xor`, 200 |
| 1522–1873 | 352 | `rho_mask_l{i}_b{b}_xor`, 176 |
| 1874–2673 | 800 | `chi_and_l{i}_b{b}_xor` and `chi_out_l{i}_b{b}_xor`, interleaved, 400 |
| 2674–2681 | 8 | `iota_out_b{b}_xor`, 4 |
| 2682–2687 | 6 | `xor8_pad_{i}`, 3 neutral fractions to 1,024 |

The two memory leaves are §0.6's one pattern, `docs/spec/memory.md` §2.2, over the
operands below; the anchor's two are `docs/spec/delegation.md` §5.1's.

```text
pattern     live·T(space, addr, ts, value) + 1 − live
positional  1 + mem_gamma·M[1] − M[1] + space·M[1]
              + mem_alpha_addr·addr·M[1] + <ts terms> + mem_alpha_val·value·M[1]
```

| leaf | space | addr | ts | value |
| --- | --- | --- | --- | --- |
| `read_w{j}` | `RAM` = 2 | `M[4 + 4j]` | `M[5 + 4j]` | `M[6 + 4j]` |
| `write_w{j}` | `RAM` = 2 | `M[4 + 4j]` | `4·cycle + 0` | `M[7 + 4j]` |
| `read_anchor` | 4 | `M[2]` | `4·cycle + 3` | `M[3]` |
| `write_anchor` | 4 | `M[2]` | the literal 0 | absent |

A fraction leaf pair is `docs/spec/lookup.md` §6's: `(1, E_l + g)` per obligation,
`(−mult, T + g)` per table, `(0, 1)` per pad.

### 12.5 Gate list 0, the enforcing gates

385 gates, relations 2,688–3,072, in this order. Every one is `Linear` or
`Quadratic` over base columns; degree 2 where a product of `live` appears and 1
otherwise; and every one is 0 on the all-zero row, so `zero_row_valid` is true.

| relations | n | name | degree | form |
| --- | --- | --- | --- | --- |
| 2688 | 1 | `live_boolean` | 2 | `M[1] − M[1]·M[1]` |
| 2689–2739 | 51 | `addr_w{j}` | 2 | `live·(addr_j − base − 4j) = 0` |
| 2740 | 1 | `base_aligned` | 2 | `live·(base − RAM_ORIGIN − 4·base_low) = 0` |
| 2741 | 1 | `base_in_window` | 2 | `live·((2^31 − 204) − base − base_room) = 0` |
| 2742–2765 | 24 | `round{r}_boolean` | 2 | `round_sel{r} − round_sel{r}²` |
| 2766 | 1 | `round_rule` | 1 | `w0_read_value − Σ_r r·round_sel{r} = 0` |
| 2767 | 1 | `one_round_a_live_row` | 1 | `Σ_r round_sel{r} − live = 0` |
| 2768–2771 | 4 | `rc{t}_rule` | 1 | `rc[t] − Σ_r ROUND_CONSTANTS[r]'s byte `IOTA_BYTES[t]` · round_sel{r} = 0` |
| 2772 | 1 | `writes_back_w0` | 1 | `w0_write_value − w0_read_value = 0` |
| 2773–2872 | 100 | `input_w{j}`, `output_w{j}`, interleaved lane by lane | 1 | `read_value − Σ_{m<4} 2^{8m}·state_in(i, 4h+m) = 0`, and the same over the output bytes |
| 2873–3072 | 200 | `rho_pi_l{i}_b{j}` | 1 | `B[i][j] − 2^{s−1}·(A'[u] + m[u]) − 2^{s−9}·(A'[w] − m[w]) − mask(s)·(2^{s−9} − 2^{s−1})·live = 0`, or `B[i][j] − A'[u] = 0` at `s = 0` |

Four notes, each a thing that is easy to get wrong.

- **`input_w{j}` and `output_w{j}` are ungated and must not be gated.** Both sides
  are 0 on the all-zero row, and each gate is the word's byte decomposition *and*
  its 32-bit bound at once. S21's `output_w{j}` **had** to carry `live`, because
  there the output came through 168 layers from committed bits and an ungated gate
  would have asked a padding row's written word to be keccak-f of the zero state.
  Here the output bytes are committed columns that are 0 on a padding row, and the
  obligations that pin them carry `live` as their selector.
- **A state byte is therefore not free on a padding row**, which is the sharp
  consequence: setting one asks the word it recomposes to be nonzero, and
  `input_w{j}` refuses it. A reviewer reading "the row mask gates everything"
  would expect otherwise, and `crates/checker/tests/keccak.rs::
  a_padding_row_is_free_only_where_the_mask_reaches` is the test that states both
  halves.
- **`one_round_a_live_row` is load-bearing.** The codes are `0..24`, so **every**
  pair sums to another round's word — `1 + 2 = 3` — and without it a row could
  claim two rounds, satisfy `round_rule`, and XOR two round constants into lane
  `(0,0)`. This is `mod_mul::one_modulus_a_live_row`'s argument (§18.5) at its
  sharpest, the codes here being consecutive from zero.
- **The rotation's constant rides `live`**, as every `sha256` gate constant does
  (§19.3): a gate carrying a bare nonzero constant cannot hold on the all-zero row,
  and `build::zero_on_zero_row` refuses it.

### 12.6 The obligations

Selector is `live` on all 1,230.

**`RANGE16`, 210.** `docs/spec/delegation.md` §10.3's shape, built by
`delegation::{gap_lookups_range16, bound_chunked}` and identical to `MOD_MUL`'s and
`EC_ADD`'s.

| name | n | expression |
| --- | --- | --- |
| `gap{j}_c{c}_range` | 102 | `gap{j}_c{c}` |
| `gap{j}_top_scaled` | 51 | `2^{10}·gap{j}_c1` |
| `gap{j}_lo_range` | 51 | `4·cycle − w{j}_read_ts − 1 − 2^{16}·gap{j}_c0 − 2^{32}·gap{j}_c1` |
| `base_low_c0_range`, `base_low_top_scaled`, `base_low_lo_range` | 3 | `base_low_hi`; `2^3·base_low_hi`; `base_low − 2^{16}·base_low_hi` |
| `base_room_c0_range`, `base_room_top_scaled`, `base_room_lo_range` | 3 | `base_room_hi`; `2·base_room_hi`; `base_room − 2^{16}·base_room_hi` |

`lookup::check_copowers` takes the 51 top gap chunks, `base_low_hi` and
`base_room_hi`, each under `live` — 53 pairs, and `keccak::artifact` panics without
them.

**`XOR8`, 1,020.** Tuple `(e0, e1, e2)` against `(a, b, a ^ b)`. Position 0 may be
any literal-weighted linear form with a constant; positions 1 and 2 are single
columns with unit coefficients, because `β^j·c` is not one `Coeff`
(`docs/spec/lookup.md` §5) — which is exactly why `rho_out` is committed and the
derived forms sit at position 0.

| name | n | `e0` | `e1` | `e2` |
| --- | --- | --- | --- | --- |
| `parity_x{x}_b{b}_s{s}_xor` | 160 | `state_in(5·0+x, b)` at `s = 0`, else `parity(x, b, s−1)` | `state_in(5(s+1)+x, b)` | `parity(x, b, s)` |
| `c_mask_x{x}_b{b}_xor` | 40 | the literal `0x80` | `theta_c(x, b)` | `c_mask(x, b)` |
| `theta_d_x{x}_b{b}_xor` | 40 | `ROTL(C[x+1], 1)`'s byte `b`, a linear form over `theta_c` and `c_mask` of column `x+1` with a constant | `theta_c(x+4 mod 5, b)` | `theta_d(x, b)` |
| `theta_a_l{i}_b{b}_xor` | 200 | `theta_d(i mod 5, b)` | `state_in(i, b)` | `theta_a(i, b)` |
| `rho_mask_l{i}_b{b}_xor` | 176 | the literal `mask(s_i)` | `theta_a(i, b)` | `rho_mask(i, b)` |
| `chi_and_l{i}_b{b}_xor` | 200 | `rho_out(B1(i), b)` | `rho_out(B2(i), b)` | `chi_and(i, b)` |
| `chi_out_l{i}_b{b}_xor` | 200 | `(rho_out(B2(i), b) − rho_out(B1(i), b) + chi_and(i, b))/2` | `rho_out(i, b)` | `chi_out(i, b)` |
| `iota_out_b{b}_xor` | 4 | `rc[t]` | `chi_out(0, b)` | `iota_out(t)` |

with `B1(i) = 5y + (x+1 mod 5)` and `B2(i) = 5y + (x+2 mod 5)` for `i = 5y + x`.

**The channel table.**

| channel | output positions | table columns | multiplicity |
| --- | --- | --- | --- |
| `RANGE16` = 1 | 2, 3 | `V[range16]` | `W[1554]` |
| `XOR8` = 4 | 4, 5 | `V[xor8_a]`, `V[xor8_b]`, `V[xor8_out]` | `W[1555]` |

**1,020 is three short of a cliff.** A fraction tree has
`(lookups + 1).next_power_of_two()` leaves, so 1,020 obligations give 1,024 and
1,024 would give 2,048 — 4,096 more inner columns, which at `2^18` is 34.4 GB
more a shard. That is why `ι` is four obligations and not eight, and
`keccak::check_shape` asserts both the count and the cliff.

### 12.7 The inner layers

Eleven row-wise lists — the `XOR8` tree's depth is 10, and it is the deepest —
then 18 halving lists. Each row-wise list reduces every tree pairwise; a tree
already at one node copies itself up so all four reach the halving phase together.

| layer | read tree | write tree | `range16` | `xor8` | width |
| --- | --- | --- | --- | --- | --- |
| `L1` | 64 | 64 | 512 | 2,048 | 2,688 |
| `L2` | 32 | 32 | 256 | 1,024 | 1,344 |
| `L3` | 16 | 16 | 128 | 512 | 672 |
| `L4` | 8 | 8 | 64 | 256 | 336 |
| `L5` | 4 | 4 | 32 | 128 | 168 |
| `L6` | 2 | 2 | 16 | 64 | 84 |
| `L7` | 1 | 1 | 8 | 32 | 42 |
| `L8` | 1 | 1 | 4 | 16 | 22 |
| `L9` | 1 | 1 | 2 | 8 | 12 |
| `L10` | 1 | 1 | 2 | 4 | 8 |
| `L11` | 1 | 1 | 2 | 2 | 6 |
| `L12`–`L29` | 1 | 1 | 2 | 2 | 6 each |

A product tree's node is `TreeProduct` at the halving lists and `Product` below
them; a fraction tree's is `TreeCross` over the pair plus `TreeProduct` of the
denominator, and `Quadratic` plus `Product` below (§0.6). Relations 3,073–5,874
are these lists in order.

`5,490 = 2,688 + 1,344 + 672 + 336 + 168 + 84 + 42 + 22 + 12 + 8 + 6 + 18·6`, and
the inner and relation totals at any admissible `n` are `5,382 + 6n` and
`5,767 + 6n`.

### 12.8 The outputs

| output | `PolyAddress` | name | read by |
| --- | --- | --- | --- |
| 0 | `L{29}[0]` | `read_root` | `verify_shard` step 10a, and step 10b's cross-shard product |
| 1 | `L{29}[1]` | `write_root` | ditto |
| 2, 3 | `L{29}[2..4]` | `range16_num_root`, `range16_den_root` | step 9: `num = 0` **and** `den ≠ 0` |
| 4, 5 | `L{29}[4..6]` | `xor8_num_root`, `xor8_den_root` | ditto |

### 12.9 Witness rows

`crates/checker/tests/keccak.rs` builds **one whole permutation** — 24 rows, round
0 through 23, each reading the state the one before it wrote and all at one frame
base — plus two corner rows and six padding rows, and evaluates every row through
`checker::violated_relations` and every `XOR8` obligation through its own reading
of the table. It runs in ordinary CI, and it is the source for this section rather
than a probe.

The two corners are the states whose byte masks are degenerate: the **all-zero**
state, where every intermediate is 0 until iota puts the round constant into lane
`(0,0)` — so a padding row and a live row differ in the one place that matters —
and the **all-ones** state, where every mask obligation sees `0xff` and every
rotation carries every bit across a byte boundary.

A row table is not reproduced here: a row is 1,764 cells. What stands in for one is
the chain, and each link runs in the fast gate:

1. `the_round_is_the_executors` holds this suite's own `u64` round, written from
   `docs/spec/delegation.md` §6.2, equal to `emulator::keccak_round` on 24 random
   states.
2. `crates/emulator/tests/keccak.rs::twenty_four_rounds_are_the_permutation` holds
   24 of those rounds equal to `tiny_keccak::keccakf`, and
   `a_round_depends_on_its_index` holds the 24 rounds pairwise distinct on one
   state.
3. `an_honest_witness_satisfies_every_gate_and_obligation` evaluates the circuit
   over a witness built from step 1's round and nothing the prover or the executor
   owns.
4. `the_twenty_four_rows_chain_through_the_frame` states the glue: round `r`'s
   written word is round `r + 1`'s read word, at one base.
5. `crates/prover/tests/fills.rs::the_keccak_fill_covers_its_circuit_exactly` holds
   the fill to writing every column the circuit declares, exactly once.

### 12.10 What fixes each cell

| cell | what fixes it |
| --- | --- |
| `cycle`, `base` | the multiset: the frame writes ride `4·cycle`, and the anchor's teardown read is at `4·cycle + 3` against the request's mirror write |
| `live` | `live_boolean`, and the multiset — a row switched off contributes the identity to both trees and the neutral tuple to both channels |
| `anchor_value` | nothing locally, by design: the request's mirror write is the other side and the two cancel only if equal (`docs/spec/delegation.md` §5.2) |
| `w{j}_addr` | `addr_w{j}`, against `base` |
| `w{j}_read_ts` | the four `gap{j}` obligations, and the multiset |
| `w0_read_value` | `round_rule`, so it is one of `0..24` |
| `w0_write_value` | `writes_back_w0` |
| a state word's `read_value` | `input_w{j}`, against its four bytes |
| a state word's `write_value` | `output_w{j}`, against the round's four output bytes |
| `gap{j}_c{c}` | its own `RANGE16` obligation and the derived `gap{j}_lo_range` — **no gate** |
| `base_low`, `base_room` | `base_aligned` / `base_in_window`, and their own obligations |
| `round_sel{r}` | `round{r}_boolean`, `round_rule`, `one_round_a_live_row` |
| `rc[t]` | `rc{t}_rule` |
| `state_in` | `input_w{j}`, and the obligations that read it — which also bound it to a byte |
| `parity`, `c_mask`, `theta_d`, `chi_and` | the `XOR8` channel **alone**: no gate reads any of them |
| `theta_a`, `rho_mask` | their own obligation **and** one of the 200 `rho_pi_l{i}_b{j}` gates |
| `rho_out` | `rho_pi_l{i}_b{j}`, and the two chi obligations that read it |
| `chi_out` | `chi_out_*_xor`, and `output_w{j}` — or, for lane 0's four iota bytes, `iota_out_b{b}_xor` |
| `iota_out` | `iota_out_b{b}_xor` and `output_w{j}` |
| the two multiplicities | their channel's root check, and nothing else — no gate reads them |

`crates/checker/tests/keccak.rs`' negative controls are that table read the other
way: fifteen cells corrupted one at a time, each refused by the relation or the
obligation named beside it, with the two that are refused by **neither a gate nor
the channel alone** separated into their own test because which of the two catches
a stage is a property of the circuit's shape.

---

## 13. `POSEIDON2` — family 10

### 13.1 Header

`family_circuit(10, n)` is `poseidon2::artifact(n)` with `poseidon2::channels()`, which is
**empty**. Like `keccak` it is not built by `build::assemble` — its work needs inner layers of
its own — but unlike `keccak` it does not carry a private builder either: the frame, the anchor,
the bounds and the layered `Assembly` are `constraints::delegation`'s, shared with `FR_ARITH`.
Normative spec: `delegation.md` §4, §5 and §12. Fill: `prover::family_fill(10)`, the private
`fill::poseidon2`.

**4,192 committed columns (100 `M`, 4,092 `W`, no `S`) and no virtual table.** Gate list 0
writes 74 columns — 64 memory leaves, the 4 carried to the top, and round 0's first sub-layer —
and holds 4,245 enforcing gates. **No lookup**, 2 outputs. At `n = 8`, the family's one height,
there are 201 gate lists, the top is `L201`, and the circuit has 2,020 inner columns and 6,268
relations. `artifact` panics unless every layer's width is its three parts' (§13.7), the column
counts are `MEMORY_COLUMNS` and `WITNESS_COLUMNS`, there is no setup column, no obligation and
no virtual table, the depth is `192 + 1 + n`, the relations `base_aligned` and `base_in_window`
exist **by name**, `addr_w` and `gap_w` number 24 each, `out_lane` 3, and the last round list
carries the three output comparisons and nothing else. It also panics on every refusal of
`validate` and of `memory::check_memory`.

**The height is `2^8`**, for the reason S21 gave `KECCAK_F` and which still holds here: one
row's forward pass is about 200 kB of `Fr`, so `2^8` rows are 51 MB and `2^16` would be 13 GB. A
delegation family's rows are invocations, so the height answers "how many permutations may a
shard hold".

**Why there is no lookup channel**: at `2^8` no table fits
(`docs/spec/delegation.md` §9). Every bound here is a bit decomposition with a booleanity gate,
and 4,093 of the 4,245 gates in list 0 are those booleanity gates. **`KECCAK_F` took the other
road at S26d** — a byte-oriented state over a byte XOR table, which fits `2^16` — and this
family did not follow it: a Poseidon2 round is field arithmetic, not a Boolean network, so there
is no byte table for it to look into.

### 13.2 Row kinds

Two, and neither is an instruction: this family is invoked, not decoded.

| row kind | `live` | what the row holds | what it adds to the multiset |
| --- | --- | --- | --- |
| an **invocation** | 1 | the requesting cycle, the frame base, the 24 words read and written, six values' 520 bits apiece, 24 × 38 gap bits and the frame pointer's 60 | 25 read tuples and 25 write tuples: the 24 frame words at `(RAM, base + 4j)`, and the anchor pair at `(DELEGATION_POSEIDON2, base)` |
| **padding** | 0 | every committed cell 0 | nothing: all 64 leaves are 1 |

A padding row still *computes* the permutation — of the all-zero state, whose output is not zero
— and the three `out_lane` gates are gated on `live` for exactly that reason. That gating is
what forces `live` and the three recomposed written lanes to be carried through all 192 round
layers: only gate list 0 can read a committed column, and the comparison happens at the top.

### 13.3 The base layer

| address | name | what it is |
| --- | --- | --- |
| `M[0]` | `cycle` | the requesting cycle |
| `M[1]` | `live` | the row's one mask; the frame and the anchor are one invocation |
| `M[2]` | `base` | the frame base pointer |
| `M[3]` | `anchor_value` | the teardown read's value, free on both sides |
| `M[4 + 4j + f]` | `w{j}_{addr,read_ts,read_value,write_value}` | frame word `j`, `j < 24` |
| `W[38j + i]` | `gap{j}_{i}` | bit `i` of word `j`'s timestamp gap |
| `W[912 + i]` | `base_low{i}` | bit `i` of `(base − RAM_ORIGIN) / 4`, 29 bits |
| `W[941 + i]` | `base_room{i}` | bit `i` of `2^31 − 96 − base`, 31 bits |

**The frame's witness columns start at `W[0]` here and at `W[1600]` in `KECCAK_F`.** S21's
circuit put the input state's bits first and the frame's above them (§12.3); S23's two put the
frame's first, because `constraints::delegation` owns them and cannot know what a family will
add. The `M` side is identical in both, so nothing about a frame's *memory* layout depends on
the family. `prover::fill::delegation_frame` therefore takes the witness base as an argument,
and `crates/prover/tests/fills.rs` holds each family's fill to covering `0..WITNESS_COLUMNS`
exactly once — a family added here that copies either layout must say which it copied.
| `W[972 + 520v + ..]` | `in{v}_*` / `out{v−3}_*` | value `v`'s 256 word bits, then 256 difference bits and 8 borrow bits |

Values `0..3` are the lanes read, `3..6` the lanes written. §13.4's canonicity gates are what
make each one a canonical `Fr`.

### 13.4 Gate list 0: the 4,245 enforcing gates

| count | gate | formula | what it fixes |
| --- | --- | --- | --- |
| 1 | `live_boolean` | `live − live²` | the one mask |
| 4,092 | `…_boolean` | `x − x²` | every gap, base and value bit |
| 24 | `addr_w{j}` | `live·(addr_j − base − 4j)` | the frame is at fixed offsets |
| 24 | `gap_w{j}` | `live·(4·cycle − 1 − read_ts_j − Σ 2^i·gap{j}_{i})` | the read precedes the write |
| 1 | `base_aligned` | `live·(base − RAM_ORIGIN − 4·Σ 2^i·base_low{i})` | word-aligned, at or above `RAM_ORIGIN` |
| 1 | `base_in_window` | `live·(2^31 − 96 − base − Σ 2^i·base_room{i})` | the frame is inside the window |
| 48 | `in{v}_word{k}` / `out{v}_word{k}` | `word − Σ 2^t·bit` | each word below `2^32`, and its decode |
| 48 | `in{v}_canonical{i}` / `out{v}_canonical{i}` | `live·(w_i − p_i) − b_{i−1} + 2^32·b_i − Σ 2^t·diff` | the borrow chain of `X − p` |
| 6 | `in{v}_below_modulus` / `out{v}_below_modulus` | `live − b_7` | the subtraction borrowed out, so `X < p` |

The canonicity argument is `delegation.md` §13.3's, and it is the same eight-limb chain here as
there: every term is a small integer, so the `Fr` equation is the integer equation, and the
eight telescope to `X − p + 2^256·b_7 = D` with `D < 2^256`.

### 13.5 The rounds

Sixty-four blocks of three gate lists, `delegation.md` §12.3's table. Round `r`'s sub-layer
`sub` is written by gate list `3r + sub` and lands in layer `3r + sub + 1`.

| sub | a full round writes | a partial round writes |
| --- | --- | --- |
| 0 | `q_0..q_2` then `t_0..t_2` | `q_0`, `t_0`, and lanes 1 and 2 carried |
| 1 | `q2_0..q2_2` then `t_0..t_2` | `q2_0`, `t_0`, and the two carried |
| 2 | `M_ext · v`, three lanes | `internal_matrix` over `(v_0, s_1, s_2)`, three lanes |

with `v_i = q2_i · t_i`. **Every `q` before every `t`**, because sub-layer 1 addresses the layer
below by region; interleaving them is the one addressing mistake this shape admits, and it is
the bug the differential caught.

`rc(r, i)` is `POSEIDON2_RC3_INITIAL[r][i]` for `r < 4`, `POSEIDON2_RC3_INTERNAL[r − 4]` on lane
0 for `4 ≤ r < 60` and zero on the other two, and `POSEIDON2_RC3_TERMINAL[r − 60][i]` above. The
initial `external_matrix` folds into round 0's first square, which is why `initial_lane(i)`
carries coefficient 2 on lane `i`'s eight words and 1 on the other sixteen.

### 13.6 The output comparison

Gate list 192 reads layer 192 — the final state, `live` and the three carried lanes — and holds
three enforcing gates and no producing ones but the tree's:

```text
out_lane{j}   live·final_j − live·out_j = 0
```

where `out_j` is `Σ_k 2^{32k}·write_value(8j + k)`, carried from gate list 0.

### 13.7 The layer geometry

Every layer is exactly `tree_width + carry_width + perm_width` columns wide, and `check_shape`
asserts it on the emitted artifact for every row-wise list:

| region | `L1` | `L2..L6` | `L7..L192` | `L193` | `L194..L201` |
| --- | --- | --- | --- | --- | --- |
| tree | 64 | 32, 16, 8, 4, 2 | 2 | 2 | 2, halving |
| carry | 4 | 4 | 4 | — | — |
| permutation | 6 | per §13.5 | per §13.5 | — | — |

The memory tree is 25 leaves a side padded to 32, so 64 columns at `L1` and five row-wise
halvings; from `L7` on the two roots are copied up to meet the permutation. Total inner columns
at `n = 8`: 2,020, of which 736 are the permutation, 768 the carry and the rest the tree.

### 13.8 The halving layers and the outputs

Eight halving lists, `L194` to `L201`, each two `TreeProduct`s. `outputs` is
`[L201[0], L201[1]]` — `READ_ROOT` then `WRITE_ROOT` — and nothing else: no channel, no
fraction tree.

### 13.9 What fixes each cell

| cell | what fixes it |
| --- | --- |
| `cycle`, `base` | the request's mirror query, through the anchor (`delegation.md` §5.3) |
| `live` | `live_boolean`, and the leaves' shape |
| `anchor_value` | nothing locally: it is the request's write-back, and the multiset pairs them |
| a frame word's `addr` | `addr_w{j}` |
| a frame word's `read_ts` | the multiset, bounded by `gap_w{j}` |
| a read lane | `in{v}_word{k}` and its canonicity chain; the permutation reads it |
| a written lane | the same, **and** `out_lane{j}` — the permutation says what it must be |
| a gap bit | its booleanity and `gap_w{j}` |
| a base bit | its booleanity and `base_aligned` / `base_in_window` |

---

## 14. `FR_ARITH` — family 11

### 14.1 Header

`family_circuit(11, n)` is `fr_arith::artifact(n)` with `fr_arith::channels()`, which is
**empty**. It is the one delegation circuit that *is* built by `build::assemble`, through
`memory::assemble`: every constraint it makes fits as an enforcing gate on gate list 0, so above
the leaves it is two product trees and nothing else. Normative spec: `delegation.md` §4, §5 and
§13. Fill: `prover::family_fill(11)`, the private `fill::fr_arith`.

**2,680 committed columns (104 `M`, 2,576 `W`, no `S`) and no virtual table.** Gate list 0
writes 64 columns — the two sides' 32 leaves — and holds 2,701 enforcing gates. **No lookup**, 2
outputs. At `n = 8` there are 14 gate lists, the top is `L14`, and the circuit has 142 inner
columns and 2,843 relations. `artifact` panics unless the column counts are `MEMORY_COLUMNS` and
`WITNESS_COLUMNS`, there is no setup column, no obligation and no virtual table, the nine named
relations of §14.4 exist **by name**, `addr_w` and `gap_w` number 25 each, `writes_back_w` 17,
and each value's `_word` and `_canonical` gates number 8. No relation's name may contain
`assume`. It also panics on every refusal of `validate` and of `memory::check_memory`.

**The height is `2^8`**, and a shard is 23 MB of forward pass. One row is one operation, so a
shard holds 256 of them; a guest doing more gets more shards, which is what shards are for.

### 14.2 Row kinds

Two. **One row is one operation** — `ops/row = 1`, which is the cost model the recursion guest's
contraction is sized against — and there is no no-op row kind: a row is live or it is padding.

| row kind | `live` | what the row holds | what it adds to the multiset |
| --- | --- | --- | --- |
| an **operation** | 1 | the requesting cycle, the frame base, the 25 words read and written, three values' 520 bits apiece, 25 × 38 gap bits, the frame pointer's 60, three selectors and three scalars | 26 read tuples and 26 write tuples: the 25 frame words at `(RAM, base + 4j)`, and the anchor pair at `(DELEGATION_FR_ARITH, base)` |
| **padding** | 0 | every committed cell 0 | nothing: all 64 leaves are 1 |

Every gate holds on the all-zero row: `one_op_a_live_row` reads `0 = 0` there, `prod_rule` reads
`0 = 0·0`, and `out_rule` reads `0 = 0`.

### 14.3 The base layer

| address | name | what it is |
| --- | --- | --- |
| `M[0..4]` | `cycle`, `live`, `base`, `anchor_value` | as §13.3 |
| `M[4 + 4j + f]` | `w{j}_*` | frame word `j`, `j < 25` |
| `W[38j + i]` | `gap{j}_{i}` | bit `i` of word `j`'s timestamp gap |
| `W[950 + i]` | `base_low{i}`, then `base_room{i}` | 29 then 31 bits |
| `W[1010 + 520v + ..]` | `a_*`, `b_*`, `out_*` | value `v`'s 256 word bits, 256 difference bits and 8 borrow bits |
| `W[2570..2573]` | `selector1`, `selector2`, `selector3` | one per operation code, in `OPS` order |
| `W[2573]` | `prod` | `a·b`, the one committed helper |
| `W[2574]` | `inv` | the witnessed inverse of `a`, 0 where `a` is 0 |
| `W[2575]` | `is_zero` | 1 exactly on an inverse row whose operand is 0 |

`is_zero` carries no booleanity gate of its own: the gadget's two gates force it
(`constraints/src/gadgets.rs`).

### 14.4 Gate list 0: the 2,701 enforcing gates

| count | gate | formula | what it fixes |
| --- | --- | --- | --- |
| 1 | `live_boolean` | `live − live²` | the one mask |
| 2,573 | `…_boolean` | `x − x²` | every gap, base, value and selector bit |
| 25 | `addr_w{j}` | `live·(addr_j − base − 4j)` | the frame is at fixed offsets |
| 25 | `gap_w{j}` | `live·(4·cycle − 1 − read_ts_j − Σ 2^i·gap{j}_{i})` | the read precedes the write |
| 1 | `base_aligned`, 1 `base_in_window` | as §13.4 | the frame pointer |
| 17 | `writes_back_w{j}` | `write_value_j − read_value_j` | the opcode word and both operands survive the call |
| 24 | `a_word{k}`, `b_word{k}`, `out_word{k}` | `word − Σ 2^t·bit` | each word below `2^32` |
| 24 | `<v>_canonical{i}` | the borrow chain of `X − p` | the value is an `Fr` |
| 3 | `<v>_below_modulus` | `live − b_7` | and a canonical one |
| 1 | `opcode_rule` | `opcode − f_add − 2·f_mul − 3·f_inv` | the opcode word is the selectors |
| 1 | `one_op_a_live_row` | `f_add + f_mul + f_inv − live` | exactly one operation a live row |
| 1 | `prod_rule` | `prod − a·b`, ungated | the product helper |
| 1 | `inv_is_an_inverse` | `a·inv + z − f_inv` | the is-zero gadget, enabled by the inverse selector |
| 1 | `is_zero_at_nonzero` | `a·z` | `z = 0` wherever `a` is not |
| 1 | `inverse_of_zero_is_zero` | `z·inv` | and `inv = 0` where it is |
| 1 | `out_rule` | `out − f_add·(a + b) − R^-1·f_mul·prod − R^2·f_inv·inv` | the operation |

`a`, `b` and `out` are linear forms over eight `M` columns apiece, so `prod_rule` is one
`Quadratic` with 64 products and `out_rule` one with 18. Both are degree 2: every product is two
committed columns.

The three gates the prompt's constraint set leaves incomplete are in the table and worth naming
again. Without `is_zero_at_nonzero` a prover sets `z = 1` at `a ≠ 0` and proves `inv(a) = 0`;
without `inverse_of_zero_is_zero` the witnessed inverse is free at `a = 0` and "inverse(0) = 0"
is prose; and without `one_op_a_live_row` a prover on an inverse row sets `f_add` and `f_mul`
instead, because the codes 1, 2 and 3 make `add + mul` spell `inv`.

### 14.5 The trees and the outputs

The memory subtree is 26 leaves a side padded to 32: 64 columns at `L1`, five row-wise halvings
to two at `L6`, then eight halving lists to `L14`. `outputs` is `[L14[0], L14[1]]`. There is
nothing else above gate list 0 — this circuit's whole statement is enforcing.

### 14.6 What fixes each cell

| cell | what fixes it |
| --- | --- |
| `cycle`, `base`, `live`, `anchor_value` | as §13.9 |
| the opcode word | `opcode_rule` and `one_op_a_live_row`, which together make it 1, 2 or 3 on a live row |
| `a`, `b` | their word gates and canonicity chains; the multiset says they are what the guest wrote |
| `out` | its word gates, its canonicity chain, and `out_rule` |
| `prod` | `prod_rule` |
| `inv`, `is_zero` | the three gadget gates |
| a selector | its booleanity, `opcode_rule` and `one_op_a_live_row` |

---

## 15. `PUBLIC_INPUT` — family 12

### 15.1 Header

`family_circuit(12, n)` is `memory::value_window_artifact(n)` with no channels. RAM window
`family::PUBLIC_INPUT_WINDOW` = 2, the statement's public input: exactly one shard in every
statement, whether or not the execution read a word of it. Spec: `public-values.md` §4 and §5;
`memory.md` §3 is the window machinery it inherits. Fill: `prover::family_fill(12)`, the private
`fill::public_input`, which is `trace::build_value_window_columns(log,
program::public_io_words(input), 2, h)`. **Three** committed columns, one virtual table, two
unmasked leaves, no enforcing gate, no lookup, no channel, two outputs. At `n = 12`, its one
height: 13 gate lists, top `L13`, 26 inner columns and relations.

**Its height is pinned at `2^12` since S-STREAM, and nothing derives another.** A window's first
address is `4h·w`, so the height is what places the window, and both public windows have to sit
inside the 64 KiB hole `[0, guest_memory::RAM_ORIGIN)` that no RAM window family initializes —
`INIT_TEARDOWN` masks RAM window 0's rows below `2^14` with `V[ram_live]` and `ZERO_WINDOWS`
never claims window 0 (`memory.md` §3.3). At `family::PUBLIC_WINDOW_HEIGHT` = `2^12` a window is
`4·2^12` = 16,384 bytes and the pair is windows 2 and 3: `4·2^12·2 = 0x8000` is
`guest_memory::PUBLIC_INPUT_ORIGIN` and `4·2^12·3 = 0xC000` is `PUBLIC_OUTPUT_ORIGIN`, the two
together ending flush against `RAM_ORIGIN` = `0x10000`. **That is a ceiling and not a
preference**: a `2^14` window is 64 KiB, the hole holds exactly one of them, and that one is
window 0 — which initializes address 0, where a null dereference would then balance. `[0,
0x8000)` stays unclaimed for exactly that reason, and windows 0 and 1 belong to nobody.
**It was `2^8` until S-STREAM**, where the pair was windows 32 and 33 at `0x8000` and `0x8400`
and a window carried 1,020 payload bytes against `4·2^12 − 4` = 16,380 now
(`public-values.md` §3, §9). `program::decode_program` writes the constant and ignores what a
caller asked for, and `verifier_core::window_height` refuses any other inside
`VmConfig::from_bytes` (`public-values.md` §2). The registry itself is looser —
`family_circuit(12, n)` is `Some` for `0 ≤ n ≤ 30`, the family carrying no channel and so
meeting no `BITS ≤ trace_vars` guard — and that looseness is never reachable through a key
(§26 observation 1).

**The height moved and not one relation did.** `trace_vars` reaches nothing inside
`memory::value_window_artifact` but its call to `memory::assemble`: both leaves come out of the
private `window_tuple` without it, and the family has no channel, so `lookup::channel_trees` is
handed an empty list and returns none. Inside `build::assemble` the depth is `1 + R + n` with
`R` still 0, so four more variables appended **four halving lists, each carrying one node per
output, and nothing else** — gate list 0, both leaves, the lookups, the outputs, the padding
contract and `zero_row_valid` are what they were at `2^8`, and so is every relation number below
the halving phase. That is the conclusion
`crates/checker/tests/{mod_mul,ec_add}.rs`' `a_height_moves_only_the_halving_layers` states for
the two delegation families that changed height before this one, read off the two window
constructors instead. What *did* move is every number that counts a layer, a row or a byte: 9
gate lists to 13, top `L9` to `L13`, 18 inner columns and relations to 26, the roots from
relations 16 and 17 to 24 and 25, the shard from 256 rows to 4,096, and the artifact from 2,027
bytes to 2,455.

### 15.2 Columns

| address | name | Rust | descriptive name | row `y` holds | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `teardown_ts` | `PolyAddress::Memory(0)` | Last write time | the timestamp of the last write to the word at `0x8000 + 4y`; 0 if the word is untouched | leaf `teardown` |
| `M[1]` | `teardown_value` | `PolyAddress::Memory(1)` | Final word | the last value written; `init_value` if untouched | leaf `teardown` |
| `M[2]` | `init_value` | `PolyAddress::Memory(2)` | Input word | `public_io_words(public.input)[y]`: word 0 the payload's byte length, then the payload little-endian, 0 to the end of the window | leaf `init`; **`verify_shard_local` step 10c** |
| `V[row]` | `row` | `VirtualKind::RowIndex`, wire tag 0 | Row index | `y` | both leaves |

All three are committed in `PublicInputs::memory_commitments`, in the global commit phase at G8
— **before** the memory challenges are squeezed, which is what `check_memory` requires of any
column a leaf weights by a global slot (`memory.md` §8). There is no `W` column and no `S`
column: `program::setup_commitments(12)` is empty, deliberately, because an `S` column is bound
by program identity and one execution's public input has no business in every execution's
identity (`public-values.md` §4). `M[2]` is `INIT_TEARDOWN`'s `S[0]` moved into the `M` group,
and that move is the whole difference between the two artifacts.

### 15.3 Leaves and layers

| `L1` | relation | node | positional | named |
| --- | --- | --- | --- | --- |
| 0 | 0 | `teardown` (read side) | `α_addr·V[row] ×4 + α_ts·M[0] + α_val·M[1] + WC` | `T(RAM, 0x8000 + 4·row, teardown_ts, teardown_value)` |
| 1 | 1 | `init` (write side) | `α_addr·V[row] ×4 + α_val·M[2] + WC` | `T(RAM, 0x8000 + 4·row, 0, init_value)` |

Here `WC = γ_M + 2 + α_addr·0x8000`, the window constant at `h = 2^12`, `w = 2`; the `2` added
to `γ_M` is `address_space::RAM`, the tag a public window shares with ordinary RAM and with the
advice region — which is what makes these families cost `MEM_WORD`, `MEM_SUBWORD` and `ATOMICS`
nothing: a load's memory leaf names its space with a literal, so a region with a tag of its own
would put a space *column* on all three load paths (`public-values.md` §2). Since S-STREAM the
window id is `2` as well, and that is a coincidence and nothing more: one `2` is a tag from
`constants::address_space`, the other is `0x8000 / 4h`. Both leaves are
`Linear` and carry no mask: every row of the window is a RAM word, and `V[ram_live]` is not
here and could not be. Its table is 1 only at `row ≥ 2^RAM_LIVE_BIT` and
`constants::memory::RAM_LIVE_BIT` is **14**, so over a `2^12`-row window it is 0 on every row;
its extension `1 − Π_{j ≥ 14}(1 − y_j)` reads the variables from 14 up, of which a 12-variable
point has none, so the product is empty and the extension is identically 0 — the mask would
switch the whole window off. **S-STREAM's raise does not reach that bound**: 12 is still at or
below 14, so both public artifacts stay mask-free exactly as they were at `2^8`, and
`gkr_verify::virtual_at_row` and `virtual_at_point` are where both halves of that are read.
Code: the private
`memory::window_tuple`, twice — `window_tuple(Some(M[0]), M[1])` and `window_tuple(None, M[2])`
— with no `memory::leaf` wrapper, there being nothing to mask. Degree 1 throughout: the circuit
has no `Quadratic` and no `Product` gate at all, its only other shape being the halving lists'
`TreeProduct`.

Halving list `k`, for `1 ≤ k ≤ n`, writes `L{k+1}` (`n − k` variables), exactly as §10.3:

| `L{k+1}` | relation | node | shape |
| --- | --- | --- | --- |
| 0 | `2k` | `read_{k+1}_0` | `TreeProduct { L{k}[0] }` |
| 1 | `2k + 1` | `write_{k+1}_0` | `TreeProduct { L{k}[1] }` |

In the last list, `k = n`, the two nodes are `read_root` and `write_root`.

| output | address, `n = 12` | node | value | verifier |
| --- | --- | --- | --- | --- |
| 0 | `L{13}[0]` | `read_root` | the product of every row's teardown leaf | step 10a: must equal `PublicInputs::memory_roots[p][0]`, `p` being the position of `(12, 0)` in `verifier_core::statement_shards` — after `INIT_TEARDOWN`'s shard, every `ZERO_WINDOWS` shard and every execution and delegation shard, the group order being `INIT_TEARDOWN`, `ZERO_WINDOWS`, then every other family ascending; a factor of `reconciles` |
| 1 | `L{13}[1]` | `write_root` | the product of every row's init leaf | step 10a: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |

**Step 10c is what makes the family mean anything**, and it reads a base claim, not an output.
A shard's base claims arrive in layout order `M`, `W`, `S`; this family has neither a `W` nor an
`S` column, so `claims[2]` is `M[2] init_value` at the shard's own opening point. The verifier
evaluates its own multilinear extension of `public_io_words(public.input)` there and compares,
returning `MemoryArgument("the public input window is not the statement's input")` on a
mismatch — after step 10a and before the opening (`reduce.rs`, `verify_shard_local`). What that
comparison is worth rests on the multiset and not on itself: the multiset already forces a
window's init column to be each address's **first** value (`memory.md` §4.2), so holding `M[2]`
to the statement says the guest's first read of every input word read the statement's input.
`claims[1]`, `M[1] teardown_value`, is held to **nothing**: a guest may overwrite its own input
buffer.

**This is where the raise is paid, and it is the only place.** The verifier's own extension is
`MultilinearPoly::new(PolyBacking::U32(public_io_words(bytes))).evaluate(&point)`, a fold that
costs `2^n − 1` multiplications over a `2^{n−1}`-element scratch: 4,095 and 2,048 `Fr` at
`2^12` where `2^8` cost 255 and 128, so a statement's two step-10c evaluations are **8,190 `Fr`
multiplications against 510**, over 81,920 live bytes a shard — the fold buffer and the
4,096-word `u32` vector `public_io_words` lays out — and 163,840 across the two
(`public-values.md` §8). Nothing else in the verifier's cost moves: step 10a still compares two
roots and step 11 still opens three columns at one point.

### 15.4 Rows

A window shard has no padding: every row is an address, and all 4,096 of them are live — word 0
the payload's byte length and 4,095 payload words, which is
`guest_memory::PUBLIC_PAYLOAD_BYTES` = 16,380 bytes and was 1,020 at `2^8`.
`zero_row_valid` is `true` and the padding contract is `M[0] = 0, M[1] = 0, M[2] = 0`; here that
all-zero row is an ordinary row and a common one — a word past the payload that no cycle
touched — whose two leaves are equal and cancel.

| row | `teardown_ts` | `teardown_value` | `init_value` | leaves |
| --- | --- | --- | --- | --- |
| word 0 | 0, or the last write's timestamp if the guest overwrote it | the payload's byte length, or what overwrote it | the payload's byte length | the length word is a committed cell like any other, and it is what makes the binding exact (`public-values.md` §3) |
| a payload word the guest only read | 0 | the input word `v` | `v` | both `T(RAM, 0x8000 + 4y, 0, v)`: they cancel |
| a payload word the guest overwrote | the last query's write timestamp `t` | the value it wrote, `v'` | the input word `v` | `T(RAM, 0x8000 + 4y, t, v')` read against `T(RAM, 0x8000 + 4y, 0, v)` written |
| a word past the payload | 0 | 0 | 0 | both `T(RAM, 0x8000 + 4y, 0, 0)`: they cancel |

Nothing in this circuit checks a row alone — there is no enforcing gate to check one with.
`M[0]` and `M[1]` are fixed by the memory argument; `M[2]` is fixed by step 10c, on every row at
once, through one multilinear evaluation.

**What holds this in CI**: `crates/checker/tests/public_values.rs`'
`the_input_window_column_is_the_verifiers_own_layout`, which builds `M[2]` from a real log with
`build_value_window_columns` and compares it row by row with `public_io_words`, and
`the_three_families_are_two_leaves_and_a_product_tree`, which refuses a channel, a lookup, a
setup column, a witness column or a third output. The proof half —
`MemoryArgument` for a claimed input that is not the committed column, and the control that the
journal's shard does not care about it — is `crates/prover/tests/public_io.rs`'
`a3_a_claimed_public_value_is_the_committed_column`, `#[ignore]`d for size.

---

## 16. `PUBLIC_OUTPUT` — family 13

### 16.1 Header

`family_circuit(13, n)` is `memory::zero_window_artifact(n)` with no channels — **`ZERO_WINDOWS`'
artifact, byte for byte**, and §11's entry describes it column for column and gate for gate. RAM
window `family::PUBLIC_OUTPUT_WINDOW` = 3, the journal: exactly one shard in every statement,
whether or not the execution committed a byte. Spec: `public-values.md` §4 and §5. Fill:
`prover::family_fill(13)`, the private `fill::window` — `ZERO_WINDOWS`' fill too — which is
`trace::build_init_teardown_columns(log, image, 3, h)`. Two committed columns, one virtual
table, two unmasked leaves, no enforcing gate, no lookup, no channel, two outputs. At `n = 12`,
its one height: 13 gate lists, top `L13`, 26 inner columns and relations. Its height is pinned
for §15.1's reason, and by the same constants.

**Its window moved and §15's did not**, which is the one asymmetry S-STREAM left. A window's
first address is `4h·w` and nothing else, so raising `h` from `2^8` to `2^12` kept
`PUBLIC_INPUT_ORIGIN` at `0x8000` — window 32 and window 2 are the same address at the two
heights — and moved the journal from `0x8400`, which is no window boundary at `2^12`, to
`0xC000`, the next one up. `guest_memory::PUBLIC_OUTPUT_ORIGIN` is the constant that records
it. Why it was raised at all is `revm-block.md` §2: that guest's frozen output commitment is a
per-transaction record of 13 fixed bytes plus the transaction's return data verbatim, under two
32-byte digests, and a 1,020-byte window held 73 of those records at zero return data and 21 at
the 45 bytes the pinned mini-block measures — against the 97 to 515 transactions a mainnet block
carries, so `guest_sdk::commit` exited 70 on all four real blocks S26 profiled. At 16,380 the
two figures are 1,255 and about 360 (`public-values.md` §9). **No circuit changed to buy it** —
§15.1's halving-list paragraph is this family's too, the two constructors differing only in the
init leaf.

**That it is the *same* artifact is the design, not a saving.** `value_window_artifact` was
written at S-IO and the journal does not take it: a committed init column is a column a
prover chooses, and it would choose the answer at timestamp 0, never store a word, and leave a
teardown column that matched anyway. The init leaf here is the literal 0 — no `M[2]`, no `S[0]`,
nothing to choose — so the only way the window ends holding the journal is that the guest's
stores put it there. Jolt closes the same hole with a mask; here the family simply has no column
to fill, which is cheaper and cannot be forgotten (`public-values.md` §5). Nothing checks this,
because there is nothing to check: the absence of a column is not a constraint.

### 16.2 Columns

| address | name | Rust | descriptive name | row `y` holds | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `teardown_ts` | `PolyAddress::Memory(0)` | Last write time | the timestamp of the last write to the word at `0xC000 + 4y`, or 0 | leaf `teardown` |
| `M[1]` | `teardown_value` | `PolyAddress::Memory(1)` | Final word | the last value written, or 0 | leaf `teardown`; **`verify_shard_local` step 10c** |
| `V[row]` | `row` | `VirtualKind::RowIndex`, wire tag 0 | Row index | `y` | both leaves |

Both are committed in `PublicInputs::memory_commitments` at G8. There is no `W`, no `S` and no
`M[2]`: `program::setup_commitments(13)` is empty, and the last row of `public-values.md` §5's
table — "there is no `M[2]`" — is the one place the design could have gone wrong.

`fill::window` reads `image.initial_word` for every window above 0, and here it returns 0 on
every row, which is what lets `ZERO_WINDOWS`' fill serve this family unchanged: the journal
window is `[0xC000, 0x10000)`, ending flush against `RAM_ORIGIN`, and both `loader`'s ELF
parser and `ProgramImage`'s own validator refuse a segment that leaves
`[RAM_ORIGIN, RAM_ORIGIN + RAM_LENGTH)` — "a segment leaves the guest RAM window" — so no image
byte can land there. An untouched row's teardown value is therefore 0, and its two leaves
cancel against the literal-zero init leaf.

### 16.3 Leaves and layers

| `L1` | relation | node | positional | named |
| --- | --- | --- | --- | --- |
| 0 | 0 | `teardown` (read side) | `α_addr·V[row] ×4 + α_ts·M[0] + α_val·M[1] + WC` | `T(RAM, 0xC000 + 4·row, teardown_ts, teardown_value)` |
| 1 | 1 | `init` (write side) | `α_addr·V[row] ×4 + WC` | `T(RAM, 0xC000 + 4·row, 0, 0)` |

Here `WC = γ_M + 2 + α_addr·0xC000`, the window constant at `h = 2^12`, `w = 3`. Both are
`Linear` and carry no mask, for §15.3's reason. Code: `memory::window_tuple(Some(M[0]), M[1])`
for the read side and the inline `Linear` of `zero_window_artifact` — four `(α_addr, V[row])`
terms on the window constant, and no value term at all — for the write side. The halving lists
and the outputs are §10.3's and §15.3's, with the same names, relation numbers and addresses;
`p` in step 10a is the position of `(13, 0)` in `statement_shards`, one past `PUBLIC_INPUT`'s.

**Step 10c reads `claims[1]`**: base claims arrive in layout order `M`, `W`, `S`, and this
family's whole layout is `M[0]`, `M[1]`, so index 1 is `teardown_value` and can be nothing
else — where `PUBLIC_INPUT`'s step 10c reads index 2. The verifier evaluates its own
multilinear extension of `public_io_words(public.output)` at the shard's opening point and
compares, returning
`MemoryArgument("the public output window is not the statement's output")` on a mismatch. The
multiset forces a window's teardown column to be each address's **last** value (`memory.md`
§4.2), so the comparison says the statement's output is what the guest's stores left behind.

### 16.4 Rows

A window shard has no padding: every row is an address, and all 4,096 of them are live — word 0
the journal's byte length and 4,095 payload words, `guest_memory::PUBLIC_PAYLOAD_BYTES` =
16,380 bytes against `2^8`'s 1,020. `zero_row_valid` is `true` and the
padding contract is `M[0] = 0, M[1] = 0`.

| row | `teardown_ts` | `teardown_value` | leaves |
| --- | --- | --- | --- |
| word 0, a run that committed nothing | 0 | 0 | both `T(RAM, 0xC000, 0, 0)`: they cancel |
| word 0, a run that committed `b` bytes | the last `commit`'s store timestamp | `b` | the final tuple read against the zero tuple written |
| a journal word the guest stored | that store's timestamp | the word it stored | as above |
| a word past the journal | 0 | 0 | both `T(RAM, 0xC000 + 4y, 0, 0)`: they cancel |

A guest that panics has still published what it committed: the journal is memory and the panic
handler does not have to know about it (`public-values.md` §7).

**What holds this in CI**: `crates/checker/tests/public_values.rs`'
`the_journals_family_has_no_init_column`, which asserts `family_circuit(13, v).to_bytes() ==
zero_window_artifact(v).to_bytes()` at `v = PUBLIC_WINDOW_HEIGHT.trailing_zeros()` — the height
read off the constant, so S-STREAM's raise needed no edit there — and that the family commits
exactly two columns — and whose
doc comment records the consequence of ever failing, that the verifier would then owe a check
that the init column is zero, and a check can be forgotten where a missing column cannot.

---

## 17. `ADVICE_WINDOWS` — family 14

### 17.1 Header

`family_circuit(14, n)` is `memory::value_window_artifact(n)` with no channels —
**`PUBLIC_INPUT`'s artifact at a different height**, and the two differ only in what the
verifier does with `M[2]`: holds it to the statement's `input`, or to nothing at all. The
prover-supplied advice region from `guest_memory::ADVICE_ORIGIN` = `0x8000_0000` up: `k ≥ 0`
shards, shard `i` being window `verifier_core::advice_first_window(h) + i`, consecutive from
the origin, so the statement carries a **count** and no window list. Spec:
`public-values.md` §6. Fill: `prover::family_fill(14)`, the private `fill::advice`, which is
`trace::build_value_window_columns(log, [trace::advice_word(bytes, h·i + y)]_y,
advice_first_window(h) + i, h)`. Three committed columns, one virtual table, two unmasked
leaves, no enforcing gate, no lookup, no channel, two outputs. At `n = 22`, its default and the
window height: 23 gate lists, top `L23`, 46 inner columns and relations; at `n = 16`, the window
height the prover suites set, 17 lists, top `L17`, 34 of each.

**It is in every `VmConfig` and usually proves zero shards.** `program::decode_program` lists it
always, at the window height — `verifier_core::window_height` requires `INIT_TEARDOWN`,
`ZERO_WINDOWS` and `ADVICE_WINDOWS` to be present and equal — while
`trace::advice_window_count` is `ceil(advice_region_words / h)` and
`trace::advice_region_words` is **0** for empty advice, not 1. No advice is no region, not a
region holding a zero length word; otherwise every program in the repository would pay a whole
window at the window height to say it has none. `verifier_core::check_memory_windows` bounds the
count from above instead, `advice_first_window(h) + k ≤ 2^30 / h`, which is the top of the
address space; the `ZERO_WINDOWS` ids stop at `2^29 / h − 1` and the advice ids start at
`2^29 / h`, so the two families' windows are disjoint by arithmetic and no disjointness rule is
needed.

### 17.2 Columns

| address | name | Rust | descriptive name | row `y` of shard `i` holds | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `teardown_ts` | `PolyAddress::Memory(0)` | Last write time | the timestamp of the last write to the word at `0x8000_0000 + 4h·i + 4y`, or 0 | leaf `teardown` |
| `M[1]` | `teardown_value` | `PolyAddress::Memory(1)` | Final word | the last value written; `init_value` if untouched | leaf `teardown` |
| `M[2]` | `init_value` | `PolyAddress::Memory(2)` | Advice word | `trace::advice_word(advice, h·i + y)`: word 0 of shard 0 the payload's byte length, then the payload little-endian, 0 past the end | leaf `init` — **and nothing else, anywhere** |
| `V[row]` | `row` | `VirtualKind::RowIndex`, wire tag 0 | Row index | `y` | both leaves |

All three are committed in `PublicInputs::memory_commitments` at G8. **`M[2]` is the one
committed column in the registry that no gate, no opening against identity or the SRS digest and
no step of `verify_shard` fixes**: only its own init leaf reads it, and a leaf constrains nothing
by itself — it balances against whatever the guest read, whatever that was. That is not an
omission; it is the definition of advice (`public-values.md` §6). What a guest owes in return
is a check of the advice against something a proof *does* bind — the public input carrying a
commitment to it, or the journal naming the state roots a block began and ended on, as
`guests/revm-block` does — and the VM cannot discharge that obligation for it.

A store into the advice region is an ordinary store and the multiset carries it like any other:
the region is **not** enforced read-only (owner's decision, S-IO), because enforcing it would need
a space selector on the load path of three frozen families and would buy no soundness on a column
nothing binds.

### 17.3 Leaves and layers

| `L1` | relation | node | positional | named |
| --- | --- | --- | --- | --- |
| 0 | 0 | `teardown` (read side) | `α_addr·V[row] ×4 + α_ts·M[0] + α_val·M[1] + WC` | `T(RAM, 4h·w + 4·row, teardown_ts, teardown_value)` |
| 1 | 1 | `init` (write side) | `α_addr·V[row] ×4 + α_val·M[2] + WC` | `T(RAM, 4h·w + 4·row, 0, init_value)` |

Here `w = advice_first_window(h) + i` and `WC = γ_M + 2 + α_addr·4h·w`, so at `h = 2^22` the
first window is 128 and shard `i` starts at `0x8000_0000 + i·2^24`. The address-space tag is
`RAM`, as it is for ordinary RAM and for the two public windows: what tells an advice word from
a heap word is which family initializes the address, and the ranges are disjoint by construction
(`public-values.md` §2). Both leaves are `Linear`, unmasked, degree 1, and the constructor is
§15.3's. The halving lists and the outputs are §10.3's, with the same names, relation numbers
and addresses; at `n = 22` the outputs are `L{23}[0]` and `L{23}[1]`, relations 44 and 45, and
`p` in step 10a is the position of `(14, i)` in `statement_shards`, last of all.

**There is no step 10c for this family.** `verify_shard_local`'s `public_value` match arm names
`PUBLIC_INPUT` and `PUBLIC_OUTPUT` and falls through to `None` for every other family, family 14
included.

### 17.4 Rows

A window shard has no padding: every row is an address. `zero_row_valid` is `true` and the
padding contract is `M[0] = 0, M[1] = 0, M[2] = 0`.

| row | `teardown_ts` | `teardown_value` | `init_value` | leaves |
| --- | --- | --- | --- | --- |
| shard 0's word 0 | 0, or a store's timestamp | the payload's byte length, or what overwrote it | the payload's byte length | the length word, laid out by `trace::advice_word` |
| an advice word the guest only read | 0 | the advice word `v` | `v` | both `T(RAM, a, 0, v)`: they cancel |
| an advice word the guest stored to | that store's timestamp | the value it stored, `v'` | the advice word `v` | `T(RAM, a, t, v')` read against `T(RAM, a, 0, v)` written |
| a word past the supplied advice | 0 | 0 | 0 | both `T(RAM, a, 0, 0)`: they cancel |

The last row is why the shard count is a function of what the **host supplied** and not of what
the guest read: the words a guest never touched still have to be initialized, and their two
tuples cancel. Above `0x8000_0000 + 4·advice_region_words` the executor's read is the fatal
`OutOfBounds`, because no window of this execution initializes an address there and nothing an
executor did with it could balance.

**What holds this in CI**: `crates/checker/tests/public_values.rs`'
`the_advice_region_is_a_length_word_then_a_payload`, `the_window_rules_take_an_honest_statement`
and `the_window_rules_refuse_each_of_their_controls`. That nothing binds `M[2]` is a negative, and
**no test asserts it directly**: the proof-level control that stood in for it — the same program
proved over two different advices, both verifying — was removed when the suite was abridged. What
holds the property now is the construction, not a test: the statement does not carry `M[2]`,
identity does not bind it, and no gate reads it.

---

## 18. `MOD_MUL` — family 15

### 18.1 Header

`family_circuit(15, n)` is `mod_mul::artifact(n)` with `mod_mul::channels()`, which is **one
`RANGE16` channel** since S26c (`delegation.md` §10.3). Like `EC_ADD` and `FR_ARITH` it is built
by `memory::assemble`: every constraint it makes fits as an enforcing gate on gate list 0, so
above the leaves it is two product trees, one fraction tree and nothing else. Normative spec:
`delegation.md` §4, §5 and **§14**. Fill: `prover::family_fill(15)`, the private
`fill::mod_mul`. Ecall `0x0504`, anchor space `address_space::DELEGATION_MOD_MUL` = 7.

**`0x0503` is retired and burned**, and the constant
`ecall::RETIRED_MOD_MUL_WITNESSED_MODULUS` is what says so. It was S26's call over a 32-word
frame carrying a **witnessed** modulus; S26b's frame is 25 words whose word 0 is a *selector*,
and append-only forbids a number a second meaning — an old binary calling `0x0503` would have
had its modulus read as a selector and computed something else, with nothing failing loudly
(`ecall-abi.md`, `delegation.md` §10.2).

**325 committed columns (104 `M`, 221 `W`, no `S`) and one virtual table, `V[range16]`.** Gate
list 0 writes 1,088 columns — 32 leaves a side of the two memory trees plus the `RANGE16` tree's
512 fraction pairs — and holds **125 enforcing gates (54 degree-1, 71 degree-2)**. **274
obligations**, all `RANGE16`, **4 outputs**. At its `n = 16` there are 26 gate lists (10 row-wise
and 16 halving), the top is `L26`, and the circuit has 2,244 inner columns and 2,369 relations,
550,391 bytes of wire form — `crates/constraints/tests/vectors/mod_mul.txt`, which is the
SHA-256 and shape line CI diffs, the artifact itself being half a megabyte. **None of the counts
before that sentence depends on `n`** except the inner and relation totals, which are
`2,180 + 4n` and `2,305 + 4n`: a height adds halving lists and nothing else, one node per output
each (`crates/checker/tests/mod_mul.rs`' `a_height_moves_only_the_halving_layers`, which now
compares `n = 16` against `n = 18`, `2^8` no longer being a height this family has).

`artifact` panics unless the column counts are `MEMORY_COLUMNS` and `WITNESS_COLUMNS`, there is
one `W` name per `W` column, the **multiplicity** closes the witness — a fill that wrote past it
would be writing into nothing, and `lookup`'s own rule wants the multiplicity last — the
obligation count is `lookups()`' own, and `A`, `B` and `OUT` index their own values
(`mod_mul::check_shape`). It also panics on every refusal of `validate`, of
`memory::check_memory`, of `lookup::check_discharge` and of `lookup::check_copowers`.

**What S26c changed is how a bound is spelled, and nothing else.** The frame is the same 25
words, the ecall is the same `0x0504`, the four moduli are the same, and every gate states what
it stated. Every bound this family made was a bit decomposition — 950 gap bits, 768 value bits,
768 chain-difference bits, 256 quotient bits, 518 carry bits, 60 base bits, 3,320 in all, each
with its own booleanity gate — and at `2^16`, where `V[range16]`'s table fits exactly,
`docs/spec/memory.md` §7's 16+16 pair makes a 32-bit bound **one committed column and two
obligations**. So:

| | pre-S26c | now | factor |
| --- | --- | --- | --- |
| committed columns | 3,468 (104 `M`, 3,364 `W`) | **325** (104 `M`, 221 `W`) | 10.7 |
| enforcing gates | 3,502 (86/3,416) | **125** (54/71) | 28.0 |
| obligations | 0 | **274** | — |
| gate lists at `n = 16` | 22 (6 + 16) | **26** (10 + 16) | — |
| inner columns at `n = 16` | 158 | **2,244** | 0.07 |
| wire bytes | 1,404,716 | **550,391** | 2.6 |
| proof bytes a shard at `n = 16` | 360,948 | **135,220** | 2.7 |

The `W` side is the whole of the committed fall: 950 gap bits became 50 chunks, 60 base bits
became 4 columns, each value's 520 columns became 32, `q`'s 264 became 16, and the carries' 518
became 42, with one multiplicity column added — 3,364 to 221, the 3,143 columns
`the_shape_is_the_manifests` names. The 125 enforcing gates are the old 3,502 less exactly three
groups: the 3,320 booleanity gates of those bit decompositions, the 32 `<v>_word{k}` and
`q_word{k}` decodes that read them, and the 25 `gap_w{j}` gates, which the gap's own obligations
now do the work of (§18.5). Nothing else went.

**The proof is where the win lands.** 3,364 witness commitments at 64 bytes were 215,296 of the
old 360,948; 221 are 14,144 of the new 135,220, and the commit phase is 325 Mercury column
commitments where it was 3,468. The numbers are `shard-proof.md` §9's layout over this circuit's
own shape, the formula `crates/prover/tests/mem.rs`' `proof_bytes` computes (§1.2).

**The computed peak barely moves, and that is the trade.** One `2^16` shard is about **5.1 GB**
— 4.57 GB of forward pass over the ten row-wise layers' 2,180 columns at `2^16` rows and 32
bytes (the sixteen halving layers add 8.4 MB between them), 0.16 GB of committed base (285
small-type columns at 4 bytes and 40 `Fr` ones at 32: `cycle`, the 25 read timestamps and the 14
carries), and 0.34 GB of transition 0's first bind, a half-height `Fr` table over 325 columns.
The same accounting on the pre-S26c circuit gives about **4.9 GB** — 0.27 GB of forward pass but
0.96 GB of base and 3.64 GB of first bind. The work moved out of the base layer and its bind and
into the inner layers, at roughly constant peak, and bought the proof and the commitments.
`crates/prover/tests/common`' `DELEGATION_CHANNEL_VARS` records 4.7 GB for this family, which is
the naive `inner × 2^16 × 32`; both are **computed**, and `delegation.md` §9.2's last paragraph
still owes a measured figure from the deferred `prover::revm` and `host::prove` suites.

**One row is one Ethereum field multiplication**, and since S26b the modulus is **one of four** a
frame word selects, supplied by the circuit as literals. S26 carried it as a witnessed 256-bit
operand; `delegation.md` §10.2 records the change and why, and §18.4 is what it bought. The four
are secp256k1's base and scalar fields and BN254's — which `docs/handoff/S26-cycle.md` §4
measures together at 31% to 57% of a mainnet block's guest cycles — and between them they are
every 256-bit field Ethereum block execution multiplies in. **The EVM's `MULMOD` is not among
them**: an arbitrary modulus has no representation in this frame and nothing routes the opcode
here.

**The height is `2^16`, and since S26c it is the only one the family has.** `RANGE16`'s table
needs sixteen variables, so `family_circuit`'s **derived** minimum-height guard — the widest
range channel's `BITS` over the family's own `channels()` — returns `None` below 16, and the
range in §1.1 is `16 ≤ n ≤ 30` where every other delegation family's is `0 ≤ n ≤ 30`. Three
things follow. `MOD_MUL_FIXTURE_VARS = 8` in `crates/prover/tests/common` is **gone**, replaced
by `DELEGATION_CHANNEL_VARS = 16`; `crates/checker/tests/mod_mul.rs` evaluates rows of the real
`2^16` circuit **row-locally** through `checker::violated_relations` rather than running a
whole-shard forward pass, because there is no reduced height to run one at; and
`crates/prover/tests/fills.rs` samples 32 live and 4 padding rows of a filled shard for the same
reason. All three are cheaper than what they replace and two of them are stronger statements.
The height was already `2^16` before S26c, for an unrelated reason — this is the one delegation
family whose invocation count a real workload drives hard, and at `2^8` S26's measured block took
1,048 shards where at `2^16` it takes 5 (`delegation.md` §9.1, §9.2) — so the channel's floor
cost nothing and the two constraints coincide.

**This family has a §0.5 row, and it is at `n = 16`.** §0.5's counts are over one circuit at
`n = 20`, which this family is never built at; its entries there are its own `n = 16` shape
counts — 824 `Linear`, 573 `Product`, 908 `Quadratic`, 48 `TreeProduct` (3 a halving list) and
16 `TreeCross` (1 a halving list) — and they sum to 2,369. The `TreeCross` is what a fourth
output costs and what makes a delegation family with a channel visible in that table at all.

### 18.2 Row kinds

Two, and neither is an instruction: **this family is invoked, not decoded**
(`delegation.md` §1). It claims no pc, `program::lookup_tuple(15)` is empty, it owns no cycle,
it is not in `constants::family::CYCLE_OWNING`, and it is in a `VmConfig` exactly when the linked
binary declares it. **One row is one multiplication** — `ops/row = 1`, as every delegation family
has it — and there is no no-op row kind: a row is live or it is padding.

| row kind | `live` | what the row holds | what it adds to the multiset |
| --- | --- | --- | --- |
| a **multiplication** | 1 | the requesting cycle, the frame base, the 25 words read and written, the four modulus selectors and the eight limbs they name, three values' 24 limb halfwords and 24 chain columns, the quotient's 8 limbs and 8 halfwords, 14 signed carries as a value and two chunks, and 25 × 2 gap chunks with the frame pointer's four columns | 26 read tuples and 26 write tuples: the 25 frame words at `(RAM, base + 4j)`, and the anchor pair at `(DELEGATION_MOD_MUL, base)` |
| **padding** | 0 | every committed cell 0 **as the honest fill writes it**, the multiplicity column excepted | nothing: all 64 leaves are 1 — 52 real ones collapse to the product's identity and 12 are pads that are literally 1 — and 274 gated zeros the channel counts |

The multiplicity column is the one committed column whose row `y` is not this shard's `y`-th
invocation: it is row `y` of `V[range16]`, and what it holds is a count over the whole shard
(§0.3).

Three gates hold the all-zero row and are worth spelling out. `one_modulus_a_live_row` forces
every selector to 0 there, so `m_limb{k}_rule` forces every modulus limb to 0, which is what
lets the three `<v>_canonical{i}` chains be **ungated** and still hold. Each
`<v>_below_modulus` reads `live = borrow7`, so a padding row's last borrow must be 0 where a live
row's must be 1 — three gates say it, and a fill that computed a padding row's chain against the
shard's modulus rather than against the row's zero `m` would fail all three. And `carry_terms`
puts `live` on the offset, so a padding row's carry reads `carry{k} − 2^36·0` and `limb{k}`
reads `0 = 0`, not `−2^36`.

**The padding row is all-zero because the fill writes it so, not because the gates force it**,
and since S26c that is true of *more* cells than before. Every obligation's selector is `live`,
and a lookup holds wherever its selector is 0, so on a padding row no bound applies at all:
with `m = 0` the limb identity reduces to a relation among `a`, `b`, `out`, `q` and the carries
over `Fr`, with none of them bounded, and a padding row could legally carry unbounded cells where
before S26c its ungated `<v>_word{k}` decompositions still pinned every limb below `2^32`. It is
harmless — the row's leaves are the multiset identity, it requests nothing, pairs with no anchor
and writes no register — but a test asserting "a padding row's columns are zero" is asserting a
property of the fill. `crates/checker/tests/tamper.rs` asserts the direction that matters in
both senses: the honest all-zero row satisfies every gate (`zero_row_valid` is `true`, which
`check_padding` recomputes), and its **control** twin writes a 1 into a padding row's
`gap_chunk(5, 0)` and requires the block to **verify** — the cell being genuinely free, because
the four obligations it feeds all carry `live`.

### 18.3 The base layer

**Memory-argument columns, `M[0..104]`** — filled by `fill::mod_mul` through the shared
`delegation_frame_range16`; committed in `PublicInputs::memory_commitments`, absorbed at G8
before the memory challenges.

| address | name | what it is |
| --- | --- | --- |
| `M[0..4]` | `cycle`, `live`, `base`, `anchor_value` | as §12.3: the requesting cycle, the row's one mask, the `a0` the request passed, and the anchor teardown's value, **free on both sides** |
| `M[4 + 4j + f]` | `w{j}_addr`, `w{j}_read_ts`, `w{j}_read_value`, `w{j}_write_value` | frame word `j`, `j < 25`: word 0 the modulus selector, 1–8 `a`, 9–16 `b`, 17–24 the result `out`, eight little-endian 32-bit limbs a value (`constants::mod_mul`'s `SELECTOR_WORD`, `A_WORD`, `B_WORD`, `OUT_WORD`) |

**Witness columns, `W[0..221]`** — all filled by `fill::mod_mul` except the last; committed in
`ShardProof::witness_commitments`, absorbed at S3, with `g` drawn after them at S4.

| address | name | what it is |
| --- | --- | --- |
| `W[2j + c]`, `j < 25`, `c < 2` | `gap{j}_c{c}` | chunk `c` of word `j`'s timestamp gap, weight `2^{16(c+1)}` — `50` columns where S26 had 950 bits |
| `W[50..54]` | `base_low`, `base_low_hi`, `base_room`, `base_room_hi` | `(base − RAM_ORIGIN)/4` and `2^31 − 100 − base`, each with its high halfword |
| `W[54..58]` | `selector1` … `selector4` | the four modulus selectors, in `mod_mul::CODES` order: codes 1, 2, 3, 4 |
| `W[58..66]` | `m_limb{k}` | limb `k` of the selected modulus — **a witness column, and the only place `m` exists** |
| `W[66 + 32v + k]` | `a{k}_hi`, `b{k}_hi`, `out{k}_hi` | the high halfword of limb `k` of value `v`, in frame order: `a` at `W[66..98]`, `b` at `W[98..130]`, `out` at `W[130..162]` |
| `W[66 + 32v + 8 + i]` | `<v>_diff{i}` | difference limb `i` of value `v`'s `< m` chain |
| `W[66 + 32v + 16 + i]` | `<v>_diff{i}_hi` | its high halfword |
| `W[66 + 32v + 24 + i]` | `<v>_borrow{i}` | borrow `i` of that chain; `borrow7` is pinned to `live` |
| `W[162..170]`, `W[170..178]` | `q_limb{k}`, `q_limb{k}_hi` | the quotient's eight limbs — **the one value in the row the execution did not record** — and their halfwords |
| `W[178 + 3k]`, `W[179 + 3k]`, `W[180 + 3k]`, `k < 14` | `carry{k}`, `carry{k}_c0`, `carry{k}_c1` | signed carry `k` as the **unsigned** `carry + 2^36`, and its two chunks. `carry{k}` is `Fr`-backed, the value reaching `2^37` |
| `W[220]` | `range16_multiplicity` | the `RANGE16` table's count, filled by `trace::build_multiplicities` and not by the fill |

Every address is reached through `mod_mul::word`, `gap_chunk`, `base_low`, `base_low_hi`,
`base_room`, `base_room_hi`, `selector`, `m_limb`, `value_hi`, `diff`, `diff_hi`, `borrow_bit`,
`q_limb`, `q_hi`, `carry`, `carry_chunk` and `multiplicity_column`, so a fill, a checker and a
tamper twin name a column and never a number; `the_witness_regions_do_not_overlap` holds those
accessors to covering the witness exactly once each. The value index is `mod_mul::A`, `::B` or
`::OUT` and never a literal — three values where S26 had four, and a bare index would have
silently renumbered every twin.

**136 of the 221 witness columns are read by no gate at all**, and that is the shape of the
re-shape: the 50 gap chunks, `base_low_hi`, `base_room_hi`, the 24 `<v>{k}_hi`, the 24
`<v>_diff{i}_hi`, the 8 `q_limb{k}_hi` and the 28 carry chunks exist only to be the direct half
of a 16+16 pair, and `range16_multiplicity` is read only by the leaf `range16_table_num`. What
*is* read by a gate is the value each pair bounds — `diff(v, i)` by `<v>_canonical{i}`,
`q_limb(k)` and `carry(k)` by the limb equations — so a corrupted halfword breaks no relation
and is refused by the channel alone (§18.5).

**Where each value reads from.** The selector, `a` and `b` are read from each word's
`read_value`; `out` alone is read from `write_value`. That is the whole of what makes the call a
function: the guest's field and operands are what it *passed*, and the result is what the
invocation *wrote*. Seventeen `writes_back_w{j}` gates then hold every non-result word to writing
back what it read, so a call can rewrite neither the guest's operands nor — word 0 being inside
that set — the field it was asked to work in.

### 18.4 The gates

125 enforcing gates on gate list 0, relations 1,088–1,212, in `artifact`'s own order.

| group | relations | count | degree | what it says |
| --- | --- | --- | --- | --- |
| `live_boolean` | 1,088 | 1 | 2 | the row's one mask is a bit |
| `addr_w{j}` | 1,089–1,113 | 25 | 2 | `live·(w{j}_addr − base − 4j)`: word `j` is at `base + 4j`. Degree 2 because it carries `live` — on a padding row `addr` and `base` are 0 and `4j` is not |
| `base_aligned`, `base_in_window` | 1,114–1,115 | 2 | 2 | `live·(base − 4·base_low − RAM_ORIGIN)` and `live·(2^31 − 100 − base − base_room)`: the base is 4-aligned and its whole 100-byte frame is inside RAM |
| `writes_back_w{j}`, `j < 17` | 1,116–1,132 | 17 | 1 | `w{j}_write_value − w{j}_read_value`: the selector and both operands survive the call |
| `selector{code}_boolean` | 1,133–1,136 | 4 | 2 | each of the four modulus selectors is a bit |
| `selector_rule` | 1,137 | 1 | 1 | `w0_read_value − Σ code_i·s_i` |
| `one_modulus_a_live_row` | 1,138 | 1 | 1 | `Σ s_i − live` |
| `m_limb{k}_rule` | 1,139–1,146 | 8 | 1 | `m_k − Σ MODULI[i][k]·s_i`, the literals of the four moduli |
| `<v>_borrow{i}_boolean` | 1,147–1,154, 1,164–1,171, 1,181–1,188 | 24 | 2 | the three chains' borrows are bits |
| `<v>_canonical{i}` | 1,155–1,162, 1,172–1,179, 1,189–1,196 | 24 | 1 | `v_i − m_i − b_{i−1} + 2^32·b_i − d_i`, **ungated** |
| `<v>_below_modulus` | 1,163, 1,180, 1,197 | 3 | 1 | `live − borrow7`: the subtraction borrowed out, so `v < m` |
| **`limb{k}`, `k < 15`** | 1,198–1,212 | 15 | 2 | the schoolbook identity, position by position |

**There is no `gap_w{j}` gate and no `<v>_word{k}` or `q_word{k}` decode.** The 25 gaps and the
40 limbs they bounded are §18.5's obligations, which are the bound and the decomposition at
once, exactly as `memory::gap_lookups` has it for an execution family. That is 57 of the 3,377
gates S26c removed; the other 3,320 are the booleanity gates of the bit columns themselves.

**The fifteen limb equations are the circuit.** With `P_k = Σ_{i+j=k} a_i·b_j` and
`S_k = Σ_{i+j=k} q_i·m_j`, gate `limb{k}` is

```text
P_k − S_k − out_k + c_{k−1} − 2^32·c_k = 0,     c_k = carry{k} − 2^36·live
```

where `out_k` is absent past limb 7, `c_{−1}` is absent, and `c_14` is absent — which is the
closing condition. Weight the fifteen equations by `2^{32k}` and sum: the carries telescope and
what is left is `a·b − q·m − out = c_14·2^{480}`. A last carry that does not exist is a last
carry of zero, so **the absence of a fifteenth carry column is the identity**
(`the_limb_identity_closes`). Each gate is one `Quadratic`: the products are pairs of committed
columns — `a_i·b_j` two `M`s and `q_i·m_j` two `W`s, 64 pairs and so 128 products over the
fifteen gates — and everything else is a column times a literal, so the degree is 2 and never 3.

**Why the equation over `Fr` is the equation over ℤ.** Every operand is bounded to `2^32` by its
own 16+16 pair, so the largest term of any position is `8·(2^32 − 1)^2 < 2^67`, the largest
coefficient is `2^32` times a carry's offset, `2^68`, and `p` is 254 bits. No limb equation can
wrap, so there is no modular-arithmetic loophole to argue about — the same argument
`delegation.md` §13.3's canonicity chain rests on. **Since S26c that premise is a lookup and not
a gate**, which is the one thing the re-shape changed about the soundness story: drop an
obligation and the identity stops being about integers, exactly as dropping a decomposition did.

**`m` has no bound of its own, and `one_modulus_a_live_row` is what stands in for it.** Every
other value in that paragraph is bounded by its two obligations; `m`'s limbs are bounded only by
`m_limb{k}_rule` pinning each to one entry of a four-row table of literals, which holds exactly
while at most one selector is set. **So the gate is load-bearing twice.** Once for the selector:
the codes are 1, 2, 3, 4, so `1 + 3 = 4` and a row claiming secp256k1's `p` *and* BN254's `q`
spells the frame word of a row claiming BN254's `r` — `selector_rule` cannot see the forgery, and
a `const` assertion in `selector_gates` says so, so nobody deletes the gate believing the codes
are separated. And once for the integer semantics: two selectors at once give
`m_0 = 0xffff_fc2f + 0xd036_4141 > 2^32`, `S_k` above `2^68`, and the paragraph above out of
reach. It is therefore **not** made redundant by any code spacing — separating the codes to
1, 2, 4, 8 would let `selector_rule` see the forgery and would still leave `Σ s_i = live` as the
only thing bounding `m`. `two_moduli_at_once_is_refused` is the twin.

**Eight columns for `m`, not four products a limb.** The alternative was substituting
`Σ MODULI[i][k]·s_i` wherever `m_k` appears. The chains would take four linear terms instead of
one, which is free; `limb{k}`'s 64 `q_i·m_j` products would become 256, taking gate list 0 from
128 products to 320. Eight committed columns and eight degree-1 gates is the cheaper half, and it
is also what makes "the modulus is not the selected literal" a cell a tamper twin can corrupt —
`a_modulus_limb_that_is_not_the_selected_literal_is_refused`.

**The signed carry.** A position's partial sum can be negative, and `Fr` has no sign, so a carry
is the committed `carry{k}` minus `2^36·live`: a 37-bit unsigned value read as an offset value in
`[−2^36, 2^36)`. The bound is the fixed point of `C = (2^67 + 2^32 + C)/2^32`, which settles just
above `2^35`, so 37 bits with a `2^36` offset is a full factor of two of room —
`the_carry_offset_covers_the_bound` computes it rather than trusting this paragraph. **The
selector does not tighten it**: the recurrence reads only the limbs' `2^32` bounds. What changed
at S26c is the *witness*: `carry{k}` is now a committed `Fr` column bounded by four obligations
where it used to be 37 boolean columns summed by a gate. The `live` factor on the offset is
unchanged and is what makes a padding row's carry 0 (§18.2).

**Three chains, and the fixed modulus is what makes them free of `live`.** `delegation.md` §13.3's
canonicity chain subtracts `p`, a *literal*, which has to be multiplied by `live` so the gate
vanishes on a padding row. Here the chain subtracts `m_i`, a **column** that `m_limb{k}_rule`
already forces to 0 on a padding row, so the gate is **ungated** and degree 1 with nothing paid
for it. S26 reached the same shape from the opposite direction — `m` was a frame word then, and
gating would have made the gate degree 3.

**`m > 0` needs no gate.** Every entry of `MODULI` is a 256-bit odd prime above `2^253`, which
`every_modulus_is_a_256_bit_odd_value` holds a fifth entry to as well. S26 needed
`emulator::mod_mul_frame` to refuse a zero modulus by name; there is no zero modulus to refuse
any more, and that refusal went with the operand it read.

**What bounds `q`, and what the operand chains buy.** Its sixteen obligations bound it to
`2^256`, and `a < m` with `b < m` make that **enough by construction**:
`q = (a·b − out)/m ≤ (m−1)²/m < m ≤ 2^256`. So the statement is *total* — every frame the circuit
accepts has a witness and every witness it has is accepted — where S26 had only soundness. S26's
note here read "a cost to the **prover**, never a false statement to the verifier", which was
true of an unreduced operand then and is not a thing that can happen now: `a_below_modulus` and
`b_below_modulus` refuse the frame, `emulator::mod_mul_frame` refuses it earlier and by name, and
the fill asserts it earlier still. The price is the caller's, and it is real:
`guests/vendor/k256` reduces an operand below `p` where it used to reduce only below `2^256`
(`delegation.md` §14.3, §14.4). `out < m` remains the **reduction** and is a different statement
from the other two: without it a prover answers `r + m` with the quotient one lower and every
limb equation still holds.

### 18.5 The lookups and the channel

One channel, `RANGE16` = channel 1, table `V[range16]`, multiplicity `W[220]`. The tuple is
**one** expression wide, so it weights its column by the literal 1, reads `g` and **no** power of
`β` and no neutral, and `E + g = g + live·e_0` is the row denominator. Every obligation's
selector is `LIVE`. The helpers are `delegation::{range16, bound32, bound_chunked,
gap_lookups_range16}`, shared with `EC_ADD`.

| obligation | relations | count | tuple | shape |
| --- | --- | --- | --- | --- |
| `gap{j}_c0_range`, `gap{j}_c1_range` | 66–613 | 50 | `gap{j}_c{c}` | direct: each chunk below `2^16` |
| `gap{j}_top_scaled` | ” | 25 | `2^10 · gap{j}_c1` | scaled: the top chunk below `2^6` |
| `gap{j}_lo_range` | ” | 25 | `4·cycle − w{j}_read_ts − 1 − 2^16·c0 − 2^32·c1` | the derived low sixteen bits |
| `base_low_c0_range`, `base_low_top_scaled`, `base_low_lo_range` | ” | 3 | `base_low_hi`, `2^3·base_low_hi`, `base_low − 2^16·base_low_hi` | `[0, 2^29)` |
| `base_room_c0_range`, `base_room_top_scaled`, `base_room_lo_range` | ” | 3 | as above with `2^1` scaling | `[0, 2^31)` |
| `{v}{k}_hi_range`, `{v}{k}_lo_range` | ” | 48 | `<v>{k}_hi`, `w{j}_value − 2^16·<v>{k}_hi` | each limb of `a`, `b`, `out` below `2^32` |
| `{v}_diff{k}_hi_range`, `{v}_diff{k}_lo_range` | ” | 48 | 16+16 over `diff(v, k)` | the three chains' difference limbs |
| `q{k}_hi_range`, `q{k}_lo_range` | ” | 16 | 16+16 over `q_limb(k)` | each quotient limb below `2^32` |
| `carry{k}_c0_range`, `_c1_range`, `_top_scaled`, `_lo_range` | ” | 56 | two chunks, `2^11·carry{k}_c1`, and `carry{k} − 2^16·c0 − 2^32·c1` | each carry's unsigned value below `2^37` |

**274 obligations**, in that order: 100 for the gaps, 3 and 3 for the base, 96 for the three
values and their chains (32 a value, interleaved limb by limb), 16 for the quotient, 56 for the
carries. `check_shape` holds `artifact.lookups.len()` to `lookups()`' own count, so a dropped
obligation is a panic where the artifact is built.

**The 38-bit timestamp gap is `RANGE16`'s and not `TIMESTAMP`'s**, and it cannot be otherwise:
that channel's `BITS` is 19 and its table needs `2^20` rows, an execution family's floor, above
this family's `2^16` (`delegation.md` §9, §10.3). Two committed chunks with a
derived low half are three 16-bit pieces for 38 bits, `38 = 16 + 16 + 6`, and the decomposition
is **exact**: the maximum is `(2^16 − 1)(1 + 2^16) + 2^32(2^6 − 1) = 2^38 − 1`. The carries' 37
bits are the same shape at `37 = 16 + 16 + 5`, exact at `2^37 − 1`, and the base's 29 and 31 bits
are one committed chunk each.

**A 16+16 pair is one committed column and two obligations, and that is the whole reason the
channel is worth carrying.** A 32-bit bound by bit decomposition is 32 columns and 32 booleanity
gates, and a 38-bit gap is 38. The low expression is *defined* as the remainder
`x − 2^16·hi`, so no wrap is possible: `hi < 2^16` and `x − 2^16·hi < 2^16` give `x < 2^32`.

**The scaled obligation alone bounds nothing**, and `lookup::check_copowers` is what says so:
`2^{16−r}` is a unit in `Fr`, so an unbounded value sweeps a coset almost none of whose members
is a small integer, and the range check sees nothing wrong. It is the top chunk's own **direct**
obligation under the **same** selector that establishes the premise — S18's fix — and
`mod_mul::scaled_columns` lists all 41 scaled columns with `LIVE` beside each: the 25 gap tops,
`base_low_hi`, `base_room_hi`, and the 14 carry tops. `artifact` runs the check and panics on it.

**One multiplicity column, and no gate reads it.** `trace::build_multiplicities` counts each
`RANGE16` table row's occurrences over the 274 gated tuples of every row of the shard — switched-
off rows included, a padding row contributing 274 zeros, so table row 0's count is large — and
appends the column after the fill; `prover::fill::mod_mul` does not write it, which is why
`crates/prover/tests/fills.rs` passes `WITNESS_COLUMNS − channels().len()` to `covers`. It has to
exist because `artifact.committed()` names it, and it is last in the witness subtree because
`lookup`'s own rule wants it there. It is the fourth output's ancestor and so the whole reason
this family has four outputs and not two.

`checker::violated_lookups` is the native reading of every one of these obligations, the same
statement LogUp proves, and `lookup::check_discharge` — which `memory::assemble` runs because the
family now declares a channel — is what says each obligation has its own denominator leaf with a
numerator of 1 beside it and the channel exactly one table fraction.

### 18.6 The trees, the inner layers and the outputs

Three trees. The two memory product trees take `d::leaves(DELEGATION_MOD_MUL, 25)`: 25 frame
words plus one anchor leaf a side, **26 real leaves padded to 32**, so each side carries 6
`read_pad{i}` / `write_pad{i}` leaves that are literally 1. The read side's leaves consume the
write each frame word names, then the anchor **teardown**
`T(space, base, 4·cycle + 3, anchor_value)`; the write side's write at `4·cycle + 0`, then the
anchor **answer** `T(space, base, 0, 0)`, stamped 0 and valued 0. The `RANGE16` fraction tree
takes 274 obligations plus its table fraction, **275 leaves padded to 512**, so 237 pad
fractions of `(0, 1)`.

**`R = 9`, and the fraction tree sets it alone** — a 32-leaf product tree is 5 deep — so the
depth is `N = 1 + 9 + n` and the circuit is **ten** row-wise lists where before S26c it was six.
That is the whole of why the list count, the inner count and every relation number moved: the
committed width fell by 10.7 and the tree above it grew by four levels.

Layer `L1` is 1,088 wide: `read_1_*` 0–31, `write_1_*` 32–63, then the fraction tree's 512
`(num, den)` pairs at 64–1,087, the table's first and the 237 pads last. Widths:

```text
L1     1,088      L5        68      L9        6      L11 … L{n+10}    4 each
L2       544      L6        34      L10       4
L3       272      L7        18
L4       136      L8        10
```

so `inner = 2,180 + 4n` — 2,244 at `n = 16`. The two product trees reach one node at `L6` and are
carried as `Linear` copies through `L7`–`L10`; the fraction tree reaches one pair at `L10`.

Relations: **0–1,087** are list 0's leaves — `read_w0`…`read_w24`, `read_anchor`,
`read_pad0`…`read_pad5`, then the write side's twelve-plus-twenty, then `range16_table_num`,
`range16_table_den`, the 274 obligations' `{name}_num` / `{name}_den` pairs in `lookups()` order
at 66–613, and `range16_pad_{i}_num` / `_den` at 614–1,087 — **1,088–1,212** its 125 enforcing
gates in §18.4's order, then **1,213–1,756** list 1, **1,757–2,028** list 2, **2,029–2,164**
list 3, **2,165–2,232** list 4, **2,233–2,266** list 5, **2,267–2,284** list 6,
**2,285–2,294** list 7, **2,295–2,300** list 8, **2,301–2,304** list 9, and halving list `k`
(`10 ≤ k ≤ n + 9`) holds `2,305 + 4(k − 10)` to `2,308 + 4(k − 10)`. The roots are relations
`2,301 + 4n` to `2,304 + 4n`: **2,365–2,368** at `n = 16`.

Each halving list is four gates: the `read_root`-side and `write_root`-side `TreeProduct`s, the
channel's denominator `TreeProduct`, and its numerator `TreeCross`. **The channel's fraction tree
is exempt from the padding-identity clause**, and `checker::check_padding_identity` makes that
exemption by shape: it requires every column the first halving list reads to be exactly 1 except
the operands of a `TreeCross`, because a fraction tree's identity is `(0, 1)` and a padding row
is not idle in a channel — it contributes 274 neutral entries the multiplicity column counts.

**The outputs**, in output-map order: 0 `read_root` and 1 `write_root` at `memory::READ_ROOT` and
`WRITE_ROOT`, read at `verify_shard` step 10a against `memory_roots[p]` for `p` the position of
`(15, shard_index)` in `verifier_core::statement_shards` — **last** in every statement it
appeared in until `EC_ADD` arrived above it, family ids being the statement's order — and each a
factor of `gkr_verify::reconciles` over the whole statement; 2 `range16_num_root` and 3
`range16_den_root`, read at step 9, the failure `Lookup { channel: 1 }` and the check **both**
`num == 0` and `den != 0`, a leaf pair of `(0, 0)` otherwise annihilating the tree.

### 18.7 What fixes each cell

| cell | what fixes it |
| --- | --- |
| `cycle`, `base` | the multiset: the request's mirror write is `T(DELEGATION_MOD_MUL, base, 4·cycle + 3, v)` and this row's teardown read is its only reader (§5's anchor); locally `base_aligned`, `base_in_window` and `addr_w{j}` against the words |
| `live` | `live_boolean`, and every leaf's mask |
| `anchor_value` | **nothing local**: the request's `deleg_write_value` must equal it, and the memory argument is what says so (§26 observation 19) |
| `w{j}_read_ts` | the memory argument alone; the four `gap{j}_*` obligations only hold it below this row's own write |
| word 0's value | the frame's read tuple, `writes_back_w0`, and `selector_rule` against the four selectors |
| `selector{code}` | its booleanity gate, `selector_rule` and `one_modulus_a_live_row` — the three together are exactly "one of the four codes, the one the frame names" |
| `m_limb{k}` | `m_limb{k}_rule`: a literal of `MODULI`, chosen by the selector, which is also its `2^32` bound — this family's one bound that is neither an obligation nor a decomposition |
| `a`, `b` word values | the frame's read tuples, `writes_back_w{j}` against their write values, their own 16+16 obligations, and their `< m` chains |
| `out` word values | `limb{k}`, `out`'s chain and its own obligations: given `m`, `a`, `b` and the bounds, integer division has one answer |
| every `<v>{k}_hi`, `<v>_diff{k}_hi`, `q_limb{k}_hi`, `gap{j}_c{c}`, `carry{k}_c{c}`, `base_low_hi`, `base_room_hi` | **its own two or four obligations and nothing else**: no gate reads any of the 136, so a wrong halfword or chunk breaks no relation and the channel is the only thing that refuses it |
| `q_limb{k}` | `limb{k}`: fifteen equations in eight unknowns over the integers, whose solution is unique once `out < m`; its `2^256` bound by its sixteen obligations |
| `<v>_diff{i}`, `<v>_borrow{i}` | `<v>_canonical{i}`, the borrows' booleanity and the `diff` obligations; `borrow7` by `<v>_below_modulus` |
| `carry{k}` | `limb{k}` and `limb{k+1}`, which the carry joins, and its four obligations |
| `range16_multiplicity` | `trace::build_multiplicities`, and the channel's own root check — no gate reads it |
| the padding row | `check_padding`'s all-zero row and §18.2's gates that hold there, subject to §18.2's last paragraph |

**The suite is row-local at `n = 16`, and since S26c it has to be.**
`crates/checker/tests/mod_mul.rs` builds a column set of eight rows — **one invocation per
selector**, so every modulus the circuit holds is run, plus the `a = 0` corner where the product,
the remainder and every carry are zero and the `(m−1)²` corner that is the widest the frame
admits, and two padding rows — and evaluates each row alone through `checker::violated_relations`
over scratch `gkr::gate_values` computes, exactly as `crates/checker/tests/add_sub.rs` does.
There is **no forward pass and there cannot be**: the family's circuit does not exist below
`2^16`, `family_circuit(MOD_MUL, 8)` being `None`, so a whole-shard pass would be 4.6 GB. One row
of the real circuit is both cheaper and a stronger statement than a pass over a toy height was.
Nothing in the file shares a line with `prover::fill::mod_mul` or with `emulator`'s executor: its
own `U256` over two `u128` halves, its own long division, its own borrow chains and its own
carries, so a circuit that stated anything but `a·b mod m` would reject an honest witness. The
moduli themselves are `constants::mod_mul::MODULI`, which `crates/constants/tests/moduli.rs`
holds to arkworks.

Fourteen tests, of which four are worth knowing about.

`a_limb_above_its_bound_is_refused_by_the_channel_alone` zeroes an honest nonzero `a0_hi`, which
leaves the derived low half equal to the whole limb, and asserts **both** halves of the
re-shape's statement: `assert_every_row_holds` finds not one violated relation, and
`checker::violated_lookups` names `a0_lo_range`. Until S26c the bound was `a_word0`, a gate; it
moved rather than vanished, and this is the test that says which.

`a_result_not_below_the_modulus_is_refused`: `(q − 1, r + m)` satisfies **every** limb equation
and every obligation — it is the same product, decomposed one multiple of `m` differently — and
`out_below_modulus` is the only thing that refuses it. It runs on a BN254 row rather than a
secp256k1 one because `p = 2^256 − 2^32 − 977` leaves no room: `r + p` does not fit eight limbs,
so on that row the forgery cannot even be written down.

`an_operand_not_below_the_modulus_is_refused`: `a = m`, then `b = m`, with the quotient, the
result, the carries and all three chains computed honestly for it — `m·b mod m = 0` with `q = b`,
a perfectly well-formed witness of a claim the circuit must refuse. Nothing is corrupted;
`a_below_modulus` and `b_below_modulus` are the only gates that fail. It is not a hypothetical
shape: `m`'s raw limb pattern is upstream `k256`'s second representation of zero, and the
vendored patch handed it across the frame until S26b made it a refusal
(`delegation.md` §14.4).

`the_shape_is_the_manifests` is the third reading of §18.1's numbers, beside
`crates/constraints/tests/vectors/mod_mul.txt` and this page: the widths, the 26 lists, the 16
halving lists, 2,244 inner, 2,369 relations, the `(125, 54, 71)` enforcing split, 274
obligations, 4 outputs, one virtual table, one channel and 550,391 wire bytes.

Two readings sit outside that suite. `crates/prover/tests/fills.rs` holds the **real** fill to
the same gates — `the_mod_mul_and_ec_add_fills_cover_their_circuits_exactly` is set equality over
addresses less the one multiplicity column, and `every_delegation_fill_satisfies_every_gate`
evaluates the first 32 and last 4 rows of a filled `2^16` shard, which is where a `< m` chain
computed against the wrong modulus or a padding row's chain computed against the shard's would
surface. And `crates/checker/tests/tamper.rs`' `s26_the_mod_mul_witness_and_anchor_are_pinned`
re-proves `guests/mod-mul-ops`' block per twin: the result, the quotient, a carry and the
selector word the call rewrote, each moved as a value **and its halfword together** — shifting
both by `2^16` and `1` leaves the derived low half exactly where it was, so both obligations
still hold and what refuses the twin is a limb equation, the gate that says the multiplication
was performed — plus the control that a padding row's gap chunk is free, and the anchor twins
through the family-parameterized `checker::assert_anchor_twins_refused`, of which this is the
fourth caller.

---

## 19. `SHA256_COMP` — family 16

| | |
| --- | --- |
| id, constant | 16, `constants::family::SHA256_COMP` |
| constructor | `constraints::sha256::artifact(n)` |
| channels | `sha256::channels()`: **`RANGE16`** and **`XOR8`**, in that order |
| fill | the private `prover::fill::sha256_comp` |
| normative spec | `docs/spec/delegation.md` §15 |
| committed | 104 `M`, 520 `W`, 0 `S` — 624 |
| virtual | 4: `V[range16]`, `V[xor8_a]`, `V[xor8_b]`, `V[xor8_out]` |
| obligations | 450: **114** on `RANGE16`, **336** on `XOR8` |
| enforcing gates | 119, all on gate list 0: 75 degree-1, 44 degree-2 |
| outputs | 6 |
| at `n = 18` | depth 28 (10 row-wise + 18 halving), 2,802 inner columns, 2,921 relations, 845,456 wire bytes, 189,988 proof bytes (derived, §1.2) |

**S26e rewrote this circuit**, and nothing of S26c's survives but the frame's
head columns and the anchor. S26c's row was a whole compression: every frame
word and all 64 rounds' working variables as **bits**, 8,216 committed and
16,688 inner columns, which forced `2^8` — 256 compressions a shard,
10,895,760 artifact bytes and about 1.33 MB of proof a shard, **5,186 proof
bytes a compression**. Once the stateless guest's SSZ hashing called it 8,011
times on block 257510, that was 32 shards and 42.5 MB, two thirds of the
block's proof. This is `KECCAK_F`'s S26d trade made a second time (§12.1).

### 19.1 What one row is, and the height

**One row is four rounds and four message-schedule words**, and a compression
is **sixteen consecutive invocations**, glued by the frame being ordinary RAM:
the global memory multiset is what proves call `r`'s written frame is call
`r + 1`'s read one, and the guest's own proven `for r in 0..16` loop
(`guest_sdk::recursion::sha256_comp`) supplies `r`. The feed-forward
`H + working variables` is the caller's, after the sixteenth call.

`DEFAULT_HEIGHTS[SHA256_COMP]` is `2^18`; **16 is the floor and 18 a choice**,
for §12.1's reason: both channels' tables need 16 variables, and a delegation
shard's proof bytes barely move with its height. At `2^18` a shard holds
**16,384 compressions** for 189,988 proof bytes — **11.6 a compression**, a
factor of 447. Its forward pass is 2,802 × 2^18 × 32 = 23.5 GB and its derived
peak about 30 GB (forward pass, committed base, transition 0's first bind). The
proof bytes are measured — an end-to-end proof of `guests/sha256-ops` at
`max_in_flight = 1` gave this shard exactly 189,988, and the whole statement
peaked at 33.1 GB RSS, unattributed to a shard
(`docs/handoff/S26e-sha256-round-and-cycles.md` §4). On block 257510 the family
goes from 32 shards to one.

**The honest price is GKR work per compression.** Sixteen rows of 2,802 inner
columns are 44,832 forward-pass cells a compression where S26c's one row was
16,688 — **2.7×** — and 9,984 committed cells where it was 8,216. The height,
and with it the shard count and the proof bytes, is what that buys.

**The circuit is flat**, as `KECCAK_F`'s is: every relation is an obligation
or a degree-≤2 enforcing gate over base columns, built through
`memory::assemble`, and nothing above gate list 0 is anything but the two
memory product trees, the two channels' fraction trees and the halving phase.

### 19.2 The frame, and what one call does

Ecall `0x0508`, frame base in `a0`, **25 words**, 100 bytes
(`constants::sha256`):

| words | holds | after the call |
| --- | --- | --- |
| 0 (`GROUP_WORD`) | `r`, the round group, `0 ≤ r < 16` | unchanged — `writes_back_w0` |
| 1..9 (`STATE_WORD`) | `a b c d e f g h` | the working variables four rounds on |
| 9..25 (`WINDOW_WORD`) | `W_{4r} … W_{4r+15}` | shifted down four; the last four are the words this call derives |

Call `r` runs rounds `4r … 4r+3` with `W_{4r+k}` = window word `k` and
`K_{4r+k}` from `constants::sha256::ROUND_CONSTANTS`, and derives
`W_{4r+16+m} = σ1(W_{4r+14+m}) + W_{4r+9+m} + σ0(W_{4r+1+m}) + W_{4r+m}` for
`m < 4`, where `W_{4r+14+m}` is derived word `m − 2` once `m ≥ 2`. That is
exactly the schedule the next call's rounds need, so the message schedule
crosses the frame sixteen words at a time and costs the guest nothing. Calls
12–15 derive `W_64 … W_79`, which nothing reads: a uniform row is cheaper than
a row with a mode.

**`0x0505` is retired and burned.** It was S26c's whole-compression call; the
frame changed shape, append-only forbids a second meaning, and the call took
`0x0508`, as `KECCAK_F`'s `0x0501` went to `0x0507` (`ecall-abi.md`).

Over the four rounds the state is two sequences: `A_0 = a`, `A_{−1} = b`,
`A_{−2} = c`, `A_{−3} = d`, and `E` likewise over `e f g h`. Round `k` reads
`A_k … A_{k−3}` and `E_k … E_{k−3}` and writes `A_{k+1}` and `E_{k+1}`, so
after four the frame holds `A_4 … A_1` and `E_4 … E_1`. **Each of the sixteen
values is one `M` column** — `j ≤ 0` a word's read value, `j ≥ 1` a word's
write value (`sha256.rs`' private `a_word` and `e_word`) — so every word a gate
needs is a column and nothing is copied.

### 19.3 Row kinds

| Kind | `live` | Carries | Memory tuples |
| --- | --- | --- | --- |
| an **invocation** | 1 | the requesting cycle, the base, the 25 words read and written, every byte and mask of §19.4, two carries a round and one a schedule word | 26 read and 26 write tuples: the 25 frame words at `(RAM, base + 4j)` and the anchor pair at `(DELEGATION_SHA256_COMP, base)` |
| **padding** | 0 | zeros | none: every leaf is masked by `live` |

**The all-zero row is valid** (`zero_row_valid`), because every constant rides
`live`: `K` is a linear form over the group selectors, and every other gate
constant is lifted onto `LIVE` by the private `Form::gate`. S26c's round gates
carried `K_i` as a bare literal, which no padding row could satisfy, and
`check_padding` caught it; the convention is the fix.

**A padding row is free only where the mask reaches.** Every obligation's
selector is `live`, so a gap chunk, a base halfword or a mask byte is free
there; the frame-value gates are **ungated**, so a byte column on a padding
row is not — its word is 0 and so are its bytes
(`a_padding_row_is_free_only_where_the_mask_reaches`).

### 19.4 The base layer

**`M[0..104]`** is the shared delegation head and frame (`constraints::delegation`):
`M[0] cycle`, `M[1] live`, `M[2] base`, `M[3] anchor_value`, then four
fields a word, `sha256::word(j, field)` = `M[4 + 4j + field]` with fields
`addr`, `read_ts`, `read_value`, `write_value`, `j < 25`.

**`W[0..520]`**, in layout order — `crates/constraints/src/sha256.rs`'
accessors are the authority, and `the_witness_names_are_the_layout` holds the
names to them:

| `W` | Columns | Accessor | What |
| --- | --- | --- | --- |
| 0..50 | `gap{j}_c{c}` | `gap_chunk(j, c)` | each frame read's timestamp gap, two committed chunks; the low part is derived |
| 50..54 | `base_low`, `base_low_hi`, `base_room`, `base_room_hi` | `base_low()` … | `(base − RAM_ORIGIN)/4` and `2^31 − 100 − base`, each with its high halfword |
| 54..70 | `group{r}` | `group_sel(r)` | the one-hot round-group selectors |
| 70..94 | `a{j}_b{b}`, `j` in `m2 … 3` | `a_byte(j, b)` | the bytes of `A_{−2} … A_3` |
| 94..118 | `e{j}_b{b}` | `e_byte(j, b)` | the bytes of `E_{−2} … E_3` |
| 118..142 | `w{i}_b{b}`, `i` in 1, 2, 3, 4, 14, 15 | `w_byte(i, b)` | the window words the schedule's sigmas read |
| 142..150 | `n{m}_b{b}`, `m < 2` | `n_byte(m, b)` | derived words 0 and 1, which `σ1` reads back for words 2 and 3 |
| 150..358 | `r{k}_…`, 52 a round | `round_col(k, Round::…, b)` | §19.5's round blocks |
| 358..514 | `s{m}_…`, 39 a word | `sched_col(m, Sched::…, b)` | §19.5's schedule blocks |
| 514..518 | `w{j}_written_hi`, `j` in 1, 5, 23, 24 | `written_hi(slot)` | the high halfwords of the four written words nothing decomposes: `A_4`, `E_4` and derived words 2 and 3 (`PAIRED_WORDS`) |
| 518..520 | `range16_multiplicity`, `xor8_multiplicity` | | |

`A_{−3}` and `E_{−3}` (`d` and `h`) and `A_4`, `E_4` have no byte columns: they
enter only the sums, never a Boolean operation.

### 19.5 The obligations: the round and the schedule

**There is no bit.** The committed unit is a byte, and every Boolean operation
is one `XOR8` obligation `(e0, x, out)` — `(a, b, a ^ b)` over bytes,
`docs/spec/lookup.md` §14. Membership bounds each of the three positions to
`[0, 256)`, which is the whole bound argument for every byte column. Position 0
may be a literal-weighted linear form with a constant; positions 1 and 2 are
single columns. Three identities make the round cheap:

- **A rotation is linear in bytes and masks.** For a byte `v`, the column
  `m = v ^ (2^s − 1)` pins `lo = v & (2^s − 1) = (v + 2^s − 1 − m)/2` and
  `hi = (v − lo)/2^s`, so byte `j` of `ROTR_{8q+s}(V)` is
  `hi(v_u) + 2^{8−s}·lo(v_{u+1})` with `u = (j + q) mod 4` — a form, not a
  column (private `rotr_byte`). A word rotation `ROTR_s(V)` for `s < 8` is
  `(V − lo_0)/2^s + 2^{32−s}·lo_0`, splitting byte 0 alone (`rotr_word`).
- **The big sigmas nest**: `Σ0(a) = ROTR2(a ^ ROTR11(a ^ ROTR9(a)))` and
  `Σ1(e) = ROTR6(e ^ ROTR5(e ^ ROTR14(e)))`, rotation distributing over XOR.
  Every XOR then has a plain byte column at position 1, and the outer rotation
  is taken on the word, where it costs one mask byte: **17 obligations a
  sigma**, against 20 for three rotations XORed directly.
- **`Ch` and `Maj` are sums**: `Ch = (f + g − (e^f) + (e^g))/2` and
  `Maj = (a + b + c − (c^a^b))/2`, each exact bit by bit, so each is two
  obligations a byte and a linear form over words.

The small sigmas carry a shift, which does not nest, so each commits its
shifted bytes — pinned to their forms by the 28 `s{m}_shr3_b{b}` and
`s{m}_shr10_b{b}` gates, a tuple holding one derived form — and XORs once
against them. `SHR10`'s top byte is 0, so `σ1` commits and XORs three bytes and
reads its fourth straight off `ROTR17(y)`.

**Per round, 52 obligations** (`r{k}_…_xor`): `Σ0` 17 (`bs0_m1` 4, `bs0_y` 4,
`bs0_m3` 4, `bs0_x` 4, `bs0_mx` 1), `Σ1` 17 (`bs1_m6`, `bs1_y`, `bs1_m5`,
`bs1_x` 4 each, `bs1_mx` 1), `Ch` 8 (`ch_ef`, `ch_eg`), `Maj` 8 (`maj_ab`,
`maj_cab`), and the two carries. **Per schedule word, 32** (`s{m}_…_xor`): `σ0`
16 (`ss0_m3`, `ss0_y`, `ss0_m7`, `ss0_z`), `σ1` 15 (`ss1_m2` 4, `ss1_y` 4,
`ss1_m1` 4, `ss1_z` 3), and the carry. A carry `c` is the byte-range tuple
`(0, c, c)`, a table row exactly when `c < 256`, which is what makes every sum
in §19.6 an integer equation. **4 × 52 + 4 × 32 = 336**, under a 512-leaf
fraction tree with 175 to spare; the next obligation past 511 doubles it.

**`RANGE16`, 114**: four a frame gap (`gap{j}_…`, 100 — there is no `gap_w{j}`
gate, the obligations being the bound and the decomposition at once), three
each for `base_low` and `base_room`, and a 16+16 pair for each of the four
`PAIRED_WORDS` (`w{j}_written_hi_range`, `w{j}_written_lo_range`). Under a
128-leaf tree, 13 spare. `check_copowers` holds every copower-scaled column —
each gap's top chunk, `base_low_hi` and `base_room_hi` — to a direct pair under
`live`.

**Every word the family writes is a u32**, the induction every writer in the
VM keeps: a copied word — the group word and the twelve shifted window words —
is a word it read; a computed word with byte columns is bounded by its bytes'
obligations through its encode gate; and the four computed without are
`PAIRED_WORDS`' pairs. The family also **reads** on that induction: `d`, `h`
and the window words only the sums touch have no byte columns, and are u32
because whoever wrote them bounded them — which is what keeps every sum in
§19.6 below `p`.

### 19.6 Gate list 0's 119 enforcing gates

| Gates | Count | Degree | What |
| --- | --- | --- | --- |
| `live_boolean`, `addr_w{j}`, `base_aligned`, `base_in_window` | 28 | 2 | the shared frame gates (`delegation::frame_gates_range16`) |
| `group{r}_boolean` | 16 | 2 | |
| `group_rule` | 1 | 1 | the group word `= Σ r·group_r` |
| `one_group_a_live_row` | 1 | 1 | `Σ group_r = live` |
| `writes_back_w0` | 1 | 1 | the group word is written back unchanged |
| `a{j}_decode`/`_encode`, `e{j}_…`, `j` in `m2 … 3` | 12 | 1 | each word with bytes `= Σ 2^{8b}·byte_b`: a read word decoded, a written one encoded |
| `w{i}_decode`, `n{m}_encode` | 8 | 1 | the window words and derived words the sigmas read |
| `w{i}_shift`, `i < 12` | 12 | 1 | window word `i` written `=` window word `i + 4` read |
| `r{k}_a`, `r{k}_e` | 8 | 1 | `A_{k+1} + 2^32·carry_a = T1 + Σ0 + Maj`, `E_{k+1} + 2^32·carry_e = A_{k−3} + T1`, with `T1 = E_{k−3} + Σ1 + Ch + K_{4r+k} + W_{4r+k}` |
| `s{m}_sum` | 4 | 1 | the derived word `+ 2^32·carry_w = σ1 + W_{4r+9+m} + σ0 + W_{4r+m}` |
| `s{m}_shr3_b{b}`, `s{m}_shr10_b{b}` | 28 | 1 | the small sigmas' committed shift bytes |

**`one_group_a_live_row` is load-bearing**, for `keccak::one_round_a_live_row`'s
reason: the codes are `0..16`, so two selectors can sum to a third group's code
(`1 + 2 = 3`), satisfy `group_rule`, and add two round constants into one round.
`K_{4r+k}` itself is `Σ_r K_{4r+k}·group_r`, a degree-1 form, which is why no
gate carries a bare constant (§19.3). **Every round and schedule gate is
degree 1** — a rotation, `Ch`, `Maj` and `K` are all linear forms — so the
circuit's 44 degree-2 gates are the frame's 28 and the 16 selector booleanities,
and nothing else.

**What a gate does not read, the channel alone pins.** No gate reads the big
sigmas' inner `y` bytes and first masks, `a ^ b`, or `σ0`'s inner `y` and
`ROTR7` mask; a wrong value there breaks no relation and is refused by the
obligation that writes it (`a_stage_no_gate_reads_is_refused_by_the_channel_alone`).
The stages a sum reads are refused twice, by the sum and by their obligation
(`a_stage_a_sum_reads_is_refused_twice`). The round **is** its obligations; the
gates only tie them to the frame.

### 19.7 The trees, the layers and the outputs

Two memory trees of 32 leaves a side — 25 frame words, the anchor and **6
pads** — and two fraction trees, `RANGE16`'s of 128 leaves and `XOR8`'s of 512.
Gate list 0 writes `L1`, **1,344** columns: 64 memory leaves, the 4 table
numerators and denominators, 450 lookup numerators, 450 lookup row
denominators and 376 pad-fraction columns. Nine row-wise lists reduce them —
`L2 … L10` are 672, 336, 168, 84, 42, 22, 12, 8 and 6 wide, the memory trees
finishing at list 5 and `RANGE16`'s at list 7 and copying themselves up — and
`n` halving lists of 6 follow: `inner = 2,694 + 6n`, **2,790 at `n = 16`** and
**2,802 at `n = 18`**. The outputs are the two memory roots, then each
channel's `(num, den)` in channel order: six. §0.5's census is this section by
shape.

### 19.8 Witness rows, and the check that holds them

`prover::fill::sha256_comp` builds one row per invocation from the frame's
read and written words through the private `sha256_row`, which recomputes the
four rounds and four schedule words, **refuses a group word at or above 16**
and checks the frame's writes against its own computation — so a fill that
disagreed with the executor panics rather than proving. The executor's half is
`emulator::sha256_call`, and `emulator::sha256_frame` refuses the same group
word as `EmuError::DelegationFrame`: a group past 15 has no selector, and an
executor that answered it would hand the prover a row no witness satisfies.

`crates/checker/tests/sha256.rs` is the second description: its own `u32`
call with every intermediate, its own witness builder, and evaluation of every
row against the relations, `violated_lookups` and its own `XOR8` reading.
`the_call_is_the_executors` holds that call to `emulator::sha256_call`, and
`sixteen_calls_are_one_compression` holds sixteen of them to FIPS 180-4's
`"abc"` digest. The honest set is that compression's sixteen chained rows plus
four corners; the controls are one per gate family and one per obligation
class; `the_fill_satisfies_every_gate_and_every_obligation` runs the prover's
own fill over `guests/sha256-ops`' real execution. `crates/constants/tests/
sha256.rs` re-derives `IV` and `ROUND_CONSTANTS` from the primes' roots.

## 20. `EC_ADD` — family 17

### 20.1 Header

`family_circuit(17, n)` is `ec_add::artifact(n)` with `ec_add::channels()`, which is **one
`RANGE16` channel** — the first a delegation family has ever carried
(`delegation.md` §10.3). Like `MOD_MUL` and `FR_ARITH` it is built by `memory::assemble`:
every constraint it makes fits as an enforcing gate on gate list 0, so above the leaves it is
two product trees and one fraction tree and nothing else. Normative spec: `delegation.md`
§4, §5 and **§16**. Fill: `prover::family_fill(17)`, the private `fill::ec_add`. Ecall
`0x0506`, anchor space `address_space::DELEGATION_EC_ADD` = 9.

**1,420 committed columns (392 `M`, 1,028 `W`, no `S`) and one virtual table, `V[range16]`.**
Gate list 0 writes 4,352 columns — 128 leaves a side of the two memory trees plus the
`RANGE16` tree's 2,048 fraction pairs — and holds **637 enforcing gates (131 degree-1, 506
degree-2)**. **1,110 obligations**, all `RANGE16`, 4 outputs. At its `n = 16` there are 28
gate lists (12 row-wise and 16 halving), the top is `L28`, and the circuit has 8,772 inner
columns and 9,409 relations, 2,350,670 bytes of wire form —
`crates/constraints/tests/vectors/ec_add.txt`, which is the SHA-256 and shape line CI diffs,
the artifact itself being 2.4 MB. **None of the counts before that sentence depends on `n`**
except the inner and relation totals, which are `8,708 + 4n` and `9,345 + 4n`: a height adds
halving lists and nothing else, one node per output each
(`crates/checker/tests/ec_add.rs`' `a_height_moves_only_the_halving_layers`).

`artifact` panics unless the column counts are `MEMORY_COLUMNS` and `WITNESS_COLUMNS`, there
is no setup column, `channels()` is exactly one, the obligation count is `lookups()`' own, no
group writes the selector word, and each group's three output words are eight-word runs that
do not overlap (`ec_add::check_shape`). It also panics on every refusal of `validate`, of
`memory::check_memory`, of `lookup::check_discharge` and of `lookup::check_copowers`, and on
either of the two derivations below failing.

**Two derivations run before the artifact is built, and they read one table.** `CEILINGS`
gives each of the nine slots' four operand ceilings as multiples of `m`;
`the_offset_covers_every_slot` requires `OFFSET_MULTIPLE` to cover the largest `a·b + c·d`,
and `the_carry_offset_covers_every_slot` recomputes the carry's fixed point from the same
row. **They were two separate arguments until S26c derived only the second and shipped an
offset the first refutes** (§20.4).

**One row is one third of one complete point addition**, on one of two curves — secp256k1 or
BN254 G1 — that frame word 0 selects together with the group. `GROUPS` is 3, so one addition
is three invocations in ascending group order, glued by the frame and not by a bus
(`delegation.md` §16.2).

**The height is `2^16`, and it is forced rather than chosen.** `RANGE16`'s table needs sixteen
variables, Mercury needs an even count, and `2^18` is four times worse; `family_circuit`'s
derived minimum-height guard returns `None` below 16 (`it_is_the_one_delegation_family_with_a_channel`).
One shard is a computed **20.5 GB** — **18.3 GB** of forward pass (the twelve row-wise
layers' 8,708 columns at `2^16` rows and 32 bytes; the sixteen halving layers add 8.4 MB
between them), **0.7 GB** of committed base (1,255 small-type columns at 4 bytes and 165 `Fr`
ones at 32), and **1.5 GB** of transition 0's first bind, a half-height `Fr` table over 1,420
columns. That is above an execution shard's ~11 GB and above `MOD_MUL`'s 5.1 GB at the same
height, but below `KECCAK_F`'s ~60 GB at its `2^18` (§12.1), so **this is the second-largest
delegation shard peak in a block** and no longer the peak-setting one; the lever that remains is the
group count, five groups of two reductions being about two-thirds the width at two more
invocations an addition. `docs/handoff/S26c-sha256-ec.md` records the deferred run's measured
figure against that estimate.

**This family has no §0.5 row at `n = 20`.** §0.5 counts gate shapes over one circuit at
`n = 20`, which this family is never built at in practice; the rows below give its shape
counts at its own `n = 16` instead, and they sum to 9,409.

### 20.2 Row kinds

Two, and neither is an instruction: **this family is invoked, not decoded**. It claims no pc,
`program::lookup_tuple(17)` is empty, and it is in a `VmConfig` exactly when the linked binary
declares it. It is not in `constants::family::CYCLE_OWNING`.

| row kind | `live` | what the row holds | what it adds to the multiset |
| --- | --- | --- | --- |
| an **invocation** | 1 | the requesting cycle, the frame base, the 97 words read and written, the six selectors and the curve constants they name, the twelve frame values' `< m` chains, and three slots' operands, quotients, results, carries and result chains | 98 read tuples and 98 write tuples: the 97 frame words at `(RAM, base + 4j)`, and the anchor pair at `(DELEGATION_EC_ADD, base)` |
| **padding** | 0 | every committed cell 0 **as the honest fill writes it** | nothing: all 196 real leaves collapse to 1, and 60 are pads that are literally 1 |

Three things hold the all-zero row and are worth spelling out. `one_code_a_live_row` forces
every selector to 0 there, so `m_limb{k}_rule` and `b3_rule` force the modulus limbs and `b3`
to 0 — which is what lets the fifteen chains' `canonical` gates be **ungated** and still hold.
Every operand pin then reads `operand = 0`, because every product in it carries a selector.
And `carry_terms` puts `live` on the offset, so a padding row's carry is
`Σ carry{r}_{c} − 2^46·0`, not `−2^46`.

**The padding row is all-zero because the fill writes it so, not because the gates force it.**
With `m = 0` and every selector 0 the limb identity reduces to a relation among `out`, the
carries and nothing else, and every range obligation is switched off by its `live` selector,
so a padding row could legally carry unbounded cells. It is harmless — the row requests
nothing, pairs with no anchor, writes no register, and its leaves are the product's identity —
but a test asserting "a padding row's columns are zero" is asserting a property of the fill.
`a_padding_row_holds_and_a_live_one_next_to_it_does_too` asserts the direction that matters:
the all-zero row satisfies every gate of a circuit whose identity carries a `1024·m²` offset
and whose carries carry a `2^46` one.

### 20.3 The base layer

**Too wide to enumerate one column a row**, as §12's is: a live row is 1,420 committed cells.
What follows is every address *group*, which is how the circuit itself names them — a fill, a
checker and a tamper twin reach a column through `ec_add::word`, `gap_chunk`, `word_high`,
`selector`, `m_limb`, `b3`, `bzz3_limb`, `byz3_limb`, `bxx9_limb`, `diff`, `diff_hi`,
`borrow`, `operand`, `out_limb`, `out_hi`, `q_limb`, `q_hi`, `carry`, `carry_chunk`,
`out_diff`, `out_diff_hi`, `out_borrow` and `multiplicity_column`, and never through a number.

**Memory-argument columns, `M[0..392]`** — filled by `fill::ec_add` from the archive's
delegation buffer; committed in `PublicInputs::memory_commitments`, absorbed at G8 before the
memory challenges.

| address | name | what it is |
| --- | --- | --- |
| `M[0..4]` | `cycle`, `live`, `base`, `anchor_value` | as §18.3 and §12.3: the requesting cycle, the row's one mask, the `a0` the request passed, and the teardown's value, which is **free on both sides** |
| `M[4 + 4j + f]` | `w{j}_addr`, `w{j}_read_ts`, `w{j}_read_value`, `w{j}_write_value` | frame word `j`, `j < 97`. Word 0 is the selector, 1–8 `X1`, 9–16 `Y1`, 17–24 `Z1`, 25–48 `X2`/`Y2`/`Z2`, 49–72 `xx`/`yy`/`zz`, 73–96 `m4`/`m5`/`m6`, eight little-endian 32-bit limbs a value (`constants::ec_add`'s `*_WORD`) |

**Group 2 writes its results over `X1`, `Y1` and `Z1`**, which groups 0 and 1 have by then
finished reading. That is what keeps the frame at 97 words rather than 121, and it is why
`EcAddFrame::result` reads the first three lanes.

**Witness columns, `W[0..1028]`** — all filled by `fill::ec_add` except the last; committed in
`ShardProof::witness_commitments`, absorbed at S3, with `g` drawn after them at S4.

| address | name | what it is |
| --- | --- | --- |
| `W[2j + c]`, `j < 97` | `gap{j}_c{c}` | chunk `c` of frame word `j`'s timestamp gap, weight `2^{16(c+1)}`; the low sixteen bits are **derived**, not committed. 194 columns |
| `W[194..198]` | `base_low`, `base_low_hi`, `base_room`, `base_room_hi` | `(base − RAM_ORIGIN)/4` and `2^31 − 388 − base`, each with its high halfword |
| `W[198 + j]` | `word{j}_hi` | frame word `j`'s read value's high halfword — its 32-bit bound, and **every** word has one, the selector included |
| `W[295..301]` | `selector{code}` | the six (curve, group) selectors, in `ec_add::CODES` order: codes 1, 2, 3 secp256k1's three groups, 4, 5, 6 BN254 G1's |
| `W[301..309]` | `m_limb{k}` | limb `k` of the selected curve's modulus — a witness column, and the only place `m` exists |
| `W[309]` | `b3` | the selected curve's `b3 = 3b`: 21 for secp256k1's `b = 7`, 9 for BN254's `b = 3`. The curve's `a` is 0 on both and never appears |
| `W[310..334]` | `bzz3_{k}`, `byz3_{k}`, `bxx9_{k}` | the three curve-scaled helpers, eight limbs each |
| `W[334 + 24v + …]` | `{name}_diff{i}`, `{name}_diff{i}_hi`, `{name}_borrow{i}` | frame value `v`'s `< m` chain, `v < 12` in `VALUES` order — `x1`, `y1`, `z1`, `x2`, `y2`, `z2`, `xx`, `yy`, `zz`, `m4`, `m5`, `m6`. 288 columns |
| `W[622 + 135r + …]` | `slot{r}_{a,b,c,d}{k}` | slot `r`'s four operands, eight limbs each, `r < 3`: 32 columns |
| … `+32`, `+40` | `out{r}_{k}`, `out{r}_{k}_hi` | the slot's reduced result and its halfwords |
| … `+48`, `+57` | `q{r}_{i}`, `q{r}_{i}_hi` | the **nine**-limb quotient and its halfwords — the one value in the row the execution did not record |
| … `+66`, `+81` | `carry{r}_{c}`, `carry{r}_{c}_c{j}` | the fifteen signed carries as unsigned `c + 2^46`, and two `RANGE16` chunks each |
| … `+111` | `out{r}_diff{i}`, `out{r}_diff{i}_hi`, `out{r}_borrow{i}` | the result's own `< m` chain |
| `W[1027]` | `range16_multiplicity` | the channel's one multiplicity column, **last in the witness subtree**, filled by `trace::build_multiplicities` after the fill and read by no gate |

**The three helpers are pinned limb-wise, and this is easy to misread.** `bzz3_{k}` is
`b3 · zz_k` — the product of a column and one limb, not a limb of a reduced value. So the
three are **loose limb vectors**: `|bzz3_k| < 21·2^32`, `byz3` is signed, and none of them is
below `m` or below `2^32`. They exist because `b3` is a column, so `b3` times a frame limb
inside a product's operand would be degree 3. The fill commits them as `Fr` columns for that
reason, and `fill::ec_add`'s comment says so.

**Where each value reads from.** Every operand limb is a frame word's `read_value`; every
result limb is the `write_value` of the word the group writes. That is the whole of what makes
the call a function: the guest's frame is what it *passed*, and the results are what the
invocation *wrote*.

### 20.4 The gates

| group | count | degree | what it says |
| --- | --- | --- | --- |
| `live_boolean` | 1 | 2 | §4's, shared with the other five delegation families |
| `addr_w{j}` | 97 | 2 | word `j` is at `base + 4j`. Degree 2 because it carries `live` as a factor — on a padding row `addr` and `base` are 0 and `4j` is not |
| `base_aligned`, `base_in_window` | 2 | 2 | `base = RAM_ORIGIN + 4·base_low`, and `base + 388 ≤ 2^31` through `base_room`. **There is no `gap_w{j}` gate**: the gap's obligations are the bound and the decomposition at once (§20.5) |
| `selector{code}_boolean` | 6 | 2 | each of the six selectors is a bit |
| `selector_rule` | 1 | 1 | `w0_read_value = Σ code_i·s_i` |
| `one_code_a_live_row` | 1 | 1 | `Σ s_i = live` |
| `m_limb{k}_rule` | 8 | 1 | `m_k = Σ CURVE_MODULI[CODE_CURVE[i]][k]·s_i`, the two curves' literals |
| `b3_rule` | 1 | 1 | `b3 = Σ CURVE_B3[CODE_CURVE[i]]·s_i` |
| `bzz3_{k}_rule`, `byz3_{k}_rule`, `bxx9_{k}_rule` | 24 | 2 | `bzz3_k = b3·zz_k`, `byz3_k = b3·(m5_k − yy_k − zz_k)`, `bxx9_k = 3·b3·xx_k` |
| `{v}_borrow{i}_boolean`, `out{r}_borrow{i}_boolean` | 120 | 2 | the fifteen chains' borrow bits |
| `{v}_canonical{i}`, `out{r}_canonical{i}` | 120 | 1 | `v_i − m_i − b_{i−1} + 2^32·b_i = d_i`, **ungated** |
| `{v}_below_modulus`, `out{r}_below_modulus` | 15 | 2 | `enable·(1 − b_7) = 0`: `enable` is the sum of the selectors of the groups that read the value, and `live` for a result |
| `operand{r}_{which}_{k}_rule` | 96 | 2 | the operand column equals `Σ_g g_sel·(group g's expression at limb k)` |
| **`slot{r}_limb{k}`, `k < 16`** | 48 | 2 | the schoolbook identity, position by position |
| `writes_back_w{j}` | 97 | 2 | `write_j − read_j − Σ g_sel·(out[r][k] − read_j) = 0` over the one `(group, slot, limb)` triple that writes word `j`, if any |

**The forty-eight limb equations are the circuit.** With `P_k = Σ_{i+j=k} (A_i B_j + C_i D_j)`,
`O_k = 1024·Σ_{i+j=k} m_i m_j` and `S_k = Σ_{i+j=k} q_i m_j`, gate `slot{r}_limb{k}` is

```text
P_k + O_k − S_k − out_k + c_{k−1} − 2^32·c_k = 0
```

where `out_k` is absent past limb 7, `c_{−1}` is absent, and `c_15` is absent — which is the
closing condition. Weight the sixteen equations by `2^{32k}` and sum: the carries telescope
and what is left is `A·B + C·D + 1024·m² − q·m − out = c_15·2^{480}`, so **the absence of a
sixteenth carry column is the identity**. Each gate is one `Quadratic`: `A_i·B_j`, `C_i·D_j`,
`m_i·m_j` and `q_i·m_j` are all pairs of committed columns, so the degree is 2 and never 3.

**One shape for all nine slots, and `D` carries the sign.** Group 2's slot 0 is
`xy·ym − byz3·xz`, and a per-group sign on a product's coefficient is **not expressible** — a
coefficient is one literal or one challenge — so the minus rides `D`, which is `xx + zz − m6`
where the other two slots' is `m6 − xx − zz`. Groups 0 and 1 leave `C` and `D` empty, so their
second product is zero; the operand pin still exists for those 48 columns and forces them to 0.

**The operands are committed columns pinned to bounded linear combinations, and the pin IS the
bound.** Every term of an operand's sum is a frame limb below `2^32` or a helper limb below
`21·2^32`, under a small literal coefficient, so `operand{r}_{which}_{k}_rule` establishes the
magnitude at the same time as the value and **no operand needs a range check of its own**.
That is what keeps the witness at 1,028 columns: 96 operand limbs bounded by bit decomposition
would be 3,072 columns and 3,072 booleanity gates, and bounded by `RANGE16` would be 96 more
committed halfwords and 192 more obligations in a fraction tree that is already the deepest of
the three (§20.6). `a_wrong_operand_is_refused_by_its_own_pin` is the twin, and it names
`operand0_0_0_rule` and not a product — which is the point.

**Why the equation over `Fr` is the equation over ℤ.** The widest single term of any position
is `2^32·c` with `c` below `2^47`, so under `2^79`; a position has at most 38 terms, so its
sum is under `2^85`, against `p`'s `2^254`. No limb equation can wrap, and there is no
modular-arithmetic loophole to argue about.

**`OFFSET_MULTIPLE` was 256 and is 1024, and the difference is a completeness bug S26c
shipped.** The offset keeps the quotient unsigned: `A·B + C·D` is as low as
`−(a·b + c·d)·m²`, each product minimised with one factor at its positive ceiling and the
other at its negative one. The binding slot is group 2's **`Y3`**, not its `X3`: `yp·ym`
with `yp ≤ 22m` and `ym ≥ −22m` reaches `−484 m²`, and `bxx9·xz` with `bxx9 ≤ 63m` and
`xz ≥ −3m` a further `−189 m²`, for **`−673 m²`**. `X3` reaches `−255 m²` — `66 + 189` —
which is exactly why 256 looked derived and was not. At 256 the honest quotient of a `Y3` row
below `−256 m²` is negative, `q_limb` cannot hold it, and the row is **unprovable**; `zz`
above about `0.76m` is enough on its own, roughly a quarter of random invocations. **Nothing
but an honest witness against the gates can find it**: `emulator::ec_add_frame` computes the
right answer, `guests/ec-ops` agrees with its own software Algorithm 7, every shape test
passes, and only the prover fails — intermittently, hours into a block proof.
`CARRY_OFFSET_BITS` moved with it, 45 → 46, because the same products bound the carry's width:
the widest position is `8·(673 + 1024)·2^64 ≈ 2^78` and the carry's fixed point `2^46`. It
read 44 when the offset was guessed, 45 when the positions were derived, and 46 once the
offset had to cover `−673 m²`. Both are now computed from `CEILINGS` at construction, and
`the_carry_offset_covers_every_slot_is_computed` runs the second as a test besides.

**`below_modulus` said `b_7 = enable` and means `enable·(1 − b_7) = 0`, and the first made
every row of the family unprovable.** The chain telescopes to `v − m + 2^256·b_7 = D` with `D`
below `2^256`, so `b_7 = 1` says the subtraction borrowed out and `v < m`. `b_7 = enable`
also forces `b_7 = 0` where `enable` is 0 — which asserts that a value a row does *not* read
is at or above the modulus. Every lane is such a value: `EcAddFrame::of` zeroes the six
intermediates, and a group-2 row's `X1..Z2` are ordinary coordinates. **The chain's sixteen
`canonical` gates are ungated**, so a non-reading value still owes a real chain, and the
prover's fill — written to match the wrong gate — filled those chains with zeros, which
satisfy the canonical gates only where `v = m`. Nothing in the executor, the guests or the
shape tests could see either half. What found it is an honest witness evaluated against the
gates: `crates/checker/tests/ec_add.rs` for the circuit and
`crates/prover/tests/fills.rs`' `every_delegation_fill_satisfies_every_gate` for the fill,
which exists for this reason and says so in its doc comment.

**Which chain is soundness and which is totality.** A slot's `out < m` is the **reduction**:
without it a prover answers `out + m` with the quotient one lower and every limb equation
holds over the integers just as well. A frame value's `< m` is **totality** — it is what
bounds the honest quotient below nine limbs, so every frame the circuit accepts is one an
honest prover can fill. `emulator::ec_add_frame` refuses an unreduced operand earlier and by
name, six messages keyed to the group's reads, and a selector naming no (curve, group) pair
before that.

**Why one modulus a live row is load-bearing twice.** It is the one-hotness that makes the six
selectors a partition, and with codes 1–6 `selector_rule` cannot see a two-selector forgery:
`1 + 3 = 4`, so a row claiming secp256k1's groups 0 and 2 spells BN254's group 0's word. It is
also the **only** thing bounding `m`'s limbs and `b3` below `2^32`, neither having a bit
decomposition: two selectors at once would give `m_0` above `2^32` and put the integer
argument above out of reach. `two_selectors_at_once_are_refused` is the twin.

### 20.5 The lookups and the channel

One channel, `RANGE16` = channel 1, table `V[range16]`, multiplicity `W[1027]`. The tuple is
**one** expression wide, so it weights its column by the literal 1 and reads `g` and no power
of `β` at all. Every obligation's selector is `LIVE`.

| obligation | count | selector | tuple | shape |
| --- | --- | --- | --- | --- |
| `gap{j}_c0_range`, `gap{j}_c1_range` | 194 | `live` | `gap{j}_c{c}` | direct: each chunk below `2^16` |
| `gap{j}_top_scaled` | 97 | `live` | `2^10 · gap{j}_c1` | scaled: the top chunk below `2^6` |
| `gap{j}_lo_range` | 97 | `live` | `4·cycle − w{j}_read_ts − 1 − 2^16·c0 − 2^32·c1` | the derived low sixteen bits |
| `base_low_c0_range`, `base_low_top_scaled`, `base_low_lo_range` | 3 | `live` | `base_low_hi`, `2^3·base_low_hi`, `base_low − 2^16·base_low_hi` | `[0, 2^29)` |
| `base_room_c0_range`, `base_room_top_scaled`, `base_room_lo_range` | 3 | `live` | as above at `2^31` | `[0, 2^31)` |
| `word{j}_hi_range`, `word{j}_lo_range` | 194 | `live` | `word{j}_hi`, `w{j}_read_value − 2^16·word{j}_hi` | every frame word below `2^32` |
| `{v}_diff{i}_hi_range`, `{v}_diff{i}_lo_range` | 192 | `live` | 16+16 over `diff(v, i)` | the twelve chains' difference limbs |
| `out{r}_{k}_hi_range`, `out{r}_{k}_lo_range` | 48 | `live` | 16+16 over `out_limb(r, k)` | each result limb below `2^32` |
| `out{r}_diff{k}_hi_range`, `out{r}_diff{k}_lo_range` | 48 | `live` | 16+16 over `out_diff(r, k)` | the three result chains |
| `q{r}_{i}_hi_range`, `q{r}_{i}_lo_range` | 54 | `live` | 16+16 over `q_limb(r, i)` | nine quotient limbs a slot |
| `carry{r}_{c}_c0_range`, `_c1_range`, `_top_scaled`, `_lo_range` | 180 | `live` | two chunks, `2·carry{r}_{c}_c1`, and the derived low half | each carry's unsigned value below `2^47` |

**1,110 obligations.** The 38-bit timestamp gap is three chunks and not a `TIMESTAMP`
obligation, because that channel's `BITS` is 19 and its table needs `2^20` rows, above this
family's `2^16` (`delegation.md` §9, §10.3). `TIMESTAMP` would be the natural
channel and does not fit; `RANGE16` at three chunks a gap is exact at `2^38`, the maximum
being `(2^16 − 1)(1 + 2^16) + 2^32(2^6 − 1) = 2^38 − 1`.

**A 16+16 pair is one committed column and two obligations, and that is the whole reason the
channel is worth carrying.** A 32-bit bound by bit decomposition is 32 columns and 32
booleanity gates; a 38-bit gap is 38. Without the channel this family's frame alone is 3,686
gap-bit columns against 194 chunk columns, and 24 more 32-bit values want bounding besides.

**The scaled obligation alone bounds nothing**, and `lookup::check_copowers` is what says so:
`2^{16−r}` is a unit in `Fr`, so an unbounded value sweeps a coset almost none of whose
members is small. It is the top chunk's own **direct** obligation under the **same** selector
that establishes the premise — S18's fix, and `ec_add::scaled_columns` lists all 144 scaled
columns with `LIVE` beside each: the 97 gap tops, `base_low_hi`, `base_room_hi`, and the 45
carry tops.

**One multiplicity column, and no gate reads it.** `trace::build_multiplicities` counts each
`RANGE16` table row's occurrences over the 1,110 gated tuples of every live row and appends
the column after the fill; `prover::fill::ec_add` does not write it, which is why
`crates/prover/tests/fills.rs` passes `WITNESS_COLUMNS − channels().len()` to `covers`. It has
to exist because `artifact.committed()` names it.

### 20.6 The trees, the inner layers and the outputs

Three trees. The two memory product trees take `d::leaves(DELEGATION_EC_ADD, 97)`: 97 frame
words plus one anchor leaf a side, **98 real leaves padded to 128**, so each side carries 30
`read_pad{i}` / `write_pad{i}` leaves that are literally 1. The read side's leaves consume the
write each frame word names, then the anchor **teardown**
`T(space, base, 4·cycle + 3, anchor_value)`; the write side's write at `4·cycle + 0`, then the
anchor **answer** `T(space, base, 0, 0)`, stamped 0 and valued 0. The `RANGE16` fraction tree
takes 1,110 obligations plus its table fraction, **1,111 leaves padded to 2,048**, so 937 pad
fractions. `R = 11`, the fraction tree setting it alone, and the depth is `N = 1 + 11 + n`.

Layer `L1` is 4,352 wide: `read_1_*` 0–127, `write_1_*` 128–255, then the fraction tree's
2,048 `(num, den)` pairs at 256–4,351, the table's first and the 937 pads last. Widths:

```text
L1     4,352      L5       272      L9       18      L13 … L{n+12}    4 each
L2     2,176      L6       136      L10      10
L3     1,088      L7        68      L11       6
L4       544      L8        34      L12       4
```

so `inner = 8,708 + 4n` — 8,772 at `n = 16`. The two product trees reach one node at `L8` and
are carried as `Linear` copies through `L9`–`L12`; the fraction tree reaches one pair at `L12`.

Relations: **0–4,351** are list 0's leaves, **4,352–4,988** its 637 enforcing gates in
`artifact`'s own order — 4,352 `live_boolean`, 4,353–4,449 `addr_w0`…`addr_w96`, 4,450
`base_aligned`, 4,451 `base_in_window`, 4,452–4,468 the selector block, 4,469–4,492 the
helpers interleaved by limb, 4,493–4,747 the fifteen chains at 17 relations each in `VALUES`
order then `out0`, `out1`, `out2`, 4,748–4,843 the operand pins, 4,844–4,891 the forty-eight
limb equations, 4,892–4,988 the write-backs. Then **4,989–7,164** list 1, **7,165–8,252** list
2, **8,253–8,796** list 3, **8,797–9,068** list 4, **9,069–9,204** list 5, **9,205–9,272**
list 6, **9,273–9,306** list 7, **9,307–9,324** list 8, **9,325–9,334** list 9,
**9,335–9,340** list 10, **9,341–9,344** list 11, and halving list `k`
(`12 ≤ k ≤ n + 11`) holds `9,345 + 4(k − 12)` to `9,348 + 4(k − 12)`. The roots are relations
`9,341 + 4n` to `9,344 + 4n`: **9,405–9,408** at `n = 16`.

Each halving list is four gates: `read_root`-side and `write_root`-side `TreeProduct`s, the
channel's denominator `TreeProduct`, and its numerator `TreeCross`.

**The outputs**, in output-map order: 0 `read_root` and 1 `write_root` at `memory::READ_ROOT`
and `WRITE_ROOT`, read at `verify_shard` step 10a against `memory_roots[p]` for `p` the
position of `(17, shard_index)` in `verifier_core::statement_shards` — **last** in every
statement it appears in, family ids being the statement's order; 2 `range16_num_root` and 3
`range16_den_root`, read at step 9, the failure `Lookup { channel: 1 }` and the check **both**
`num == 0` and `den != 0`.

### 20.7 Witness rows

**There is no row table here and there cannot usefully be one**: a live row is 1,420 committed
cells, 1,110 of which exist only to be range-checked. What stands in its place is a chain of
four independent readings, and the chain is what §12.9's is for `KECCAK_F`.

1. **`crates/checker/tests/ec_add.rs`** builds honest rows of the real `2^16` circuit and
   evaluates each **row-locally** through `checker::violated_relations` over scratch that
   `gkr::gate_values` computes — a whole-shard forward pass being impossible at a family whose
   circuit exists only at `2^16`. Its **operand structure** is transcribed (a witness builder
   has to know what the circuit expects in a committed operand column) but its **answer** is
   not: `expected` computes each group's three results from Algorithm 7 over ordinary 256-bit
   modular arithmetic — schoolbook multiplication, shift-and-subtract division — sharing no
   line with the emulator or the fill, and `the_reductions_are_the_group_law` holds the `out`
   that falls out of the limb identity's long division equal to it, slot for slot.
   `the_three_invocations_are_one_addition` then runs Algorithm 7 end to end in one expression
   and holds the third row's results to it, which is the check that **the split into three
   invocations is the same function as the whole**.
2. **`crates/prover/tests/fills.rs`** holds the real fill to the same gates:
   `the_mod_mul_and_ec_add_fills_cover_their_circuits_exactly` is set equality over addresses,
   and `every_delegation_fill_satisfies_every_gate` evaluates the first 32 and last 4 rows of a
   filled shard — which is what caught the `below_modulus` fill bug (§20.4).
3. **`crates/emulator/tests/guests.rs`**: `guests/ec-ops` checks every delegated addition
   against its own Algorithm 7 over its own long division, limb for limb, and the resulting
   point against `k256` and `ark-bn254` by cross-multiplication, including `P + P`, `P + O`,
   `O + O` and `P + (−P)`; it exits 20, and a disagreement between its two implementations
   exits 251. `the_new_families_are_invoked_the_pinned_number_of_times` pins **81**
   invocations for `ec-ops` (27 point operations, three groups each) and **39** for
   `mod-mul-ops`, which names no shim and reaches the family through the vendored `k256`
   alone — which is what makes that second count the projective patch's only test.
4. **`crates/checker/tests/ec_add.rs`' fifteen negative controls**, each corrupting one cell of
   an otherwise honest witness or supplying an honest witness for a claim the circuit must
   refuse, and naming the relation that catches it.

An honest live row, in words:

| column group | value |
| --- | --- |
| `cycle`, `live`, `base`, `anchor_value` | the requesting cycle; 1; the frame pointer, 4-aligned, in `[RAM_ORIGIN, 2^31 − 388]`; 0 |
| `w{j}_addr`, `w{j}_read_ts` | `base + 4j`, and the last write to that word from the log |
| `w{j}_read_value`, `w{j}_write_value` | the 97 words before and after the group |
| `gap{j}_c{c}` | bits `[16(c+1), 16(c+2))` of `4·cycle − w{j}_read_ts − 1` |
| `base_low`, `base_room`, and their halfwords | `(base − RAM_ORIGIN)/4` and `2^31 − 388 − base` |
| `word{j}_hi` | `w{j}_read_value >> 16` |
| `selector{code}` | 1 on the frame's code, 0 on the other five |
| `m_limb{k}`, `b3` | the selected curve's modulus limbs and `3b` |
| `bzz3_{k}`, `byz3_{k}`, `bxx9_{k}` | `b3·zz_k`, `b3·(m5_k − yy_k − zz_k)`, `3·b3·xx_k` — **signed and loose** |
| `{v}_diff{i}`, `{v}_borrow{i}` | the honest chain of `v − m`, computed for **all twelve values on every row** |
| `slot{r}_{a,b,c,d}{k}` | the group's expression at limb `k`, signed and loose |
| `out{r}_{k}`, `q{r}_{i}`, `carry{r}_{c}` | the reduction, its nine-limb quotient, and `carry + 2^46` |
| `out{r}_diff{i}`, `out{r}_borrow{i}` | the result's own chain |
| `range16_multiplicity` | `trace`'s count; 0 on a row the table does not hold |

and a padding row is 0 in every one of them. The suite's honest set is **seven live rows and
one padding row**: both curves' three groups over one random point pair each — where each
group's written frame is the next group's read frame, so the three rows of a curve are one
real addition and not three unrelated frames — plus a seventh at the **widest** operands group
2 admits, secp256k1's group 2 with every intermediate at `m − 1`, which is the row the carry
bound is sized for and which a bound off by one bit refuses.

### 20.8 What fixes each cell

| cell | what fixes it |
| --- | --- |
| `cycle`, `base` | the multiset: the request's mirror write is `T(DELEGATION_EC_ADD, base, 4·cycle + 3, v)` and this row's teardown read is its only reader (§5's anchor); locally `base_aligned` and `base_in_window`, and `addr_w{j}` against the words |
| `live` | `live_boolean`, and every leaf's mask |
| `anchor_value` | **nothing local**: the request's `deleg_write_value` must equal it, and the memory argument is what says so |
| `w{j}_read_ts` | the memory argument alone; `gap{j}_*` only holds it below this row's own write |
| word 0's value | the frame's read tuple, `writes_back_w0`, and `selector_rule` against the six selectors |
| `selector{code}` | its booleanity gate, `selector_rule` and `one_code_a_live_row` — the three together are exactly "one of the six codes, the one the frame names" |
| `m_limb{k}`, `b3` | `m_limb{k}_rule` and `b3_rule`: a literal of `CURVE_MODULI` and of `CURVE_B3`, chosen by the selector, which is also their `2^32` bound |
| the twelve values' words | the frame's read tuples, `writes_back_w{j}`, their own `word{j}` obligations, and their `< m` chains where the row's group reads them |
| every `w{j}_write_value` | `writes_back_w{j}`: the result of the one slot that writes word `j`, bounded by that slot's `out{r}_{k}` obligations, or the read value, bounded by `word{j}` |
| `bzz3_{k}`, `byz3_{k}`, `bxx9_{k}` | their degree-2 pins, which are also their bounds |
| `slot{r}_{a,b,c,d}{k}` | `operand{r}_{which}_{k}_rule` alone — the pin is the bound, and no obligation reads an operand |
| `out{r}_{k}` | `slot{r}_limb{k}` and `out{r}`'s chain: given `m`, the operands and the bounds, integer division has one answer |
| `q{r}_{i}` | `slot{r}_limb{k}`: sixteen equations in nine unknowns over the integers, whose solution is unique once `out < m` |
| `carry{r}_{c}` | `slot{r}_limb{k}` and `slot{r}_limb{k+1}`, which the carry joins, and its four obligations |
| every `_diff`, `_borrow` | the chain's `canonical{i}` gates, the borrows' booleanity, and the `diff` obligations; the last borrow by `below_modulus` where a group reads the value |
| `range16_multiplicity` | `trace::build_multiplicities`, and the channel's own root check — no gate reads it |
| the padding row | `check_padding`'s all-zero row and §20.2's gates that hold there, subject to §20.2's last paragraph |

The fifteen negative controls read that table backwards, and four are worth knowing about.
`a_wrong_result_limb_is_refused` names `out0_canonical0` rather than `slot0_limb0` because
**two** gates see a result limb and the chain comes first in relation order — that the identity
also catches it is what `a_wrong_quotient_limb_is_refused` shows, the quotient being a value
only the identity reads. `a_wrong_curve_constant_is_refused` swaps `b3 = 21` for `9`, which is
a correct addition **on the wrong curve** and which nothing else in the row would notice.
`an_unreduced_frame_value_is_refused_on_the_group_that_reads_it` clears `x1`'s last borrow on a
group-0 row, and has to be a group-0 or group-1 row, the conclusion being gated.
`a_frame_word_above_its_bound_is_refused_by_the_channel_alone` is the one place the two kinds
of refusal are told apart: a 32-bit bound is an obligation and not a relation, so
`violated_relations` must name no `*_range` and `violated_lookups` must name the word.

**No anchor twin is called for this family, deliberately.** `checker::assert_anchor_twins_refused`
is `constraints::delegation`'s one mechanism, built identically for all six base families and
already proved refused at block level over four of them in `crates/checker/tests/tamper.rs` —
`MOD_MUL` included, which also carries a lookup channel, so even that combination is not new.
A fifth replay would be the same mutation set at another re-proof in the slowest deferred
suite, which the root `CLAUDE.md`'s test rule exists to refuse.

---

## 21. `FIELD_WINDOWS` — family 18

### 21.1 Header

`recursion_circuit(18, n)` is `memory::field_window_artifact(n)` with no channels, and
`family_circuit(18, n)` is `None` at every `n`: **the recursion registry holds this family and
the base registry does not** (`recursion.md` §1.2). One window of the **field memory**,
`address_space::FIELD` = 10, whose cells hold whole `Fr` elements and which no instruction
reaches (`recursion.md` §2.1). Window `w` is cells `[h·w, h·(w + 1))`, the windows are
consecutive from cell 0, and shard `i` is window `i` (`verifier_core::shard_window`), so the
statement carries a count and no window list. Spec: `recursion.md` §2.2; `memory.md` §3 is the
window machinery it inherits. Fill: `prover::family_fill(18)`, the private
`fill::field_window`, which writes row `y` from `trace::MemoryState::field_cell(h·w + y)`, and
`(0, 0)` for a cell no access reached. Two committed columns, one virtual table, two unmasked
leaves, no enforcing gate, no lookup, no channel, two outputs. At `n = 20`, its default
(`family::DEFAULT_HEIGHTS`): 21 gate lists, top `L21`, 42 inner columns and relations, 2,758
bytes — the shape line `crates/constraints/tests/vectors/recursion.txt` pins beside the
artifact's SHA-256, `b19670d8…5fe0f4`. At `n = 12`, where `crates/checker/tests/recursion.rs`
fills it, 13 lists, top `L13`, 26 of each and 1,894 bytes; at `n = 16`, the window height the
deferred `crates/prover/tests/field_ops.rs` gives it, 17 lists, top `L17`, 34 of each and 2,326
bytes.

**It is in a `VmConfig` exactly when the program declares a field family, and its presence is
the recursion format.** `program::decode_program` lists it when the linked binary declares any
of `program::FIELD_DELEGATIONS` — `FR_OP`, `P2_FIELD`, `FIELD_IO` and `FQ_OP` — and
`VmConfig::is_recursion` is `height(FIELD_WINDOWS).is_some()` and nothing else: no wire form
carries a format (`recursion.md` §1.1), so this family's entry is what sends a key's load rule
and the prover's registration to `recursion_circuit` (`VmConfig::circuit`). Its height is the
program's, `ProgramParams::heights[18]`, and nothing pins it. `verifier_core::window_height`
reads `INIT_TEARDOWN`, `ZERO_WINDOWS`, `ADVICE_WINDOWS` and the two public families and not
this one, so any menu height may carry it, and identity binds it through `VM_CONFIG` as it binds
every family's. Its shard count is `MemoryState::field_windows(h)`: `⌊top / h⌋ + 1` over the
highest cell the execution touched, 0 when it touched none. Step 2's `check_memory_windows`
refuses `count·h > 2^32` as `Statement("the field windows do not fit the 2^32 cells")`, a cell
being a `u32`. A count too small cannot be proved at all: a cell above the last window has no
init tuple, and its accesses cannot balance (`recursion.md` §2.2). The family owns no cycle
(`family::CYCLE_OWNING[18]` is `false`).

**`ZERO_WINDOWS`' construction at a stride of one cell, and not its bytes.**
`field_window_artifact(n)` and `zero_window_artifact(n)` are the private
`memory::zero_window(n, stride)` at strides 1 and `WORD_BYTES` = 4. They have the same columns,
names, virtual table, halving lists, relation numbers, outputs and padding contract, and differ
in one thing: how many `(α_addr, V[row])` terms each leaf carries, one here and four there. That
is six terms fewer, three a leaf, and each leaf is stored twice, in gate list 0 and in the flat
relation list. At 37 bytes a term — a 34-byte coefficient (tag, slot, a zero `Fr`) and a 3-byte
address — that is 444 bytes at every `n`: 2,758 against `zero_window_artifact(20)`'s 3,202, and
1,894 against `PUBLIC_OUTPUT`'s 2,338 at `n = 12`. So where `PUBLIC_OUTPUT` takes
`ZERO_WINDOWS`' artifact byte for byte (§16.1), this family takes its constructor and not its
artifact. Neither artifact names an address space: `RAM`'s 2 and `FIELD`'s 10 both enter
through slot 5 alone (§21.3).

### 21.2 Columns

| address | name | Rust | descriptive name | row `y` of window `w` holds | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `teardown_ts` | `PolyAddress::Memory(0)` | Last write time | the write timestamp of the last access to cell `h·w + y`, `4·c + Δ` for the cycle `c` whose invocation made it; 0 if no access reached the cell | leaf `teardown` |
| `M[1]` | `teardown_value` | `PolyAddress::Memory(1)` | Final cell | the value that access wrote, any `Fr`; 0 if no access reached the cell | leaf `teardown` |
| `V[row]` | `row` | `VirtualKind::RowIndex`, wire tag 0 | Row index | `y` | both leaves |

Both are committed in `PublicInputs::memory_commitments`, which G8 absorbs before the memory
challenges are squeezed, and **as one stack**: this family's presence puts the statement in the
recursion format, whose shards commit stacks (`recursion.md` §1.3). `VmConfig::stack_vars` is 2
at every menu height, two `M` columns and no `W` needing two stack variables, so `M[0]` and
`M[1]` are slots 0 and 1 of a four-slot stack whose slots 2 and 3 are zero. The shard proof
carries no witness commitment, and its opening is that one stack at `u ‖ r`, after two
`STACK_CHALLENGE` squeezes. There is no `W` and no `S`: `program::setup_commitments(18)` is
empty, so identity commits an empty list for the family, as for `ZERO_WINDOWS`.
`fill::field_window` writes both columns `Fr`-backed (`fill::fr_column`) whatever their values.
A field value is a whole field element and not a `u32` (`recursion.md` §2.1), which is also why
a field access is not a `MemoryEventLog` event and why the fill reads `MemoryState`'s field
table and not `build_init_teardown_columns`.

### 21.3 Leaves and layers

| `L1` | relation | node | positional | named |
| --- | --- | --- | --- | --- |
| 0 | 0 | `teardown` (read side) | `α_addr·V[row] + α_ts·M[0] + α_val·M[1] + WC` | `T(FIELD, h·w + row, teardown_ts, teardown_value)` |
| 1 | 1 | `init` (write side) | `α_addr·V[row] + WC` | `T(FIELD, h·w + row, 0, 0)` |

Here `WC = γ_M + 10 + α_addr·h·w`, slot 5 at window `w`, the shard's index. The `10` is
`address_space::FIELD`, and `h·w` is the window's first cell: `2^n·w`, where a RAM window's
first address is `4·2^n·w`. `gkr_verify::field_window_challenges` derives it, and
`verifier_core::shard_challenges` calls that for this family alone, on both sides: the prover's
`gkr_part` and `verify_shard_local`. A recursion verifier's tape derives it a third time, in
`tape::shard_tape`'s `window(address_space::FIELD, 1)`. **The address space is in no
artifact**, here or in any RAM window. What separates cell `x` from RAM word `x` is the `10`
against the `2` in that one derived slot, while the field families' own leaves carry `FIELD` as
a literal (`recursion.md` §3–§6). Both leaves are `Linear`, unmasked and degree 1, with one
`α_addr·V[row]` term each where §11.3's carry four, because the stride is one cell a row. There
is no `V[ram_live]`: every row of every field window is a cell, cell 0 included, and window 0
supplies cell 0's init tuple. Code: the private `memory::stride_tuple(1, Some(M[0]), M[1])` for
the read side, and for the write side `memory::zero_window`'s inline `Linear`, which puts
`stride` copies of `(α_addr, V[row])` on the window constant and no value term.

Halving list `k`, for `1 ≤ k ≤ n`, writes `L{k+1}` (`n − k` variables), exactly as §10.3:

| `L{k+1}` | relation | node | shape |
| --- | --- | --- | --- |
| 0 | `2k` | `read_{k+1}_0` | `TreeProduct { L{k}[0] }` |
| 1 | `2k + 1` | `write_{k+1}_0` | `TreeProduct { L{k}[1] }` |

In the last list, `k = n`, the two nodes are `read_root` and `write_root`.

| output | address, `n = 20` | node | value | verifier |
| --- | --- | --- | --- | --- |
| 0 | `L{21}[0]` | `read_root`, relation 40 | the product of every row's teardown leaf | step 10a: must equal `PublicInputs::memory_roots[p][0]`, `p` the position of `(18, i)` in `verifier_core::statement_shards`. The group order is `INIT_TEARDOWN`, `ZERO_WINDOWS`, then every other family ascending, so this family's shards follow every family below 18 and precede `FR_OP`'s. A factor of `reconciles` |
| 1 | `L{21}[1]` | `write_root`, relation 41 | the product of every row's init leaf | step 10a: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |

**There is no step 10c**: `verify_shard_local`'s `public_value` match names `PUBLIC_INPUT` and
`PUBLIC_OUTPUT` and falls through to `None` for family 18. The shard claims the trivial time
window `[0, 2^38)` (`TRIVIAL_TS_WINDOW`), because the family is neither cycle-owning nor a
delegation family, so `check_ts_windows` asks nothing of it. The field memory has no boundary
either: registers and the pc are the whole boundary (`memory.md` §4.2), so every field tuple
balances between the field families' leaves and these windows' roots inside `reconciles`' one
product.

### 21.4 Rows

A window shard has no padding: every row is a cell. `zero_row_valid` is `true` and the padding
contract is `M[0] = 0, M[1] = 0`. Here that all-zero row is an ordinary row, a cell no access
reached, and its two leaves cancel.

| row | `teardown_ts` | `teardown_value` | leaves |
| --- | --- | --- | --- |
| a cell no access reached | 0 | 0 | both `T(FIELD, h·w + y, 0, 0)`: they cancel |
| a cell some access reached, by a read or a write (a read writes back what it read) | the last access's write timestamp `t = 4·c + Δ` | the value it wrote, `v`: any `Fr`, 0 for a cell only read | `T(FIELD, h·w + y, t, v)` read against `T(FIELD, h·w + y, 0, 0)` written |

`guests/field-ops`' cell 0 is the second row with `v = 0`: it is read and never written, so the
read re-stamps the cell and keeps its zero, which `crates/emulator/tests/guests.rs` asserts.

Nothing in this circuit checks a row alone. There is no enforcing gate to check one with, and no
obligation bounds either column. Both are fixed by the memory argument alone: the multiset
forces a window's teardown column to be each cell's last `(ts, value)` (`memory.md` §4.2), over
the chain the field accesses' own gap checks build, two `RANGE16` chunks a read as for a frame
word (`recursion.md` §2.1). `teardown_value` needs no bound, because a cell holds an `Fr`.
`teardown_ts` needs none, because the final read balances only against the chain's highest
write (`memory.md` §4.2).

**What holds this in CI**:

- `crates/constraints/tests/recursion.rs`'
  `the_recursion_families_build_in_the_recursion_registry_alone` builds the circuit at `2^20`,
  which runs `validate` and `check_memory`. It asserts `zero_row_valid` and that
  `family_circuit(18, 20)` is `None`.
- `recursion.txt`'s first line is rewritten by `cargo run -p kat-gen -- recursion`, a default
  group, and CI diffs it.
- `crates/checker/tests/recursion.rs`' `the_field_families_hold_and_the_field_memory_balances`
  fills a `2^12` field window from `guests/field-ops`' real trace with `prover::family_fill`.
  It evaluates both leaves on all 4,096 rows through the engine's kernel, under
  `field_window_challenges` at window 0. It then multiplies every field leaf that the four
  field families' live rows evaluate, and holds the reads times the teardowns equal to the
  writes times the inits. So a slot, an offset or a stride on which the circuits and the
  executor disagree leaves a tuple with no partner.
- `crates/emulator/tests/guests.rs`' `field_ops_checks_itself_under_the_recursion_ecalls`
  asserts that the guest's field memory is one window at `2^20`.

The proof half is `crates/prover/tests/field_ops.rs`' `the_recursion_format_proves_and_verifies`,
`#[ignore]`d for size. It proves one field window shard, verifies it through `verify_block` and
replays its tape against `verify_shard_local`.

**Two things no suite reaches.** `field-ops` touches fewer than 4,096 cells, so it is one window
at every height a suite gives the family, and every run above is window 0. Whatever depends on
`w` is therefore exercised only where it is 0: slot 5's `α_addr·h·w`, in
`field_window_challenges` and in the tape, and the fill's first cell `h·w`. The stride inside the
artifact is held, by every row from 1 up of the checker's window; the stride in the window's
first cell is not. And `check_memory_windows`' cell bound has no negative control.

---

## 22. `FR_OP` — family 19

### 22.1 Header

| | |
| --- | --- |
| id, constant | 19, `constants::family::FR_OP` |
| registry | `constraints::recursion_circuit(19, n)` and nothing else: `family_circuit(19, n)` is `None` at every `n` |
| constructor | `constraints::fr_op::artifact(n)` |
| channels | `fr_op::channels()`: **`RANGE16`**, table `V[range16]`, multiplicity `W[30]` |
| fill | the private `prover::fill::fr_op` |
| normative spec | `docs/spec/recursion.md` §3, with §1.2, §1.4 and §2; `docs/spec/delegation.md` §4 and §5 for the frame and the anchor |
| ecall, spaces | `0x0509` (`ecall::PRECOMPILE_FR_OP`); anchor space `address_space::DELEGATION_FR_OP` = 11; cells in `address_space::FIELD` = 10 |
| committed | 31 `M`, 31 `W`, 0 `S` — 62 |
| virtual | 1: `V[range16]` |
| gate list 0 | 144 producing columns — 8 memory leaves a side, no pad, and 64 fraction pairs — and 44 enforcing gates (9 degree-1, 35 degree-2) |
| obligations | 36, all `RANGE16` |
| outputs | 4 |
| at `n = 20` | depth 27 (7 row-wise + 20 halving), top `L27`, 370 inner columns, 414 relations, 89,741 wire bytes |

`recursion_circuit(19, n)` is `fr_op::artifact(n)` with `fr_op::channels()`, one `RANGE16`
channel. **Only the recursion registry holds it** (`recursion.md` §1.2): its arm in
`constraints::circuit` is `f::FR_OP if recursion`, so `family_circuit(19, n)` is `None` at every
height, and `crates/constraints/tests/recursion.rs`'
`the_recursion_families_build_in_the_recursion_registry_alone` asserts both halves at the default
height. A verifying key reaches it through `VmConfig::circuit`, which takes `recursion_circuit`
exactly when the config holds `FIELD_WINDOWS`; declaring `FR_OP` is what puts `FIELD_WINDOWS`
there (`program::FIELD_DELEGATIONS`), so a program that calls this family is in the recursion
format by construction. Like `MOD_MUL`, `EC_ADD` and `FR_ARITH` it is built by `memory::assemble`:
every constraint is an enforcing gate on gate list 0, and above the leaves there are two product
trees, one fraction tree and nothing else.

**None of the counts in the table depends on `n`** but its last row's: the depth, the inner and
the relation totals are `7 + n`, `290 + 4n` and `334 + 4n`, a height adding one halving list of
four nodes and nothing else, and the wire bytes grow with it — this page gives them at `n = 20`
only. `crates/constraints/tests/vectors/recursion.txt` pins the `n = 20` artifact by digest, as
the six base delegation families are pinned (§1.2):
`FR_OP 20 31 31 27 370 414 4 89741 b3cf7d6c…d27a596f` — `n`, `M`, `W`, gate lists, inner columns,
relations, outputs, bytes and SHA-256. `cargo run -p kat-gen -- recursion` writes the line and
`recursion` is a default group, so CI regenerates and diffs it; unlike the six lines of the
`delegation` group, no kat-gen unit test holds it to its constructor. This section was read from a
`checker dump` of those 89,741 bytes, whose SHA-256 is the committed one.

`artifact` panics unless `lookup::check_copowers` accepts its ten scaled columns (§22.6) and the
widths are `fr_op::MEMORY_COLUMNS` = 31 and `fr_op::WITNESS_COLUMNS` = 31; `memory::assemble`
before it panics on every refusal of `validate`, of `memory::check_memory` and, the family
declaring a channel, of `lookup::check_discharge`. **There is no `check_shape`**: unlike
the six base delegation families, nothing asserts the obligation count or a gate by name where
the artifact is built.

**The height is `2^20`, a choice above a floor of `2^16`.** `RANGE16`'s table needs sixteen
variables, so §1.1's derived guard makes `recursion_circuit(19, n)` `Some` for `16 ≤ n ≤ 30` and
`None` below. `DEFAULT_HEIGHTS[FR_OP]` is `2^20`, "a million field operations a shard", and
`recursion.md` §8.3 measures one leaf over block 257510's first 32 base shards at 312,984 `FR_OP`
calls, one `2^20` shard. The circuit is narrow enough for the height: its seven row-wise layers'
290 columns at `2^20` rows and 32 bytes are about 9.7 GB of forward pass — computed as §18.1
computes its figures, not measured. **The suites build it at `2^16`**:
`crates/checker/tests/recursion.rs` evaluates rows of `recursion_circuit(19, 16)`, and the deferred
`crates/prover/tests/field_ops.rs` proves `guests/field-ops`' block with the family at `2^16`.

**Stacked commitments.** In the recursion format a shard commits its `M` columns and its `W`
columns as stacks (`recursion.md` §1.3). `VmConfig::stack_vars` gives this artifact
`σ = min(6, 24 − n)` — six being the smallest even `σ` with `2^σ ≥ 31` — so at `n = 20` each
phase's 31 columns are two stacks of sixteen, and at the suites' `n = 16` one stack of 64. §1.2's
`proof_bytes` is the base format's layout, one commitment a column, so this page gives no
proof-byte figure for the family.

**One row is one field operation**, `ops/row = 1`, over up to three cells of the field memory,
and the frame `[op, d, a, b]` is **read-only**: four RAM words the guest wrote — an operation code
and three cell numbers, the last of which `IMM` and `SHL` read as an integer instead — written
back unchanged. The result goes to a field cell and never to RAM. The request that pairs with the
row, an `ADD_SUB` row of the recursion format, leaves `a0` at `base + 16` rather than 0
(`recursion.md` §1.4); that is that circuit's `deleg_a0_rule`, which
`crates/checker/tests/add_sub.rs`' `a_recursion_request_advances_a0_past_its_frame` holds, and
nothing in this circuit reads `a0`. Its callers are `verifier_core::tape`, which compiles a
shard's checks into straight-line runs of `FR_OP`, `P2_FIELD` and `FIELD_IO` calls over absolute
cells (`recursion.md` §7), and the fold's MSM templates (`recursion.md` §8.3).

**Its §0.5 counts are at `n = 20`**, its default: 107 `Linear`, 77 `Product`, 150 `Quadratic`, 60
`TreeProduct` (3 a halving list) and 20 `TreeCross` (1 a halving list), which sum to 414.

### 22.2 Row kinds

**Invoked, not decoded**: the family claims no pc, `program::lookup_tuple(19)` is empty, it owns
no cycle (`CYCLE_OWNING` is `false` for it), and it is in a `VmConfig` exactly when the linked
binary declares it, through its `.rodata.apogee.delegations.fr_op` record. A row is live or
padding; there is no no-op kind. On a live row exactly one op selector is set, and its code is
frame word 0.

| op | code | selector | `a_live` | `b_live` | `d_live` | `x` | what the row states | field accesses |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `MUL` | 1 | `op1`, `W[18]` | 1 | 1 | 1 | `b` | `d′ = prod = a·b` | 3 |
| `ADD` | 2 | `op2`, `W[19]` | 1 | 1 | 1 | 0 | `d′ = a + b` | 3 |
| `SUB` | 3 | `op3`, `W[20]` | 1 | 1 | 1 | 0 | `d′ = a − b` | 3 |
| `MAC` | 4 | `op4`, `W[21]` | 1 | 1 | 1 | `b` | `d′ = d + prod` — the one op whose gate reads `d`'s old value | 3 |
| `INV` | 5 | `op5`, `W[22]` | 1 | 0 | 1 | `d′` | `a·d′ = 1 − z`: `d′ = a⁻¹`, and 0 at `a = 0` | 2 |
| `EQ` | 6 | `op6`, `W[23]` | 1 | 1 | 0 | 0 | `a = b`, or the row has no witness; writes nothing | 2 |
| `IMM` | 7 | `op7`, `W[24]` | 0 | 0 | 1 | 0 | `d′ = w3`, frame word 3 read as an integer | 1 |
| `SHL` | 8 | `op8`, `W[25]` | 1 | 0 | 1 | 0 | `d′ = 2^32·a + w3` | 2 |
| `DIGIT` | 9 | `op9`, `W[26]` | 1 | 1 | 1 | 0 | `a = d′ + 2^8·b′` with `d′ < 2^8`, writing `b` and `d` | 3 |
| padding | — | all 0 | 0 | 0 | 0 | 0 | nothing | 0 |

Every live row adds five read and five write tuples besides its field accesses: the four frame
words at `(RAM, base + 4j)`, read at their own timestamps and written back at `4·cycle + 0`, and
the anchor pair at `(DELEGATION_FR_OP, base)` — the teardown read at `4·cycle + 3` and the answer,
written at timestamp 0 with value 0. Each field access is one read and one write at
`(FIELD, cell)`: `a` at `4·cycle + 0`, `b` at `+ 1`, `d` at `+ 2`. A masked-off access's two leaves
are the product's identity, so a live row adds 8, 7 or 6 tuples a side. A padding row adds none:
its 16 leaves are all 1.

**Every aliasing is legal because the slots are distinct** (`recursion.md` §3,
`execution-trace.md` §3). The three field accesses take Δ 0, 1 and 2, the frame's RAM words also
take Δ 0 but in another space, and the anchor takes Δ 3 in its own; so a cell named twice in one
row is read, written back and read again at the next slot. `guests/field-ops` makes the cases on
purpose: `MUL 1, 1, 1` reads cell 1 as `a`, as `b` after `a`'s write-back and as `d` after `b`'s,
and writes 49 at Δ 2; `DIGIT 12, 11, 11` reads one cell as `a` and as `b` and writes the rest back
into it; `EQ 0, 1, 1` compares a cell with itself. An access whose read consumes the same row's
previous slot has a gap of 0, which its obligations admit.

**Not provable**, and refused by the executor first: an op word outside 1–9
(`EmuError::DelegationFrame`, "the op is not one FR_OP answers"); an `EQ` whose cells differ (the
same error, "EQ's two cells hold different values"); a frame base that is misaligned or puts the
frame outside RAM (`Misaligned`, `OutOfBounds`). A cell no `FIELD_WINDOWS` window covers has no
init tuple, so a read of it cannot balance (`recursion.md` §2.2); no gate says so.

**The padding row.** With `live = 0`, `one_op_a_live_row` and the nine booleanity gates force
every selector to 0; the three mask rules then force every mask to 0, `x_rule` and `prod_rule`
give `x = prod = 0`, and `z_only_inv` gives `z = 0`. `op_word` and `writes_back_w{j}` are
ungated, so the op word reads 0 and every frame word writes back what it read; `b_kept` makes
`b′ = b`. Nothing else is forced: every other cell is free on a padding row and is 0 because the
fill writes it so. `zero_row_valid` is `true` and the padding contract is the all-zero row.

### 22.3 The base layer

**`M`, 31 columns** — `constraints::delegation`'s head and frame over four words, then the three
accesses. Filled by `fill::fr_op`: the head and the frame through `recursion_frame`, which is
`delegation_frame_range16`, and each access through `access_columns`, which writes zeros where
the row does not make the access (`trace::AccessColumns`). Committed in
`PublicInputs::memory_commitments`, as stacks, and absorbed at G8 before the memory challenges.

| `PolyAddress` | name | Rust | what the honest fill writes | read by |
| --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `delegation::CYCLE` | the requesting cycle | `read_anchor`'s timestamp, the seven write leaves but `write_anchor`, the seven `*_lo_range` obligations — **no gate** |
| `M[1]` | `live` | `delegation::LIVE` | 1 on an invocation | the ten frame and anchor leaves (mask), the 22 frame and base obligations (selector), `live_boolean`, `addr_w{j}`, `base_aligned`, `base_in_window`, `one_op_a_live_row` |
| `M[2]` | `base` | `delegation::BASE` | the frame base the request passed in `a0` | `read_anchor`, `write_anchor`, `addr_w{j}`, `base_aligned`, `base_in_window` |
| `M[3]` | `anchor_value` | `delegation::ANCHOR_VALUE` | 0 | `read_anchor` alone |
| `M[4 + 4j]` | `w{j}_addr` | `delegation::word(j, WORD_ADDR)` | `base + 4j` | `read_w{j}`, `write_w{j}`, `addr_w{j}` |
| `M[5 + 4j]` | `w{j}_read_ts` | `word(j, WORD_READ_TS)` | the timestamp of the write the read consumed | `read_w{j}`, `gap{j}_lo_range` — **no gate** |
| `M[6]` | `w0_read_value` | `word(0, WORD_READ_VALUE)` | the op code | `read_w0`, `writes_back_w0`, `op_word` |
| `M[10]` | `w1_read_value` | `word(1, WORD_READ_VALUE)` | `d`'s cell | `read_w1`, `writes_back_w1`, and the address of `read_d` and `write_d` |
| `M[14]` | `w2_read_value` | `word(2, WORD_READ_VALUE)` | `a`'s cell | `read_w2`, `writes_back_w2`, and the address of `read_a` and `write_a` |
| `M[18]` | `w3_read_value` | `word(3, WORD_READ_VALUE)` | `b`'s cell, or the integer `IMM` and `SHL` read | `read_w3`, `writes_back_w3`, the address of `read_b` and `write_b`, `imm_rule`, `shl_rule` |
| `M[7 + 4j]` | `w{j}_write_value` | `word(j, WORD_WRITE_VALUE)` | the word read, unchanged | `write_w{j}`, `writes_back_w{j}` |
| `M[20]` | `a_live` | `fr_op::A_LIVE` | 1 where the op reads `a`: every op but `IMM` | `read_a`, `write_a` (mask), `gap_a_*` (selector), `a_live_boolean`, `a_live_rule` |
| `M[21]` | `a_read_ts` | `fr_op::A_READ_TS` | when `a`'s cell was last written | `read_a`, `gap_a_lo_range` — **no gate** |
| `M[22]` | `a` | `fr_op::A` | `a`'s value — the read value **and** the written one | `read_a`, `write_a`, `prod_rule`, `add_rule`, `sub_rule`, `eq_rule`, `shl_rule`, `digit_rule`, `z_kills_a` |
| `M[23]` | `b_live` | `fr_op::B_LIVE` | 1 on `MUL`, `ADD`, `SUB`, `MAC`, `EQ`, `DIGIT` | `read_b`, `write_b` (mask), `gap_b_*` (selector), `b_live_boolean`, `b_live_rule` |
| `M[24]` | `b_read_ts` | `fr_op::B_READ_TS` | when `b`'s cell was last written | `read_b`, `gap_b_lo_range` — **no gate** |
| `M[25]` | `b` | `fr_op::B` | `b`'s value before the row | `read_b`, `x_rule`, `add_rule`, `sub_rule`, `eq_rule`, `b_kept` |
| `M[26]` | `b_new` | `fr_op::B_NEW` | `b`'s value after it: `DIGIT`'s rest, and `b` on every other op | `write_b`, `digit_rule`, `b_kept` |
| `M[27]` | `d_live` | `fr_op::D_LIVE` | 1 on every op but `EQ` | `read_d`, `write_d` (mask), `gap_d_*` (selector), `d_live_boolean`, `d_live_rule` |
| `M[28]` | `d_read_ts` | `fr_op::D_READ_TS` | when `d`'s cell was last written | `read_d`, `gap_d_lo_range` — **no gate** |
| `M[29]` | `d` | `fr_op::D` | `d`'s value before the row | `read_d`, `mac_rule` |
| `M[30]` | `d_new` | `fr_op::D_NEW` | the result | `write_d`, `x_rule`, `mul_rule`, `add_rule`, `sub_rule`, `mac_rule`, `imm_rule`, `shl_rule`, `digit_rule`, `z_kills_d`, `digit_range`, `digit_scaled` |

**`W`, 31 columns**, in layout order — all filled by `fill::fr_op` but the last. Committed in
`ShardProof::witness_commitments`, as stacks, absorbed at S3, with `g` drawn after them at S4.

| `PolyAddress` | name | Rust | what the honest fill writes | read by |
| --- | --- | --- | --- | --- |
| `W[2j + c]`, `j < 4`, `c < 2` | `gap{j}_c{c}` | — (`fill::recursion_chunk`) | chunk `c` of `4·cycle − w{j}_read_ts − 1`, weight `2^{16(c+1)}` | `gap{j}_c{c}_range`, `gap{j}_lo_range`, and at `c = 1` `gap{j}_top_scaled` — **no gate** |
| `W[8]` | `base_low` | — | `(base − RAM_ORIGIN)/4` | `base_aligned`, `base_low_lo_range` |
| `W[9]` | `base_low_hi` | — | its high halfword | the three `base_low_*` obligations — **no gate** |
| `W[10]` | `base_room` | — | `2^31 − 16 − base` | `base_in_window`, `base_room_lo_range` |
| `W[11]` | `base_room_hi` | — | its high halfword | the three `base_room_*` obligations — **no gate** |
| `W[12 + 2q + c]`, `q` = `a`, `b`, `d` | `gap_{q}_c{c}` | `fr_op::gap_chunk(q, c)` | chunk `c` of `4·cycle + Δ_q − read_ts − 1` where the row makes the access, 0 where it does not | the access's four obligations — **no gate** |
| `W[18 + i]`, `i < 9` | `op{i+1}` | `fr_op::selector(i)` | 1 on the row's own op, in `constants::fr_op::OPS` order | `op{c}_boolean`, `one_op_a_live_row`, `op_word`, each mask rule that names the op, and the op's own gate; `op5` also `x_rule` and `z_only_inv`, `op1` and `op4` `x_rule`, `op9` `b_kept` and the two digit obligations' selector |
| `W[27]` | `x` | `fr_op::X` | `b` on `MUL` and `MAC`, `d′` on `INV`, 0 on every other op | `x_rule`, `prod_rule` |
| `W[28]` | `prod` | `fr_op::PROD` | `a·x` | `prod_rule`, `mul_rule`, `mac_rule`, `inv_rule` |
| `W[29]` | `z` | `fr_op::Z` | 1 exactly on an `INV` row whose `a` is 0 | `inv_rule`, `z_boolean`, `z_kills_a`, `z_kills_d`, `z_only_inv` |
| `W[30]` | `mult_range16` | `fr_op::MULTIPLICITY` | `trace::build_multiplicities`' count, appended after the fill | `range16_table_num` — **no gate** |

**`S`: none**, the channel's table being a closed form.

The frame's own `W` columns, `W[0..12]`, have no accessor in `constraints::fr_op`: they are
`delegation::read_only_frame_range16`'s, the layout `delegation::frame_witness_range16(4) = 12`
names, and the fill reaches the chunks through its private `recursion_chunk`.

**The cells are frame words, so a row has no address column of its own.** `a`'s cell is
`w2_read_value`, `b`'s `w3_read_value` and `d`'s `w1_read_value`, and each field leaf's address
operand is that `M` column. No gate bounds a cell number.

**Sixteen of the columns the fill writes are `Fr`-backed** — `cycle`, the four frame and three
access read timestamps, the five value columns `a`, `b`, `b_new`, `d`, `d_new`, and `x`, `prod`
and `z` — and every other is `u32`-backed. A cell holds a whole `Fr`, and no gate decomposes one.

**17 of the 31 `W` columns are read by no gate**: the 14 gap chunks, `base_low_hi`, `base_room_hi`
and the multiplicity. Each is the direct half of a range bound or a table count, and the channel
is the only thing that refuses a wrong one.

### 22.4 Gate list 0: the 144 leaves

144 producing columns, relations 0–143 in tree order; relation `r` defines `L1[r]`.

| relations | columns | what |
| --- | --- | --- |
| 0–3 | 4 | `read_w0` … `read_w3` |
| 4 | 1 | `read_anchor` |
| 5–7 | 3 | `read_a`, `read_b`, `read_d` |
| 8–11 | 4 | `write_w0` … `write_w3` |
| 12 | 1 | `write_anchor` |
| 13–15 | 3 | `write_a`, `write_b`, `write_d` |
| 16–17 | 2 | `range16_table_num`, `range16_table_den` |
| 18–49 | 32 | the four frame gaps' four obligations, `(num, den)` each |
| 50–61 | 12 | `base_low`'s three obligations, then `base_room`'s |
| 62–85 | 24 | the three accesses' gaps, `a`, `b` then `d`, four obligations each |
| 86–89 | 4 | `digit_range`, `digit_scaled` |
| 90–143 | 54 | `range16_pad_0` … `range16_pad_26`, 27 neutral fractions to 64 |

**No pad leaf.** The frame and the anchor are five leaves a side, which `delegation::leaves` pads
to eight; `delegation::leaves_with` drops those pads, appends the three accesses' pairs, and pads
again to a power of two, and eight is one. `FR_OP` is the first delegation family in this page
whose product trees are exactly full.

The sixteen memory leaves are §0.6's frame-leaf pattern, each under its mask `m`, built by
`delegation::masked_leaf` — the frame and the anchor through `delegation::leaves`, the accesses
through `delegation::Access::leaves` — each one `Quadratic` with constant 1:

```text
pattern     m·T(space, addr, ts, value) + 1 − m
positional  1 + mem_gamma·m + -1·m + space·m + (mem_alpha_ts·m) ×Δ
              + mem_alpha_addr·addr·m + <ts> + mem_alpha_val·value·m
<ts>        mem_alpha_ts·read_ts·m on a read; (mem_alpha_ts·M[0]·m) ×4 on a write
```

| leaf | relation | mask `m` | space | addr | ts | value |
| --- | --- | --- | --- | --- | --- | --- |
| `read_w{j}` | `j` | `live` `M[1]` | `RAM` = 2 | `M[4 + 4j]` | `M[5 + 4j]` | `M[6 + 4j]` |
| `read_anchor` | 4 | `live` | 11 | `M[2]` | `4·cycle + 3` | `M[3]` |
| `read_a` | 5 | `a_live` `M[20]` | `FIELD` = 10 | `M[14]` | `M[21]` | `M[22]` |
| `read_b` | 6 | `b_live` `M[23]` | 10 | `M[18]` | `M[24]` | `M[25]` |
| `read_d` | 7 | `d_live` `M[27]` | 10 | `M[10]` | `M[28]` | `M[29]` |
| `write_w{j}` | `8 + j` | `live` | 2 | `M[4 + 4j]` | `4·cycle + 0` | `M[7 + 4j]` |
| `write_anchor` | 12 | `live` | 11 | `M[2]` | the literal 0 | absent |
| `write_a` | 13 | `a_live` | 10 | `M[14]` | `4·cycle + 0` | `M[22]`, the value read |
| `write_b` | 14 | `b_live` | 10 | `M[18]` | `4·cycle + 1` | `M[26]` |
| `write_d` | 15 | `d_live` | 10 | `M[10]` | `4·cycle + 2` | `M[30]` |

`read_anchor`'s timestamp `4·cycle + 3` is spelled as a write's is, three `mem_alpha_ts·M[1]`
linear terms and four `mem_alpha_ts·M[0]·M[1]` products; `write_anchor` is
`1 + mem_gamma·M[1] + -1·M[1] + 11·M[1] + mem_alpha_addr·M[2]·M[1]` and nothing else.

The fraction leaves are `lookup.md` §6's — `(−mult, T + g)` for the table, `(1, E_l + g)` per
obligation, `(0, 1)` per pad — and every one is `Linear` but the 36 row denominators:

```text
range16_table_num    -1·W[30] + 0
range16_table_den    1·V[range16] + lookup_g
<obligation>_num     1
<obligation>_den     lookup_g + <constant>·s + Σ c·s·x        Quadratic; s the selector, c·x the tuple's terms
range16_pad_{i}_num  0
range16_pad_{i}_den  1
```

so `gap_a_lo_range_den` is
`lookup_g + -1·M[20] + 4·M[20]·M[0] + -1·M[20]·M[21] + -65536·M[20]·W[12] + 0x30644e72…f592f0000001·M[20]·W[13]`,
and `digit_range_den` is `lookup_g + 1·W[26]·M[30]`.

### 22.5 Gate list 0: the 44 enforcing gates

Relations 144–187, in `artifact`'s order: the frame's eleven from
`delegation::read_only_frame_range16` (`frame_gates_range16`, then one `writes_back_w{j}` a
word), then the family's 33 from `fr_op`'s private `gates()`. The nine degree-1 gates are
`Linear` (`delegation::linear`); the 35 degree-2 gates are `Quadratic` with constant 0
(`delegation::quadratic` and `booleanity`). Every gate's constant is 0, so `zero_row_valid` is
`true` (`build::zero_on_zero_row`).

Positional form, as the dump stores each, `0 = …` for every row; `0x30644e72…f592f0000001` is
`−2^32` (§0.2):

```text
144 live_boolean        (0 + 1·M[1] + -1·M[1]·M[1])
145 addr_w0             (0 + 0·M[1] + 1·M[1]·M[4] + -1·M[1]·M[2])
146 addr_w1             (0 + -4·M[1] + 1·M[1]·M[8] + -1·M[1]·M[2])
147 addr_w2             (0 + -8·M[1] + 1·M[1]·M[12] + -1·M[1]·M[2])
148 addr_w3             (0 + -12·M[1] + 1·M[1]·M[16] + -1·M[1]·M[2])
149 base_aligned        (0 + -65536·M[1] + 1·M[1]·M[2] + -4·M[1]·W[8])
150 base_in_window      (0 + 2147483632·M[1] + -1·M[1]·M[2] + -1·M[1]·W[10])
151 writes_back_w0      (1·M[7] + -1·M[6] + 0)                 152–154 the same over M[11]/M[10], M[15]/M[14], M[19]/M[18]
155 op1_boolean         (0 + 1·W[18] + -1·W[18]·W[18])         156–163 the same over W[19] … W[26]
164 one_op_a_live_row   (-1·M[1] + 1·W[18] + 1·W[19] + 1·W[20] + 1·W[21] + 1·W[22] + 1·W[23] + 1·W[24] + 1·W[25] + 1·W[26] + 0)
165 op_word             (-1·M[6] + 1·W[18] + 2·W[19] + 3·W[20] + 4·W[21] + 5·W[22] + 6·W[23] + 7·W[24] + 8·W[25] + 9·W[26] + 0)
166 a_live_boolean      (0 + 1·M[20] + -1·M[20]·M[20])
167 a_live_rule         (1·M[20] + -1·W[18] + -1·W[19] + -1·W[20] + -1·W[21] + -1·W[22] + -1·W[23] + -1·W[25] + -1·W[26] + 0)
168 b_live_boolean      (0 + 1·M[23] + -1·M[23]·M[23])
169 b_live_rule         (1·M[23] + -1·W[18] + -1·W[19] + -1·W[20] + -1·W[21] + -1·W[23] + -1·W[26] + 0)
170 d_live_boolean      (0 + 1·M[27] + -1·M[27]·M[27])
171 d_live_rule         (1·M[27] + -1·W[18] + -1·W[19] + -1·W[20] + -1·W[21] + -1·W[22] + -1·W[24] + -1·W[25] + -1·W[26] + 0)
172 x_rule              (0 + 1·W[27] + -1·W[18]·M[25] + -1·W[21]·M[25] + -1·W[22]·M[30])
173 prod_rule           (0 + 1·W[28] + -1·M[22]·W[27])
174 mul_rule            (0 + 1·W[18]·M[30] + -1·W[18]·W[28])
175 add_rule            (0 + 1·W[19]·M[30] + -1·W[19]·M[22] + -1·W[19]·M[25])
176 sub_rule            (0 + 1·W[20]·M[30] + -1·W[20]·M[22] + 1·W[20]·M[25])
177 mac_rule            (0 + 1·W[21]·M[30] + -1·W[21]·M[29] + -1·W[21]·W[28])
178 eq_rule             (0 + 1·W[23]·M[22] + -1·W[23]·M[25])
179 imm_rule            (0 + 1·W[24]·M[30] + -1·W[24]·M[18])
180 shl_rule            (0 + 1·W[25]·M[30] + 0x30644e72…f592f0000001·W[25]·M[22] + -1·W[25]·M[18])
181 inv_rule            (0 + -1·W[22] + 1·W[22]·W[28] + 1·W[22]·W[29])
182 digit_rule          (0 + 1·W[26]·M[22] + -1·W[26]·M[30] + -256·W[26]·M[26])
183 b_kept              (0 + 1·M[26] + -1·M[25] + -1·W[26]·M[26] + 1·W[26]·M[25])
184 z_boolean           (0 + 1·W[29] + -1·W[29]·W[29])
185 z_kills_a           (0 + 1·W[29]·M[22])
186 z_kills_d           (0 + 1·W[29]·M[30])
187 z_only_inv          (0 + 1·W[29] + -1·W[29]·W[22])
```

`addr_w0` carries the term `0·M[1]`: the constructor writes `−4j·live` at every `j`, and keeps it
at `j = 0`.

Named form:

| relations | gate | degree | `= 0` | what it fixes |
| --- | --- | --- | --- | --- |
| 144 | `live_boolean` | 2 | `live − live²` | the frame's one mask is a bit |
| 145–148 | `addr_w{j}` | 2 | `live·(w{j}_addr − base − 4j)` | word `j` is at `base + 4j` |
| 149 | `base_aligned` | 2 | `live·(base − 65,536 − 4·base_low)` | the base is word-aligned and at or above `RAM_ORIGIN` = 65,536 |
| 150 | `base_in_window` | 2 | `live·(2^31 − 16 − base − base_room)` | the 16-byte frame is inside RAM |
| 151–154 | `writes_back_w{j}` | 1 | `w{j}_write_value − w{j}_read_value` | the frame survives the call: the guest's op and cells cannot be rewritten |
| 155–163 | `op{c}_boolean` | 2 | `op{c} − op{c}²` | each selector is a bit |
| 164 | `one_op_a_live_row` | 1 | `Σ_c op{c} − live` | one op a live row, none on padding |
| 165 | `op_word` | 1 | `Σ_c c·op{c} − w0_read_value` | the op word is the set selector's code |
| 166, 168, 170 | `{a,b,d}_live_boolean` | 2 | `m − m²` | each access mask is a bit |
| 167 | `a_live_rule` | 1 | `a_live − Σ_{c ≠ 7} op{c}` | `a` is read by every op but `IMM` |
| 169 | `b_live_rule` | 1 | `b_live − (op1 + op2 + op3 + op4 + op6 + op9)` | `b` is read by six ops |
| 171 | `d_live_rule` | 1 | `d_live − Σ_{c ≠ 6} op{c}` | `d` is written by every op but `EQ` |
| 172 | `x_rule` | 2 | `x − op1·b − op4·b − op5·d_new` | the multiplicand: `b` on `MUL` and `MAC`, `d′` on `INV`, else 0 |
| 173 | `prod_rule` | 2 | `prod − a·x`, ungated | the one product |
| 174 | `mul_rule` | 2 | `op1·(d_new − prod)` | `MUL` |
| 175 | `add_rule` | 2 | `op2·(d_new − a − b)` | `ADD` |
| 176 | `sub_rule` | 2 | `op3·(d_new − a + b)` | `SUB` |
| 177 | `mac_rule` | 2 | `op4·(d_new − d − prod)` | `MAC` |
| 178 | `eq_rule` | 2 | `op6·(a − b)` | `EQ` |
| 179 | `imm_rule` | 2 | `op7·(d_new − w3_read_value)` | `IMM` |
| 180 | `shl_rule` | 2 | `op8·(d_new − 2^32·a − w3_read_value)` | `SHL` |
| 181 | `inv_rule` | 2 | `op5·(prod + z − 1)` | `INV`: `a·d′ = 1 − z` |
| 182 | `digit_rule` | 2 | `op9·(a − d_new − 2^8·b_new)` | `DIGIT` |
| 183 | `b_kept` | 2 | `(1 − op9)·(b_new − b)` | `b` is written back as read on every row but a `DIGIT` |
| 184 | `z_boolean` | 2 | `z − z²` | — implied, see below |
| 185 | `z_kills_a` | 2 | `z·a` | `z = 0` wherever `a ≠ 0` |
| 186 | `z_kills_d` | 2 | `z·d_new` | `d′ = 0` wherever `z = 1` |
| 187 | `z_only_inv` | 2 | `z·(1 − op5)` | `z = 0` off an `INV` row |

**One product serves every op that multiplies.** `x` is `b` on `MUL` and `MAC` and `d′` on `INV`,
so `prod = a·x` is the row's one product of two values, and each op's equation stays a sum of
`selector·column` products, degree 2. `INV` is §14.4's is-zero gadget — `inv_rule`, `z_kills_a`
and `z_kills_d` in the places of its three gates, the first spelled `op5·(prod + z − 1)` over the
shared product — plus `z_only_inv`: on an `INV` row `a·d′ + z = 1`, `z·a = 0` and `z·d′ = 0`
leave `d′ = a⁻¹` where `a ≠ 0` and `z = 1`, `d′ = 0` where `a = 0`.

Five notes, each a thing that is easy to get wrong.

- **`one_op_a_live_row` is what keeps a field write inside an invocation.** The three masks are
  tied to the selectors and to nothing else, and the selectors are tied to `live` by this gate
  alone. Without it a padding row — which pairs with no request, its ten frame and anchor leaves
  being the product's identity — could set `op7`: `d_live_rule` makes its `d` access live,
  `imm_rule` writes `w3_read_value`, which is free on a padding row, to the cell
  `w1_read_value` names, likewise free, at a `cycle` of its choosing, and the multiset balances
  it as an ordinary read-modify-write. Its other job is a second op on a live row. The codes are
  1–9, so sums collide (`1 + 2 = 3`), but every pair of selectors but `{op6, op7}` already drives
  one mask to 2 and is refused by that mask's booleanity — `a` is read by every op but `IMM` and
  `d` written by every op but `EQ` — and `EQ` with `IMM` spells 13, which names no op.
- **Four booleanity gates are implied, and three of them are required anyway.** Given
  `one_op_a_live_row` and the nine `op{c}_boolean`, at most one selector is set, so each mask, a
  sum of selectors, is 0 or 1. `a_live_boolean`, `b_live_boolean` and `d_live_boolean` are
  nevertheless what `check_memory` requires of a committed leaf mask and `validate` of a lookup
  selector, and each looks for that gate. `z_boolean` is implied by the gadget: off an `INV` row
  `z_only_inv` makes `z` 0, and on one `inv_rule` and `z_kills_a` make it 1 exactly where `a = 0`.
  `FR_ARITH`'s `is_zero` carries no such gate (§14.3); `recursion.md` §3 lists this one, and it
  costs a gate and no degree.
- **`DIGIT` does not pin the digit.** `digit_range` and `digit_scaled` hold `d′` below `2^8`, and
  `digit_rule` then defines `b′ = (a − d′)·2^{−8}` over `Fr` for each of the 256 candidates, so a
  `DIGIT` row admits 256 witnesses; the executor writes `a`'s canonical low byte. What gives a
  chain of digits its meaning is the caller's last check that the rest is 0 —
  `guests/field-ops`' `EQ 0, 11, 0` after four, the MSM template's sixteen `DIGIT`s "leaving
  nothing over" (`recursion.md` §8.3) — after which `Σ_k d_k·2^{8k}` is congruent to the scalar,
  a representation and not necessarily the canonical one (`recursion.md` §3).
- **`b_kept` is what makes `b` an operand.** `b_live` is 1 on six ops and the `b` access writes
  `b_new` at `4·cycle + 1`; on the five of them that are not `DIGIT`, `b_kept` is the only thing
  saying `b_new = b`, so without it a `MUL` could rewrite its second operand's cell. `a` needs no
  such gate: `write_a` writes `M[22]`, the column `read_a` read, so its write-back is structural.
- **`op_word` and `writes_back_w{j}` are ungated**, both sides being 0 on the all-zero row, and
  every nonzero constant rides a column: `base_aligned`'s `−RAM_ORIGIN` and `base_in_window`'s
  `2^31 − 16` ride `live`, `inv_rule`'s `−1` rides `op5`.

### 22.6 The 36 obligations and the channel

One channel, `RANGE16` = channel 1, table `V[range16]`, multiplicity `W[30]`. The tuple is **one**
expression wide, so it weights its column by the literal 1 and reads `g` and **no** power of `β`
and no neutral: `E + g = g + s·e_0`. The helpers are
`delegation::{bound_chunked, gap_lookups_range16, range16}`, shared with the base delegation
families that carry `RANGE16`.

| obligation | relations | count | selector | tuple | bound |
| --- | --- | --- | --- | --- | --- |
| `gap{j}_c0_range`, `gap{j}_c1_range` | 18–49 | 8 | `live` | `W[2j + c]` | each chunk below `2^16` |
| `gap{j}_top_scaled` | ” | 4 | `live` | `2^10·W[2j + 1]` | the top chunk below `2^6` |
| `gap{j}_lo_range` | ” | 4 | `live` | `4·cycle − w{j}_read_ts − 2^16·W[2j] − 2^32·W[2j + 1] − 1` | the derived low sixteen bits: the frame word's read precedes `4·cycle + 0` |
| `base_low_c0_range`, `base_low_top_scaled`, `base_low_lo_range` | 50–55 | 3 | `live` | `W[9]`; `2^3·W[9]`; `W[8] − 2^16·W[9]` | `base_low < 2^29` |
| `base_room_c0_range`, `base_room_top_scaled`, `base_room_lo_range` | 56–61 | 3 | `live` | `W[11]`; `2·W[11]`; `W[10] − 2^16·W[11]` | `base_room < 2^31` |
| `gap_a_c0_range`, `_c1_range`, `_top_scaled`, `_lo_range` | 62–69 | 4 | `a_live` | `W[12]`; `W[13]`; `2^10·W[13]`; `4·cycle − a_read_ts − 2^16·W[12] − 2^32·W[13] − 1` | `a`'s read precedes `4·cycle + 0` |
| `gap_b_c0_range`, `_c1_range`, `_top_scaled`, `_lo_range` | 70–77 | 4 | `b_live` | `W[14]`; `W[15]`; `2^10·W[15]`; `4·cycle − b_read_ts − 2^16·W[14] − 2^32·W[15]` | `b`'s read precedes `4·cycle + 1` |
| `gap_d_c0_range`, `_c1_range`, `_top_scaled`, `_lo_range` | 78–85 | 4 | `d_live` | `W[16]`; `W[17]`; `2^10·W[17]`; `4·cycle − d_read_ts − 2^16·W[16] − 2^32·W[17] + 1` | `d`'s read precedes `4·cycle + 2` |
| `digit_range` | 86–87 | 1 | `op9` | `d_new` | `d′ < 2^16` |
| `digit_scaled` | 88–89 | 1 | `op9` | `2^8·d_new` | with the above, `d′ < 2^8` |

**36 obligations**, in that order: 16 for the frame's gaps, 3 and 3 for the base, 12 for the
accesses' gaps, 2 for the digit. Each gap is `4·cycle + Δ − read_ts − 1` in `[0, 2^38)`, so a
`lo_range` tuple's constant is `Δ − 1`: −1 for the frame and `a`, 0 for `b`, +1 for `d`. The
38-bit gap is §18.5's exact three-piece shape, `38 = 16 + 16 + 6`, and the base's 29 and 31 bits
one committed chunk each.

**Selectors: 22 obligations ride `live`, twelve an access's own mask and two `op9`.** Every leaf
and every obligation of the six base delegation families rides `live`; here a row that does not
make an access has `read_ts` 0, and its `gap_{q}_lo_range` would read `4·cycle + Δ − 1`, out of
range once `4·cycle` passes `2^16` — the mask exempts it, as `live` exempts a padding row. The
digit's pair rides the op's own selector, so `d_new` is bounded on a `DIGIT` row and nowhere else;
on every other op no obligation reads it.

**The scaled obligation alone bounds nothing**, and `lookup::check_copowers` is what says so
(§18.5). `fr_op::artifact` passes it ten `(column, selector)` pairs, each the selector its scaled
obligation carries: the four frame gap tops `W[1]`, `W[3]`, `W[5]`, `W[7]` and the two base
halfwords `W[9]`, `W[11]` under `live`; the three access gap tops `W[13]`, `W[15]`, `W[17]` under
`a_live`, `b_live`, `d_live`; and `d_new`, `M[30]`, under `op9`. Each has its direct obligation
under the same selector, and the artifact is not built without it.

**The channel table.**

| channel | output positions | table columns | multiplicity |
| --- | --- | --- | --- |
| `RANGE16` = 1 | 2, 3 | `V[range16]` | `W[30]` |

**37 leaves in a 64-leaf tree.** 36 obligations and the table fraction pad to 64 with 27 neutral
fractions. 27 more obligations fit before the tree doubles; five fewer would halve it to 32 and
take a row-wise list off the circuit, this tree alone setting `R = 6`, each product tree being 3
deep.

**One multiplicity column, read by no gate.** `trace::build_multiplicities` counts each table
row's occurrences over the 36 gated tuples of every row of the shard — padding rows included, 36
zeros each — and appends the column after the fill; `fill::fr_op` does not write it.
`checker::violated_lookups` is the native reading of every obligation above, and
`lookup::check_discharge`, which `memory::assemble` runs, is what says each has its own
denominator leaf beside a numerator of 1 and the channel exactly one table fraction.

### 22.7 The trees, the inner layers and the outputs

Three trees: `read` and `write`, eight leaves each, and `range16`, 64 fractions. Seven row-wise
lists — the `range16` tree's six levels and gate list 0 — then `n` halving lists. Each row-wise
list reduces every tree pairwise; a tree already at one node copies itself up, so all three reach
the halving phase together.

| layer | read tree | write tree | `range16` | width |
| --- | --- | --- | --- | --- |
| `L1` | 8 | 8 | 128 | 144 |
| `L2` | 4 | 4 | 64 | 72 |
| `L3` | 2 | 2 | 32 | 36 |
| `L4` | 1 | 1 | 16 | 18 |
| `L5` | 1 | 1 | 8 | 10 |
| `L6` | 1 | 1 | 4 | 6 |
| `L7` | 1 | 1 | 2 | 4 |
| `L8`–`L27` | 1 | 1 | 2 | 4 each |

`370 = 144 + 72 + 36 + 18 + 10 + 6 + 4 + 20·4`, and at any admissible `n` the inner and relation
totals are `290 + 4n` and `334 + 4n`.

Relations: **0–143** list 0's leaves and **144–187** its enforcing gates, then **188–259** list 1,
**260–295** list 2, **296–313** list 3, **314–323** list 4, **324–329** list 5, **330–333** list 6,
and halving list `k` (`7 ≤ k ≤ n + 6`) holds `334 + 4(k − 7)` to `337 + 4(k − 7)`. The roots are
relations `330 + 4n` to `333 + 4n`: **410–413** at `n = 20`. A product node is `Product` in lists
1–3, where the memory trees reduce, and `TreeProduct` in a halving list; lists 4–6 carry the two
memory nodes up as `Linear` copies. A fraction node is a `Quadratic` numerator and a `Product`
denominator in lists 1–6, a `TreeCross` numerator and a `TreeProduct` denominator in a halving
list (§0.6). Each halving list is the four gates `read_{k+1}_0`, `write_{k+1}_0`,
`range16_{k+1}_0_num` and `range16_{k+1}_0_den`, the last list's being `read_root`, `write_root`,
`range16_num_root` and `range16_den_root`.

**The outputs**, in output-map order:

| output | `PolyAddress` | name | read by |
| --- | --- | --- | --- |
| 0 | `L{27}[0]` | `read_root` | `verify_shard` step 10a, against `memory_roots[p]` for `p` the position of `(19, shard_index)` in `verifier_core::statement_shards`, and step 10b's product over the statement |
| 1 | `L{27}[1]` | `write_root` | ditto |
| 2, 3 | `L{27}[2..4]` | `range16_num_root`, `range16_den_root` | step 9: `num = 0` **and** `den ≠ 0`, or `Lookup { channel: 1 }` |

On the all-zero row every memory leaf is `m·T + 1 − m` at `m = 0`, which is 1, so the product-tree
clause holds with no pad leaf to help it; the fraction tree is exempt from it, as every fraction
tree is (§0.6, `lookup.md` §6).

### 22.8 Witness rows

`crates/checker/tests/recursion.rs`' `the_field_families_hold_and_the_field_memory_balances` fills
a `2^16` shard of this family from `guests/field-ops`' real trace with `prover::family_fill`, and
evaluates each of its 38 live rows and the first padding row through `checker::violated_relations`,
over scratch the engine's gate kernel computes row-locally, and through `checker::violated_lookups`.
It also multiplies every live row's field leaves, with `P2_FIELD`'s, `FIELD_IO`'s and `FQ_OP`'s and
the field window's teardown and init, and requires reads × teardowns = writes × inits: a slot or an
address the circuit and the executor disagreed on would leave a tuple with no partner. It runs in
ordinary CI. `crates/emulator/tests/guests.rs`' `field_ops_checks_itself_under_the_recursion_ecalls`
pins the 38 invocations and the guest's exit status, 26, each check a literal read back through an
`EXPORT`.

The rows below are those calls' operation-level cells as `fill::fr_op` writes them over the
executor's answers. **They were derived from the guest's source and `emulator`'s `fr_op`, not
printed from a run**, and the cycle, the base, the read timestamps and the gap chunks, which are
the run's, are left out. A call is written `OP d, a, b` as `guests/field-ops`' `fr` takes it, so
the frame is `[code, d, a, b]`; `live` is 1 on rows 0–37, and the row's own `op{c}` is its one
selector.

| row | call | frame `w0`…`w3` | `a_live` `b_live` `d_live` | `a` | `b` | `b_new` | `d` | `d_new` | `x` | `prod` | `z` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | `IMM 1, 0, 7` | 7, 1, 0, 7 | 0 0 1 | 0 | 0 | 0 | 0 | 7 | 0 | 0 | 0 |
| 2 | `MUL 3, 1, 2` | 1, 3, 1, 2 | 1 1 1 | 7 | 11 | 11 | 0 | 77 | 11 | 77 | 0 |
| 5 | `MAC 5, 1, 2` | 4, 5, 1, 2 | 1 1 1 | 7 | 11 | 11 | 73 | 150 | 11 | 77 | 0 |
| 6 | `INV 6, 5, 0` | 5, 6, 5, 0 | 1 0 1 | 150 | 0 | 0 | 0 | `150⁻¹` | `150⁻¹` | 1 | 0 |
| 9 | `EQ 0, 7, 8` | 6, 0, 7, 8 | 1 1 0 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| 10 | `INV 9, 0, 0` | 5, 9, 0, 0 | 1 0 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| 11 | `SHL 10, 8, 5` | 8, 10, 8, 5 | 1 0 1 | 1 | 0 | 0 | 0 | `2^32 + 5` | 0 | 0 | 0 |
| 12 | `MUL 1, 1, 1` | 1, 1, 1, 1 | 1 1 1 | 7 | 7 | 7 | 7 | 49 | 7 | 49 | 0 |
| 15 | `DIGIT 12, 11, 11` | 9, 12, 11, 11 | 1 1 1 | `0x12345678` | `0x12345678` | `0x123456` | 0 | `0x78` | 0 | 0 | 0 |
| 38 | padding | 0, 0, 0, 0 | 0 0 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

Row 10 is the gadget's zero case, `z = 1` and `d′ = 0`; row 12 reads one cell three times, `b`
and `d` each reading the previous slot's write-back; row 15's `0x78` is one of the 256 digits its
gates admit. The 0s of
an access the op does not make — `a` and `b` on row 0, `b` on rows 6 and 11, `d` on row 9 — are
the fill's, and free (§22.9).

**No negative control exercises this circuit.** No suite corrupts a cell of an `FR_OP` row and
requires a named gate or obligation to refuse it, row-locally or through `checker::TamperHarness`,
and none runs the checker's independent validators — `check_laws`, `check_padding`,
`check_padding_identity` — over this artifact: its construction-time checks are `constraints`'
own, and a key built over it runs `VerifyingKey::check`. What a whole proof adds is the deferred
`crates/prover/tests/field_ops.rs`: the block at `2^16` proved and verified through
`verify_block`, and every shard's tape replayed and held to `verify_shard_local` and
`pcs::batch_verify_deferred`.

### 22.9 What fixes each cell

Read off the gates and §22.3's readers, not off a tamper table or a probe; §22.8 says why there
is neither.

| cell | what fixes it |
| --- | --- |
| `cycle`, `base` | the multiset: the frame's and the accesses' writes ride `4·cycle + Δ`, and the anchor's teardown read at `4·cycle + 3` has the request's mirror write as its only partner; locally `base_aligned`, `base_in_window` and `addr_w{j}` |
| `live` | `live_boolean`, every frame and anchor leaf's mask, and `one_op_a_live_row` |
| `anchor_value` | **nothing local**: the request's mirror write must equal it, and the memory argument is what says so (§26 observation 19) |
| `w{j}_addr` | `addr_w{j}`, against `base` |
| `w{j}_read_ts` | the multiset; the four `gap{j}_*` obligations only hold it below `4·cycle` |
| `w0_read_value`, the op word | the frame's read tuple, `writes_back_w0` and `op_word` — with the selectors, one of 1–9 on a live row and 0 on a padding row |
| `w1_read_value` … `w3_read_value` | the frame's read tuples and `writes_back_w{j}`; as cell numbers, nothing local — a cell no window initializes cannot balance; `w3` is also `imm_rule`'s and `shl_rule`'s operand |
| `w{j}_write_value` | `writes_back_w{j}` |
| `a_live`, `b_live`, `d_live` | the mask rule against the selectors, and its booleanity gate |
| `a_read_ts`, `b_read_ts`, `d_read_ts` | where the access is made, the multiset and the access's four gap obligations under its mask; where it is not, **nothing** |
| `a` | where `a_live` is 1, the multiset — `read_a` and `write_a` are one column, so the read is the cell's last value and is what goes back; the op gates read it. On an `IMM` row, **nothing** |
| `b` | where `b_live` is 1, the multiset; on `INV`, `IMM` and `SHL` rows `b` and `b_new` are free together under `b_kept` |
| `b_new` | `b_kept`, `b` on every row but a `DIGIT`; there `digit_rule`, given `a` and `d_new` |
| `d` | where `d_live` is 1, the multiset, `d`'s cell's last value; only `mac_rule` reads it. On an `EQ` row, **nothing** |
| `d_new` | the op's gate — `mul_rule`, `add_rule`, `sub_rule`, `mac_rule`, `imm_rule` or `shl_rule`, the `INV` gadget, or `digit_rule` with `digit_range` and `digit_scaled`; on an `EQ` row, **nothing** |
| gap chunks, `base_low_hi`, `base_room_hi` | **their own obligations and nothing else**: no gate reads any of the 16 |
| `base_low`, `base_room` | `base_aligned` / `base_in_window`, and their obligations |
| `op{c}` | `op{c}_boolean`, `one_op_a_live_row` and `op_word` |
| `x` | `x_rule` |
| `prod` | `prod_rule` |
| `z` | `inv_rule`, `z_kills_a` and `z_only_inv` determine it; `z_boolean` and `z_kills_d` hold besides |
| `mult_range16` | `trace::build_multiplicities`, and the channel's root check — no gate reads it |

**An unmade access's cells are free, and nothing depends on them.** On a live row whose op does
not make an access, that access's leaves are the product's identity, its four obligations are off,
and no live gate reads its values: an `EQ` row's `d`, `d_new`, `d_read_ts` and gap chunks, an
`IMM` row's `a` and `b` accesses, and an `INV` or `SHL` row's `b` access — `b_kept` holding `b_new`
to `b` without fixing either. It is §26 observation 7's shape, `jalr_drop` off a `jalr` row, and
the honest fill writes 0.

---

## 23. `P2_FIELD` — family 20

### 23.1 Header

| | |
| --- | --- |
| id, constant | 20, `constants::family::P2_FIELD` |
| registry | `constraints::recursion_circuit(20, n)` **alone**; `family_circuit(20, n)` is `None` at every `n` |
| constructor | `constraints::p2_field::artifact(n)` |
| channels | `p2_field::channels()`: **`RANGE16`** alone, multiplicity `W[381]` |
| fill | the private `prover::fill::p2_field` |
| ecall, anchor space | `0x050A` (`ecall::PRECOMPILE_P2_FIELD`), `address_space::DELEGATION_P2_FIELD` = 12; the eight field accesses are in `address_space::FIELD` = 10 |
| normative spec | `docs/spec/recursion.md` §4, with §2 for the field memory, §1.2 for the registry and §1.4 for the request's `a0`; `delegation.md` §4 and §5 for the frame and the anchor |
| committed | 45 `M`, 382 `W`, 0 `S` — 427 |
| virtual | 1: `V[range16]` |
| obligations | 58, all `RANGE16` |
| enforcing gates | 372 (6 degree-1, 366 degree-2), all on gate list 0 |
| outputs | 4 |
| at `n = 18` | depth 25 (7 row-wise + 18 halving), 392 inner columns, 764 relations, 294,425 wire bytes — the default height, and the one `crates/constraints/tests/vectors/recursion.txt` pins |
| at `n = 16` | depth 23 (7 + 16), 384 inner columns, 756 relations, 293,915 wire bytes — the height the two suites that fill it build |

`recursion_circuit(20, n)` is `p2_field::artifact(n)` with `p2_field::channels()`, one `RANGE16`
channel. **The base registry never returns it**: the private `circuit` behind both registries
holds one match and guards this family's arm by the registry, so `family_circuit(20, n)` falls
through to `None` at every `n` and no base-format key can name the family
(`crates/constraints/tests/recursion.rs`'
`the_recursion_families_build_in_the_recursion_registry_alone`, `recursion.md` §1.2). It is built
by `memory::assemble`: every constraint it makes is an enforcing gate or an obligation on gate
list 0, so above the leaves it is two product trees, one fraction tree and the halving phase. Its
frame and anchor are `constraints::delegation`'s read-only `RANGE16` frame,
`read_only_frame_range16` over five words, and its eight field accesses are `delegation::Access`es
that `delegation::leaves_with` appends to the frame's leaves. Fill: `prover::family_fill(20)`.

**427 committed columns (45 `M`, 382 `W`, no `S`) and one virtual table, `V[range16]`.** Gate list
0 writes 160 columns — 16 leaves a side of the two memory trees plus the `RANGE16` tree's 64
fraction pairs — and holds **372 enforcing gates (6 degree-1, 366 degree-2)**: 20 for the frame and
the absorption, 352 for the permutation. **58 obligations**, all `RANGE16`, and **4 outputs**. At
`n = 18` there are 25 gate lists (7 row-wise and 18 halving), the top is `L25`, and the circuit has
392 inner columns and 764 relations and is 294,425 bytes of wire form, SHA-256 `ff920a02…63f2f025`
in `recursion.txt` — one line among the recursion format's six, which
`cargo run -p kat-gen -- recursion` writes and CI regenerates and diffs. Only the depth, the inner
and relation totals and the wire length depend on `n`: the first three are `7 + n`, `320 + 4n` and
`692 + 4n`, a height adding halving lists and nothing else, one node per output each.

`artifact` panics on every refusal of `validate` (through `build::assemble`), of
`memory::check_memory` and `lookup::check_discharge` (through `memory::assemble`) and of
`lookup::check_copowers` over its fifteen scaled columns, and unless the `M` and `W` widths are
`MEMORY_COLUMNS` and `WITNESS_COLUMNS`, 45 and 382, and the all-zero row is a valid padding row.
**It has no `check_shape`**: nothing at construction counts the 58 obligations or names a relation,
as `keccak::check_shape` and `sha256::check_shape` do. What holds the shape is the digest line and
§23.9's suites.

**One row is one step of the transcript's duplex**, `transcript::Transcript::duplex` over cells of
the field memory (`recursion.md` §2, §4). The frame `[n, s, x, y, d]` is five RAM words the
request's `a0` names: `n` the count absorbed, `s` the first of the three cells holding the state,
`x` and `y` the cells absorbed, `d` the first of the three cells the permuted state is written to.
The row reads `s, s+1, s+2` at Δ0, `x` at Δ1 when `n ≥ 1` and `y` at Δ2 when `n = 2`; forms the
lanes `(n ≥ 1 ? x : s₀, n = 2 ? y : (n = 1 ? 0 : s₁), s₂ + n)` — the rate overwritten and
zero-filled and the count added to the capacity, which is what keeps `[a]` and `[a, 0]` apart; and
writes `poseidon2_permute` of them to `d, d+1, d+2` at Δ3. The frame itself is read-only. **A cell
holds a whole `Fr`**, so no value crosses a frame as words, and there is no canonicity chain and no
bit decomposition anywhere — where `POSEIDON2` (§13) carried its three lanes as 24 RAM words read
and written in place, each of its six values with 520 bit columns. The next state goes to cells
the caller chose, so no handle to an old state is ever overwritten (`recursion.md` §4);
`verifier_core::tape`'s shard transcript over cells is this duplex (`recursion.md` §7).

**Flat, not layered.** `POSEIDON2` computes its permutation in 192 round layers, `193 + n` gate
lists, and a parent pays one sumcheck a layer to verify a shard; this circuit is `7 + n`
(`recursion.md` §4). What buys that is commitment: each of the 80 S-boxes commits `u²` and `u⁴`,
and each round but the last commits its three output lanes — `349 = 2·80 + 3·63` `W` columns — so
every gate is degree 2 over committed columns. **The last round's outputs are `M` columns**,
`next0`–`next2`, the values the next state's write leaves publish, so no copy gate stands between
the permutation and the multiset. The width is cheap where it lands: a recursion-format shard
commits each phase as stacks (`recursion.md` §1.3), and `VmConfig::stack_vars` gives
`σ = min(24 − n, 10)` for this circuit — `σ = 6` at `n = 18`, its 45 `M` columns one stack and its
382 `W` columns six; `σ = 8` at `n = 16`, one and two.

**Homogeneous.** Every round constant enters as `rc·live`, so on a padding row each round is the
constant-free round and the all-zero row satisfies every gate. A bare constant would make
`zero_row_valid` false, which `artifact` asserts true.

**The height is `2^18`, and 16 is the floor.** `RANGE16`'s table needs sixteen variables, so the
registry's derived guard returns `None` below 16, and `recursion_circuit(20, n)` is `Some` for
`16 ≤ n ≤ 30`. `DEFAULT_HEIGHTS[P2_FIELD]` is `2^18`, 262,144 duplex steps a shard, which is the
height `recursion.txt` pins. The two suites that fill a shard take `2^16`:
`crates/checker/tests/recursion.rs`' `VARS`, and the deferred `crates/prover/tests/field_ops.rs`,
whose statement puts this family at `WINDOW_VARS = 16`. Every gate and obligation is the same at
both.

**This family's §0.5 entries are at `n = 18`**, its default: 84 `Linear`, 93 `Product`, 515
`Quadratic`, 54 `TreeProduct` (3 a halving list) and 18 `TreeCross` (1 a halving list), which sum
to 764.

### 23.2 Row kinds

Four, and none is an instruction: the family is invoked, not decoded. It claims no pc, owns no
cycle, is not in `constants::family::CYCLE_OWNING`, and is in a `VmConfig` exactly when the linked
binary declares it — which, `P2_FIELD` being one of `program::FIELD_DELEGATIONS`, also brings
`FIELD_WINDOWS` in and makes the statement the recursion format's (`recursion.md` §1.1). The three
live kinds are one row shape, told apart by `n` through `n_word` and the two masks.

| row kind | `live` | `n` | `x_live`, `y_live` | lanes `(lane0, lane1, state2 + n)` | what it adds to the multiset |
| --- | --- | --- | --- | --- | --- |
| **absorb two** | 1 | 2 | 1, 1 | `(x, y, state2 + 2)` | 14 read tuples and 14 write tuples: the 5 frame words at `(RAM, base + 4j)`, the anchor pair at `(DELEGATION_P2_FIELD, base)`, and 8 field accesses at `(FIELD, cell)` |
| **absorb one** | 1 | 1 | 1, 0 | `(x, 0, state2 + 1)` | 13 and 13: no `y` access |
| **squeeze** | 1 | 0 | 0, 0 | `(state0, state1, state2)` | 12 and 12: neither `x` nor `y` |
| **padding** | 0 | 0 | 0, 0 | — | nothing: all 32 leaves are 1 — 28 real ones collapse to the product's identity and 4 are pads that are literally 1 — and 58 gated zeros the channel counts |

A live row holds the requesting cycle, the frame base, the five frame words, each access's read
timestamp and value, the two absorbed lanes, the permutation's 349 intermediates, the next state,
and the gap chunks of its frame words and of the accesses it makes, with the frame pointer's four
columns. The request that made it is a recursion-format `ADD_SUB` row whose `deleg_a0_rule`
writes `base + 20` into `a0` (`recursion.md` §1.4), which `crates/checker/tests/add_sub.rs`'
`a_recursion_request_advances_a0_past_its_frame` runs over this family's number among three.
Nothing in this circuit sees `a0`.

**A padding row is all-zero because the fill writes it so, and the gates force less than that and
more than nothing.** Four cells are pinned: `x_needs_live` makes `x_live` 0, `y_needs_x` then makes
`y_live` 0, `n_word` — ungated — makes the frame's `n` 0, and `writes_back_w0` its write. Every
leaf is masked and every obligation's selector is `live`, `x_live` or `y_live`, so outside the
permutation the rest is free: `cycle`, `base`, `anchor_value`, the frame's addresses and its other
four words (each written back as read), every timestamp, every gap chunk, the base columns, `x`,
`y`, `next{i}_old` and the three state values. **The permutation's region is not free**: its 352
gates are ungated and `lane0_rule` and `lane1_rule` hold with both masks 0, so a padding row's
`lane0` is `state0`, its `lane1` is `state1`, and every intermediate and `next0`–`next2` are the
constant-free permutation of `(state0, state1, state2)`. It is harmless — no leaf publishes any of
it — and it is read off the gates: no suite evaluates a padding row other than the all-zero one.

**Not provable**: an `n` of 3 or more, for which no pair of boolean masks satisfies `n_word`; a
frame that is not 4-aligned, starts below `RAM_ORIGIN` or ends past `2^31`, which `base_aligned`
and `base_in_window` refuse; and an access to a cell no `FIELD_WINDOWS` shard initializes, which
has no init tuple and cannot balance (`recursion.md` §2.2). The executor refuses the first two
before it answers — `emulator`'s private `p2_field` names `n > 2` as a `DelegationFrame` error,
and `delegation_frame` a misaligned base as `Misaligned` and one outside RAM as `OutOfBounds` —
and refuses an `s` or a `d` above `u32::MAX − 3` by the same `DelegationFrame` error, whose detail
reads "absorbs more than the rate, or its states leave the cells".

### 23.3 The base layer

**Memory-argument columns, `M[0..45]`** — `M[0..24]` filled by `fill::recursion_frame`, the shared
`delegation_frame_range16`, and `M[24..45]` by `fill::access_columns`; committed in
`PublicInputs::memory_commitments` before the memory challenges, as one stack.

| `PolyAddress` | name | Rust | what the fill writes | read by |
| --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `delegation::CYCLE` | the requesting cycle | `read_anchor` and the 13 write leaves other than `write_anchor`, as `4·cycle`; the 13 `*_lo_range` obligations |
| `M[1]` | `live` | `delegation::LIVE` | 1 on an invocation | the mask of 24 leaves — all but the four `x` and `y` leaves and the pads; the selector of 50 obligations; `live_boolean`, `addr_w{j}`, `base_aligned`, `base_in_window`, `x_needs_live`; and, as `rc·live`, the 272 permutation gates that carry a round constant |
| `M[2]` | `base` | `delegation::BASE` | the frame base `a0` carried | `addr_w{j}`, `base_aligned`, `base_in_window`, the anchor's two leaves |
| `M[3]` | `anchor_value` | `delegation::ANCHOR_VALUE` | 0 | `read_anchor` |
| `M[4 + 4j + f]`, `j < 5` | `w{j}_{addr,read_ts,read_value,write_value}` | `delegation::word(j, f)` | word `j`'s address, the timestamp of the write its read consumed, its value, and the same value | `read_w{j}`, `write_w{j}`, `addr_w{j}`, `gap{j}_lo_range`, `writes_back_w{j}`; the read value also as the next table says |
| `M[24 + 2i]`, `i < 3` | `state{i}_read_ts` | `p2_field::state_read_ts(i)` | when cell `s + i` was last written | `read_state{i}`, `gap_state{i}_lo_range` |
| `M[25 + 2i]` | `state{i}` | `p2_field::state(i)` | cell `s + i`'s value | `read_state{i}`, `write_state{i}`; and `state0` by `lane0_rule`, `state1` by `lane1_rule`, `state2` by round 0's six gates |
| `M[30]` | `x_live` | `p2_field::X_LIVE` | 1 where `n ≥ 1` | the mask of `read_x` and `write_x`; the selector of the four `gap_x_*`; `x_live_boolean`, `y_needs_x`, `x_needs_live`, `n_word`, `lane0_rule`, `lane1_rule` |
| `M[31]` | `x_read_ts` | `p2_field::X_READ_TS` | when cell `x` was last written; 0 where `n = 0` | `read_x`, `gap_x_lo_range` |
| `M[32]` | `x` | `p2_field::X` | cell `x`'s value; 0 where `n = 0` | `read_x`, `write_x`, `lane0_rule` |
| `M[33]` | `y_live` | `p2_field::Y_LIVE` | 1 where `n = 2` | the mask of `read_y` and `write_y`; the selector of the four `gap_y_*`; `y_live_boolean`, `y_needs_x`, `n_word`, `lane1_rule` |
| `M[34]` | `y_read_ts` | `p2_field::Y_READ_TS` | when cell `y` was last written; 0 where `n < 2` | `read_y`, `gap_y_lo_range` |
| `M[35]` | `y` | `p2_field::Y` | cell `y`'s value; 0 where `n < 2` | `read_y`, `write_y`, `lane1_rule` |
| `M[36 + 3i]`, `i < 3` | `next{i}_read_ts` | `p2_field::next_read_ts(i)` | when cell `d + i` was last written | `read_next{i}`, `gap_next{i}_lo_range` |
| `M[37 + 3i]` | `next{i}_old` | `p2_field::next_old(i)` | what cell `d + i` held | `read_next{i}` — **and nothing else** |
| `M[38 + 3i]` | `next{i}` | `p2_field::next(i)` | lane `i` of the permuted state, the executor's write | `write_next{i}`, `r63_out{i}` |

**The frame's words name cells, and the columns `x` and `y` are the cells' values.** The five read
values are:

| word | `constants::p2_field` | value | read, besides by the frame's own leaves and gates, by |
| --- | --- | --- | --- |
| 0 | `N_WORD` | `n` | `n_word`, and round 0's six gates as lane 2's `+ n` |
| 1 | `S_WORD` | `s` | the six `read_state{i}`, `write_state{i}` leaves, as the address `s + i` |
| 2 | `X_WORD` | the cell `x` is read from | `read_x`, `write_x`, as the address |
| 3 | `Y_WORD` | the cell `y` is read from | `read_y`, `write_y`, as the address |
| 4 | `D_WORD` | `d` | the six `read_next{i}`, `write_next{i}` leaves, as the address `d + i` |

No gate or obligation of this circuit bounds `s`, `d` or the two absorbed cells' indices: each is a
RAM word the guest wrote, and an address no field window covers cannot balance.

**Witness columns, `W[0..382]`** — all filled by `fill::p2_field` except the last; committed in
`ShardProof::witness_commitments`, six stacks at `n = 18`, before `g` is drawn.

| `PolyAddress` | name | Rust | what the fill writes | read by |
| --- | --- | --- | --- | --- |
| `W[2j + c]`, `j < 5`, `c < 2` | `gap{j}_c{c}` | `read_only_frame_range16`'s layout; the fill's `recursion_chunk` | chunk `c` of `4·cycle − 1 − w{j}_read_ts`, weight `2^{16(c+1)}` | `gap{j}_c{c}_range`, `gap{j}_lo_range`, and at `c = 1` `gap{j}_top_scaled` — **no gate** |
| `W[10]`, `W[11]` | `base_low`, `base_low_hi` | ditto; the fill's `recursion_frame` | `(base − RAM_ORIGIN)/4` and its high halfword | `base_aligned` (`base_low` only); the three `base_low_*` |
| `W[12]`, `W[13]` | `base_room`, `base_room_hi` | ditto | `2^31 − 20 − base` and its high halfword | `base_in_window` (`base_room` only); the three `base_room_*` |
| `W[14 + 2q + c]`, `q < 8`, `c < 2` | `gap_<q>_c{c}` | `p2_field::gap_chunk(q, c)` | chunk `c` of `4·cycle + Δ_q − 1 − <q>_read_ts`; 0 where the row does not make access `q` | that access's four obligations — **no gate** |
| `W[30]` | `lane0` | `p2_field::LANE0` | `x` where `n ≥ 1`, else `state0` | `lane0_rule`, round 0's six gates |
| `W[31]` | `lane1` | `p2_field::LANE1` | `y` where `n = 2`, 0 where `n = 1`, `state1` where `n = 0` | `lane1_rule`, round 0's six gates |
| `W[32 + k]`, `k < 349` | `r{r}_l{i}_u2`, `r{r}_l{i}_u4`, `r{r}_s{i}` | `p2_field::permutation_column(k)` | `p2_field::permutation_witness`' intermediates, in round order | below |
| `W[381]` | `mult_range16` | `p2_field::MULTIPLICITY` | `trace::build_multiplicities`' count, appended after the fill | `range16_table_num` — **and no gate** |

with access `q` = `state0`, `state1`, `state2`, `x`, `y`, `next0`, `next1`, `next2` and slot `Δ_q` =
0, 0, 0, 1, 2, 3, 3, 3 (`constants::p2_field::DELTA_*`).

**The permutation's columns, `W[32..381]`**, round by round — each S-box's `u²` and `u⁴` adjacent,
then the round's output lanes:

| rounds | kind | columns a round | addresses |
| --- | --- | --- | --- |
| 0–3 | full | 9 | `r{r}_l{i}_u2`, `r{r}_l{i}_u4` at `W[32 + 9r + 2i]`, `W[33 + 9r + 2i]`; `r{r}_s{i}` at `W[38 + 9r + i]` |
| 4–59 | partial | 5 | `r{r}_l0_u2`, `r{r}_l0_u4` at `W[68 + 5(r − 4)]`, `W[69 + 5(r − 4)]`; `r{r}_s{i}` at `W[70 + 5(r − 4) + i]` |
| 60–62 | full | 9 | `W[348 + 9(r − 60) + 2i]`, `W[349 + 9(r − 60) + 2i]`; `r{r}_s{i}` at `W[354 + 9(r − 60) + i]` |
| 63 | full, the last | 6 | `r63_l{i}_u2`, `r63_l{i}_u4` at `W[375 + 2i]`, `W[376 + 2i]`; its outputs are `M[38]`, `M[41]`, `M[44]` |

`36 + 280 + 27 + 6 = 349`. Each `u2` is read by the `square` gate that defines it and by its
`fourth`; each `u4` by the `fourth` that defines it and the round's three `out` gates; each
`r{r}_s{i}` by the `out` that defines it, the next round's three `out` gates and, where the next
round S-boxes lane `i`, the next round's `square`. `u` itself — a lane plus `rc·live` — is never a
column, and neither is an S-box's output `u·u⁴`: each is an expression inside the gates that read
it.

**`S`: none.** `V[range16]` is read by `range16_table_den` alone.

### 23.4 Gate list 0: the 160 producing columns

Relation `i` defines `L1[i]`, in tree order.

| relations | columns | what |
| --- | --- | --- |
| 0–4 | 5 | `read_w{j}`, the frame words |
| 5 | 1 | `read_anchor` |
| 6–8 | 3 | `read_state{i}` |
| 9, 10 | 2 | `read_x`, `read_y` |
| 11–13 | 3 | `read_next{i}` |
| 14, 15 | 2 | `read_pad14`, `read_pad15`, the literal 1, to 16 leaves |
| 16–31 | 16 | the write side in the same order: `write_w{j}`, `write_anchor`, `write_state{i}`, `write_x`, `write_y`, `write_next{i}`, `write_pad14`, `write_pad15` |
| 32, 33 | 2 | `range16_table_{num,den}` |
| 34–73 | 40 | the five frame gaps' four obligations, `(num, den)` each |
| 74–85 | 12 | `base_low`'s three and `base_room`'s three |
| 86–109 | 24 | `gap_state{i}`'s four, `i < 3` |
| 110–117 | 8 | `gap_x`'s four |
| 118–125 | 8 | `gap_y`'s four |
| 126–149 | 24 | `gap_next{i}`'s four, `i < 3` |
| 150–159 | 10 | `range16_pad_{0..4}`, five neutral fractions to 64 |

The pads are named by position, 14 and 15, because `delegation::leaves_with` strips the frame's own
pads, appends the eight accesses' leaves and pads again.

Every memory leaf is one pattern — §0.6's frame leaf under its own mask and at an address offset,
`delegation::masked_leaf`:

```text
pattern     m·T(space, addr + o, ts, value) + 1 − m
positional  1 + mem_gamma·m + -1·m + space·m + (mem_alpha_addr·m) ×o + (mem_alpha_ts·m) ×Δ
              + mem_alpha_addr·addr·m + <ts products> + mem_alpha_val·value·m
```

A column timestamp is the one product `mem_alpha_ts·read_ts·m`; a timestamp `4·cycle + Δ` — every
write leaf but `write_anchor`, and `read_anchor` at Δ 3 — is `(mem_alpha_ts·cycle·m) ×4` beside
the linear `(mem_alpha_ts·m) ×Δ`; the literal 0, `write_anchor`'s, is no term, and neither is its
absent value. An offset repeats `(mem_alpha_addr·m)` `o` times, as `4·cycle` repeats its term, a
coefficient being one literal or one challenge. Every real leaf is one `Quadratic` with constant
1.

| leaf | `m` | space | `addr + o` | ts | value |
| --- | --- | --- | --- | --- | --- |
| `read_w{j}` | `live` | `RAM` = 2 | `w{j}_addr` | `w{j}_read_ts` | `w{j}_read_value` |
| `write_w{j}` | `live` | 2 | `w{j}_addr` | `4·cycle + 0` | `w{j}_write_value` |
| `read_anchor` | `live` | 12 | `base` | `4·cycle + 3` | `anchor_value` |
| `write_anchor` | `live` | 12 | `base` | the literal 0 | absent |
| `read_state{i}` | `live` | `FIELD` = 10 | `w1_read_value + i` | `state{i}_read_ts` | `state{i}` |
| `write_state{i}` | `live` | 10 | `w1_read_value + i` | `4·cycle + 0` | `state{i}` |
| `read_x` | `x_live` | 10 | `w2_read_value` | `x_read_ts` | `x` |
| `write_x` | `x_live` | 10 | `w2_read_value` | `4·cycle + 1` | `x` |
| `read_y` | `y_live` | 10 | `w3_read_value` | `y_read_ts` | `y` |
| `write_y` | `y_live` | 10 | `w3_read_value` | `4·cycle + 2` | `y` |
| `read_next{i}` | `live` | 10 | `w4_read_value + i` | `next{i}_read_ts` | `next{i}_old` |
| `write_next{i}` | `live` | 10 | `w4_read_value + i` | `4·cycle + 3` | `next{i}` |

Two of them positionally, the second with its repeats folded as `×k`:

```text
read_state1   1 + mem_gamma·M[1] + -1·M[1] + 10·M[1] + mem_alpha_addr·M[1]
                + mem_alpha_addr·M[10]·M[1] + mem_alpha_ts·M[26]·M[1] + mem_alpha_val·M[27]·M[1]
write_y       1 + mem_gamma·M[33] + -1·M[33] + 10·M[33] + (mem_alpha_ts·M[33]) ×2
                + mem_alpha_addr·M[18]·M[33] + (mem_alpha_ts·M[0]·M[33]) ×4 + mem_alpha_val·M[35]·M[33]
```

**A read-only access writes back the column it read**: `write_state{i}`, `write_x` and `write_y`
take their read's value column, so the state and an absorbed cell leave the call with a new
timestamp and the same value; only the next state has distinct old and new columns. **Each access
kind has a slot of its own** — the state at 0, `x` at 1, `y` at 2, the next state at 3 — so no two
accesses at one cell share a slot, and every aliasing is legal: `x` may be `y`, either may be a
state or a destination cell, and `d` may overlap `s`. A read at a later slot consumes the earlier
one's write-back.

The fraction leaves are §0.6's: `(1, E_l + g)` per obligation; `(−mult, T + g)` for the table,
`(-1·W[381] + 0)` and `(1·V[range16] + lookup_g)`, both `Linear`; and `(0, 1)` per pad. A row
denominator is `lookup_g` plus the selector times every term of the tuple, a constant folding into
a literal on the selector, so it is one `Quadratic`:

```text
define_gap_y_lo_range_den   lookup_g + 1·M[33] + 4·M[33]·M[0] + -1·M[33]·M[34]
                              + -65536·M[33]·W[22] + 0x30644e72…f592f0000001·M[33]·W[23]
```

### 23.5 Gate list 0: the 20 frame and absorption gates

Relations 160–179, in `artifact`'s order: `read_only_frame_range16`'s thirteen, then the
absorption's seven. None reads a challenge, and every one is 0 on the all-zero row.

| relation | name | degree | positional | named |
| --- | --- | --- | --- | --- |
| 160 | `live_boolean` | 2 | `0 + 1·M[1] + -1·M[1]·M[1]` | `live − live²` |
| 161–165 | `addr_w{j}` | 2 | `0 + -4j·M[1] + 1·M[1]·M[4+4j] + -1·M[1]·M[2]` | `live·(w{j}_addr − base − 4j)` |
| 166 | `base_aligned` | 2 | `0 + -65536·M[1] + 1·M[1]·M[2] + -4·M[1]·W[10]` | `live·(base − RAM_ORIGIN − 4·base_low)` |
| 167 | `base_in_window` | 2 | `0 + 2147483628·M[1] + -1·M[1]·M[2] + -1·M[1]·W[12]` | `live·((2^31 − 20) − base − base_room)` |
| 168–172 | `writes_back_w{j}` | 1 | `1·M[7+4j] + -1·M[6+4j] + 0` | `w{j}_write_value − w{j}_read_value` |
| 173 | `x_live_boolean` | 2 | `0 + 1·M[30] + -1·M[30]·M[30]` | `x_live − x_live²` |
| 174 | `y_live_boolean` | 2 | `0 + 1·M[33] + -1·M[33]·M[33]` | `y_live − y_live²` |
| 175 | `y_needs_x` | 2 | `0 + 1·M[33] + -1·M[30]·M[33]` | `y_live·(1 − x_live)` |
| 176 | `x_needs_live` | 2 | `0 + 1·M[30] + -1·M[30]·M[1]` | `x_live·(1 − live)` |
| 177 | `n_word` | 1 | `1·M[6] + -1·M[30] + -1·M[33] + 0` | `n − x_live − y_live` |
| 178 | `lane0_rule` | 2 | `0 + 1·W[30] + -1·M[25] + -1·M[30]·M[32] + 1·M[30]·M[25]` | `lane0 − x_live·x − (1 − x_live)·state0` |
| 179 | `lane1_rule` | 2 | `0 + 1·W[31] + -1·M[27] + 1·M[30]·M[27] + -1·M[33]·M[35]` | `lane1 − (1 − x_live)·state1 − y_live·y` |

`RAM_ORIGIN` is 65,536 and the frame 20 bytes, so `2^31 − 20` is 2,147,483,628. There is no
`gap_w{j}` gate: the frame's gaps are §23.7's obligations, the bound and the decomposition at once.
`x_live_boolean` and `y_live_boolean` are owed twice over — `check_memory` requires a booleanity
gate for every `M` leaf mask and `validate` one for every lookup selector, and both columns are
both.

Four notes, each a thing that is easy to get wrong.

- **`n_word` is what ties the capacity's count to what was absorbed, and it is ungated.** Lane 2
  adds the frame word `n` itself, so without it a row could count 2 and absorb nothing, or absorb
  two cells and count 0. On a padding row it is what makes `n` 0, the masks being 0 there.
- **`y_needs_x` is load-bearing.** Without it `n = 1` has a second spelling,
  `(x_live, y_live) = (0, 1)`, which passes `n_word` and gives `lane0 = state0` and
  `lane1 = state1 + y` — `y` added into the rate with `s₀` kept, which is no step of any
  transcript. With it the masks are a function of `n`: `(0, 0)`, `(1, 0)`, `(1, 1)`.
- **`x_needs_live` keeps every field access on an invocation**: without it a padding row could set
  `x_live` and make an `x` access, read and written back, on a row that requests nothing.
- **`x` and `y` are free on a live row whose mask is 0.** `lane0_rule` reads `x` only as
  `x_live·x` and `lane1_rule` reads `y` only as `y_live·y`, and their leaves and gap obligations
  carry the same masks. The honest fill writes 0 there.

### 23.6 Gate list 0: the 352 permutation gates

Relations 180–531, one block a round in round order. A full round's block is `r{r}_l{i}_square`
and `r{r}_l{i}_fourth` for `i` = 0, 1, 2, interleaved, then `r{r}_out0`–`r{r}_out2`: nine
relations. A partial round's is `r{r}_l0_square`, `r{r}_l0_fourth`, `r{r}_out0`–`r{r}_out2`:
five.

| relations | rounds | kind | gates |
| --- | --- | --- | --- |
| 180–188 | 0 | full, the initial external matrix folded in | 9 |
| 189–215 | 1–3 | full | 27 |
| 216–495 | 4–59 | partial, round `r` at `216 + 5(r − 4)` to `220 + 5(r − 4)` | 280 |
| 496–522 | 60–62 | full | 27 |
| 523–531 | 63 | full, its outputs `next0`–`next2` | 9 |

Write `rc_{r,i}` for round `r`'s constant on lane `i`: `POSEIDON2_RC3_INITIAL[r][i]` for `r < 4`,
`POSEIDON2_RC3_INTERNAL[r − 4]` on lane 0 alone for `4 ≤ r < 60`, and
`POSEIDON2_RC3_TERMINAL[r − 60][i]` for `r ≥ 60` — `transcript::poseidon2_permute`'s own tables,
read by `p2_field`'s `rounds` with no second copy. Round `r`'s input lanes are `r{r−1}_s{i}`, and
round 0's are the external matrix over the absorbed lanes:

```text
E0 = 2·lane0 + lane1 + state2 + n
E1 = lane0 + 2·lane1 + state2 + n
E2 = lane0 + lane1 + 2·(state2 + n)
```

An S-boxed lane's input is `u = E_i + rc·live` in round 0 and `u = r{r−1}_s{i} + rc·live` after,
and its S-box output is `v = u4·u = u⁵`. A full round's output is `M_E·v` with
`M_E = [[2,1,1],[1,2,1],[1,1,2]]`; a partial round S-boxes lane 0 alone and its output is
`M_I·(v_0, s_1, s_2)` with `M_I = [[2,1,1],[1,2,1],[1,1,3]]`, `s_i` the round's input lanes.

| gate | count | products, positionally | named |
| --- | --- | --- | --- |
| `r0_l{i}_square` | 3 | 21, 21, 28 | `r0_l{i}_u2 − (E_i + rc_{0,i}·live)²` |
| `r{r}_l{i}_square`, `r ≥ 1` | 77 | 3 | `r{r}_l{i}_u2 − (r{r−1}_s{i} + rc_{r,i}·live)²` |
| `r{r}_l{i}_fourth` | 80 | 1 | `r{r}_l{i}_u4 − r{r}_l{i}_u2²` |
| `r0_out{i}` | 3 | 25, 25, 26 | `r0_s{i} − (M_E·v)_i` |
| `r{r}_out{i}`, full, `r ≥ 1` | 21 | 8 | `r{r}_s{i} − (M_E·v)_i`; at `r = 63` the column is `next{i}` |
| `r{r}_out0`, partial | 56 | 4, beside the linear `s_1` and `s_2` | `r{r}_s0 − 2·v_0 − s_1 − s_2` |
| `r{r}_out1`, `r{r}_out2`, partial | 112 | 2, beside three linear terms | `r{r}_s1 − v_0 − 2·s_1 − s_2` and `r{r}_s2 − v_0 − s_1 − 3·s_2` |

`3 + 77 + 80 + 3 + 21 + 56 + 112 = 352`. Every one is a `Quadratic` with constant 0, of degree 2,
that reads no challenge.

**The positional form does not merge terms**, and that is where the product counts come from.
`p2_field`'s `Expr` squares a linear form term by term and adds forms by concatenation, so `E0`'s
`2·lane0` is two `lane0` terms, and its square with `rc·live` is 21 products where the merged
square of five distinct operands is 15; `E2`'s seven terms give 28. A full round's output repeats
its own lane's `v`, `(M_E·v)_0 = v_0 + v_1 + v_2 + v_0`, so it carries `v_i`'s two products twice.
A constant appears as `−2·rc` on each `x·live` product of a square, `−rc²` on its `live·live`, and
`−rc` on an output's `u4·live`; the dump prints each as 64 hex digits. Round 4, the first partial
round, reads in full:

```text
216 r4_l0_square   0 + 1·W[68] + -1·W[65]·W[65] + 0x2c8e9069…74d05698·W[65]·M[1]
                     + 0x112265e8…f9f55bb1·M[1]·M[1]
217 r4_l0_fourth   0 + 1·W[69] + -1·W[68]·W[68]
218 r4_out0        0 + 1·W[70] + -1·W[66] + -1·W[67] + -1·W[69]·W[65] + 0x16474834…ba682b4c·W[69]·M[1]
                     + -1·W[69]·W[65] + 0x16474834…ba682b4c·W[69]·M[1]
219 r4_out1        0 + 1·W[71] + -1·W[66] + -1·W[67] + -1·W[66] + -1·W[69]·W[65]
                     + 0x16474834…ba682b4c·W[69]·M[1]
220 r4_out2        0 + 1·W[72] + -1·W[66] + -1·W[67] + -2·W[67] + -1·W[69]·W[65]
                     + 0x16474834…ba682b4c·W[69]·M[1]
```

with `W[65..68]` `r3_s0`–`r3_s2`, `W[68]` `r4_l0_u2`, `W[69]` `r4_l0_u4`, `W[70..73]`
`r4_s0`–`r4_s2`, and the three literals `−2·rc_4`, `−rc_4²` and `−rc_4` for
`rc_4 = POSEIDON2_RC3_INTERNAL[0]`.

**Why every gate is degree 2.** The S-box `u⁵` is split at its squares: `u²` and `u⁴` are columns,
and `u·u⁴` is a product of a column and a linear form inside the output gate that consumes it. A
constant rides `live`, a column times a literal. Besides its own 349 columns and `live`, the block
reads only round 0's inputs — `lane0`, `lane1`, `state2` and the frame word `n` — and it writes
outside them only `next0`–`next2`.

### 23.7 The 58 lookups and the channel

One channel, `RANGE16` = channel 1, table `V[range16]`, multiplicity `W[381]`. The tuple is one
expression wide, so it reads `g` and no power of `β`. The helpers are
`delegation::{read_only_frame_range16, gap_lookups_range16, bound_chunked}` and
`Access::gap_lookups`.

| obligation | relations (num, den) | count | selector | tuple | shape |
| --- | --- | --- | --- | --- | --- |
| `gap{j}_c0_range`, `gap{j}_c1_range`, `j < 5` | 34–73 | 10 | `live` | `gap{j}_c{c}` | direct: each chunk below `2^16` |
| `gap{j}_top_scaled` | ” | 5 | `live` | `1024·gap{j}_c1` | scaled: the top chunk below `2^6` |
| `gap{j}_lo_range` | ” | 5 | `live` | `4·cycle − w{j}_read_ts − 2^16·c0 − 2^32·c1 − 1` | the derived low sixteen bits |
| `base_low_c0_range`, `base_low_top_scaled`, `base_low_lo_range` | 74–79 | 3 | `live` | `base_low_hi`, `8·base_low_hi`, `base_low − 2^16·base_low_hi` | `[0, 2^29)` |
| `base_room_c0_range`, `base_room_top_scaled`, `base_room_lo_range` | 80–85 | 3 | `live` | `base_room_hi`, `2·base_room_hi`, `base_room − 2^16·base_room_hi` | `[0, 2^31)` |
| `gap_state{i}_*`, `i < 3` | 86–109 | 12 | `live` | the frame's four over `state{i}_read_ts`, constant `−1` | the read precedes slot 0 |
| `gap_x_*` | 110–117 | 4 | `x_live` | over `x_read_ts`, constant 0 | precedes slot 1 |
| `gap_y_*` | 118–125 | 4 | `y_live` | over `y_read_ts`, constant `+1` | precedes slot 2 |
| `gap_next{i}_*`, `i < 3` | 126–149 | 12 | `live` | over `next{i}_read_ts`, constant `+2` | precedes slot 3 |

Each word's and each access's four are `_c0_range`, `_c1_range`, `_top_scaled` and `_lo_range`, in
that order. Access `q`'s derived low half is

```text
4·cycle + Δ_q − 1 − <q>_read_ts − 2^16·gap_<q>_c0 − 2^32·gap_<q>_c1
gap_y_lo_range, positionally:   4·M[0] + -1·M[34] + -65536·W[22] + 0x30644e72…f592f0000001·W[23] + 1
```

whose constant `Δ_q − 1` is the `−1`, `0`, `+1`, `+2` above, the long literal being `−2^32`.

**A field access carries the gap check every read carries** (`recursion.md` §2.1): 38 bits, two
committed chunks and a derived low half, `38 = 16 + 16 + 6`, exact at `2^38 − 1`. `TIMESTAMP` would
need `2^20` rows; `FQ_OP` takes that height for it (`recursion.md` §6), and this family's `2^18`
does not have it.

**`lookup::check_copowers` takes fifteen pairs**, each top chunk with the selector its scaled
obligation carries: the five frame gap tops, `base_low_hi` and `base_room_hi` under `live`
(`delegation::frame_scaled_range16`), the six state and next tops under `live`, `gap_x_c1` under
`x_live` and `gap_y_c1` under `y_live` (`Access::scaled`). The scaled obligation alone bounds
nothing — `2^{16−r}` is a unit in `Fr` — and the direct pair under the same selector is its
premise.

**Every obligation is gated by the mask of the access it bounds**, so an access the row does not
make neither bounds nor is bounded: its gated tuple is the all-zero one, a real entry of the table,
and the multiplicity counts it.

| channel | output positions | table columns | multiplicity |
| --- | --- | --- | --- |
| `RANGE16` = 1 | 2, 3 | `V[range16]` | `W[381]` |

**58 obligations and the table fraction are 59 leaves of a 64-leaf tree.** One more field access —
a leaf a side and four obligations — fits both trees; a second fills the memory trees exactly and
doubles the `RANGE16` tree.

`trace::build_multiplicities` counts each table row over the 58 gated tuples of every row of the
shard, a padding row and an unmade access contributing zeros, and appends the column after the
fill; `fill::p2_field` does not write it.

### 23.8 The trees, the inner layers and the outputs

Three trees. The memory product trees are 14 real leaves a side padded to 16; the `RANGE16`
fraction tree is 59 leaves padded to 64. `R = 6`, the fraction tree setting it alone — a 16-leaf
product tree is 4 deep — so the depth is `N = 1 + 6 + n`: seven row-wise lists, then `n` halving
lists. Each row-wise list reduces every tree pairwise, and a tree already at one node copies itself
up.

| layer | read tree | write tree | `range16` | width |
| --- | --- | --- | --- | --- |
| `L1` | 16 | 16 | 128 | 160 |
| `L2` | 8 | 8 | 64 | 80 |
| `L3` | 4 | 4 | 32 | 40 |
| `L4` | 2 | 2 | 16 | 20 |
| `L5` | 1 | 1 | 8 | 10 |
| `L6` | 1 | 1 | 4 | 6 |
| `L7` | 1 | 1 | 2 | 4 |
| `L8`–`L{n+7}` | 1 | 1 | 2 | 4 each |

so `inner = 320 + 4n` — 392 at `n = 18`, 384 at `n = 16`. The product trees reach one node at `L5`
and are carried as `Linear` copies through `L6` and `L7`; the fraction tree reaches one pair at
`L7`.

Relations: **0–159** are list 0's producing gates (§23.4), **160–531** its 372 enforcing gates
(§23.5, §23.6), **532–611** list 1, **612–651** list 2, **652–671** list 3, **672–681** list 4,
**682–687** list 5, **688–691** list 6, and halving list `k` (`7 ≤ k ≤ n + 6`) holds
`692 + 4(k − 7)` to `695 + 4(k − 7)`. The roots are relations `688 + 4n` to `691 + 4n`:
**760–763** at `n = 18`, **752–755** at `n = 16`. Inner nodes are `read_{k}_{j}`, `write_{k}_{j}`
and `range16_{k}_{j}_{num,den}`, the last list's `read_root`, `write_root`, `range16_num_root` and
`range16_den_root`. Each halving list is four gates: the two memory `TreeProduct`s, the channel's
denominator `TreeProduct` and its numerator `TreeCross`.

| output | `PolyAddress` at `n = 18` | name | read by |
| --- | --- | --- | --- |
| 0 | `L{25}[0]` | `read_root` | `verify_shard` step 10a, against `memory_roots[p]` for `p` the position of `(20, shard_index)` in `verifier_core::statement_shards`; and step 10b's cross-shard product |
| 1 | `L{25}[1]` | `write_root` | ditto |
| 2, 3 | `L{25}[2..4]` | `range16_num_root`, `range16_den_root` | step 9: `num = 0` **and** `den ≠ 0`, the failure `Lookup { channel: 1 }` |

### 23.9 Witness rows

**There is no row table here**: a live row is 427 committed cells, 349 of them the permutation's.
What stands in for one is a chain of readings, every one in the ordinary workspace run but the
last.

1. `crates/constraints/src/p2_field.rs`' unit test `the_witness_is_the_permutation` evaluates the
   352 permutation gates directly over `Fr` on `permutation_witness([7, 11, 13])` with `live = 1`,
   and requires each to vanish — the witness generator the fill calls and the gates are one
   spelling — besides holding `permutation_witness` to `PERMUTATION_COLUMNS` columns and the `W`
   names to `WITNESS_COLUMNS`.
2. `crates/emulator/tests/guests.rs`' `field_ops_checks_itself_under_the_recursion_ecalls`:
   `guests/field-ops` exits 26, every check passing — among them one duplex step at each of
   `n = 2, 1, 0` whose exported lanes equal literals `transcript::poseidon2_permute` computed
   host-side, and a step replayed from a tape whose lane 0 equals a direct call's — and its trace
   holds exactly 5 `P2_FIELD` invocations.
3. `crates/checker/tests/recursion.rs`' `the_field_families_hold_and_the_field_memory_balances`
   fills a `2^16` shard of those five with `prover::family_fill` and evaluates every live row and
   the first padding row through `checker::violated_relations` and `checker::violated_lookups`.
   The `next` columns are the executor's writes — `poseidon2_permute`'s output — while the
   intermediates are `permutation_witness`', so a permutation the circuit spells differently from
   the transcript breaks `r63_out*` there. The same test multiplies the eight accesses' field
   leaves on every live row into one product with the `FIELD_WINDOWS` shard's teardown and init
   leaves and requires reads to equal writes: a slot or an offset the circuit and the executor
   disagree on is a tuple with no partner.
4. `crates/constraints/tests/recursion.rs`' `the_recursion_families_build_in_the_recursion_registry_alone`
   builds the circuit at `2^18` — `validate`, `check_memory` and `check_discharge` with it —
   asserts that the all-zero row pads, and that `family_circuit(20, 18)` is `None`.
5. `crates/prover/tests/field_ops.rs`' `the_recursion_format_proves_and_verifies` — deferred,
   `#[ignore]`d — proves `guests/field-ops` as one block holding exactly one `P2_FIELD` shard,
   verifies it through `verify_block`, holds the shard's witness commitments to
   `stack_count(382, σ)`, and replays the shard's tape against `verify_shard_local` and
   `pcs::batch_verify_deferred`.

An honest live row, in words:

| column group | value |
| --- | --- |
| `cycle`, `live`, `base`, `anchor_value` | the requesting cycle; 1; the frame pointer, 4-aligned, in `[RAM_ORIGIN, 2^31 − 20]`; 0 |
| `w{j}_addr`, `w{j}_read_ts` | `base + 4j`, and the last write to that word |
| `w{j}_read_value`, `w{j}_write_value` | `n`, `s`, `x`'s cell, `y`'s cell, `d`, each written back unchanged |
| `gap{j}_c{c}`, `gap_<q>_c{c}` | bits `[16(c+1), 16(c+2))` of `4·cycle + Δ − 1 − read_ts`; 0 for an access the row does not make |
| `base_low`, `base_room` and their halfwords | `(base − RAM_ORIGIN)/4` and `2^31 − 20 − base` |
| `state{i}_read_ts`, `state{i}` | the last write to cell `s + i`, and its value |
| `x_live`, `x_read_ts`, `x` | 1, the last write to cell `x` and its value, where `n ≥ 1`; 0, 0, 0 otherwise |
| `y_live`, `y_read_ts`, `y` | the same where `n = 2` |
| `next{i}_read_ts`, `next{i}_old`, `next{i}` | the last write to cell `d + i`, what it held, and lane `i` of `poseidon2_permute(lanes)` |
| `lane0`, `lane1` | the absorbed rate |
| `r{r}_l{i}_u2`, `r{r}_l{i}_u4`, `r{r}_s{i}` | `u²` and `u⁴` of each S-box input `u = lane + rc`, and each round's output lanes but the last's |
| `mult_range16` | `trace`'s count; 0 on a table row no tuple names |

and a padding row is 0 in every one of them.

### 23.10 What fixes each cell

Read off the artifact's gates and obligations — `checker dump`'s read sets — and not off a tamper
table: no suite corrupts a cell of this family and names what refuses it, so this is an account,
not a test.

| cell | what fixes it |
| --- | --- |
| `cycle`, `base` | the multiset: the request's mirror write is `T(DELEGATION_P2_FIELD, base, 4·cycle + 3, v)` and this row's teardown read is its only reader, and every frame and field write rides `4·cycle`; locally `base_aligned`, `base_in_window` and `addr_w{j}` |
| `live` | `live_boolean`, and the 24 leaves it masks; through `x_needs_live` and `y_needs_x` it also switches the `x` and `y` accesses off |
| `anchor_value` | nothing locally: the request's `deleg_write_value` must equal it, and the memory argument is what says so (§26 observation 19) |
| `w{j}_addr` | `addr_w{j}`, against `base` |
| `w{j}_read_ts` | the multiset; the four `gap{j}_*` obligations hold it below this row's own write |
| `w{j}_write_value` | `writes_back_w{j}`: the frame is read-only |
| `n` (`w0_read_value`) | the frame's read tuple and `n_word` |
| `s`, `d`, `x`'s and `y`'s cells (`w1`–`w4` read values) | the frame's read tuples; as addresses, the field leaves — a cell no window covers cannot balance. No gate or obligation bounds them |
| `x_live`, `y_live` | their booleanity, `n_word`, `y_needs_x` and `x_needs_live`: `(0, 0)`, `(1, 0)`, `(1, 1)` for `n` = 0, 1, 2, and `(0, 0)` on a padding row |
| `state{i}`, `state{i}_read_ts` | the multiset: the read consumes the cell's last write, and the write-back at `4·cycle + 0` carries the same column; `gap_state{i}_*` holds the stamp below it |
| `x`, `x_read_ts`; `y`, `y_read_ts` | the same, where the access's mask is 1; nothing where it is 0 |
| `next{i}_read_ts` | the multiset, and `gap_next{i}_*` |
| `next{i}_old` | **the multiset alone**: its read leaf is its only reader, a destination's old value being no input of the duplex |
| `next{i}` | `r63_out{i}`, and the write leaf that publishes it to the field memory |
| `lane0`, `lane1` | `lane0_rule`, `lane1_rule` |
| `r{r}_l{i}_u2`, `r{r}_l{i}_u4`, `r{r}_s{i}` | the `square`, `fourth` or `out` gate that defines it, whose one unknown it is once the round before is fixed |
| `gap{j}_c{c}`, `gap_<q>_c{c}`, `base_low_hi`, `base_room_hi` | their own obligations and nothing else — no gate reads any of these 28 |
| `base_low`, `base_room` | `base_aligned` and `base_in_window`, and their `lo_range` obligations |
| `mult_range16` | `trace::build_multiplicities`, and the channel's root check — no gate reads it |
| the padding row | `check_padding`'s all-zero row, subject to §23.2's padding paragraph |

---

## 24. `FIELD_IO` — family 21

### 24.1 Header

`recursion_circuit(21, n)` is `field_io::artifact(n)` with `field_io::channels()`, which is **one
`RANGE16` channel**, and `family_circuit(21, n)` is `None` at every `n`: this is one of the five
families only the **recursion** registry holds (`recursion.md` §1.2), so no base key can name it,
and a program that declares it has `FIELD_WINDOWS` in its config and is in the recursion format
(§1.1). Like `MOD_MUL` and `FR_ARITH` it is built by `memory::assemble`: every constraint it
makes is an enforcing gate on gate list 0, so above the leaves it is two product trees, one
fraction tree and nothing else. Normative spec: `recursion.md` **§5**, with §1.4 (the request's
`a0`) and §2 (the field memory); the frame and the anchor are `delegation.md` §4 and §5,
consumed unchanged. Fill: `prover::family_fill(21)`, the private `fill::field_io`. Ecall `0x050B`
(`ecall::PRECOMPILE_FIELD_IO`), anchor space `address_space::DELEGATION_FIELD_IO` = 13, and the
cell's space `address_space::FIELD` = 10. S-RECURSION added it.

**82 committed columns (43 `M`, 39 `W`, no `S`) and one virtual table, `V[range16]`.** Gate list
0 writes 288 columns — 16 leaves a side of the two memory trees plus the `RANGE16` tree's 128
fraction pairs — and holds **24 enforcing gates (5 degree-1, 19 degree-2)**. **70 obligations**,
all `RANGE16`, 54 under `live` and 16 under `export`; **4 outputs**. At its default `n = 18`
there are 26 gate lists (8 row-wise and 18 halving), the top is `L26`, and the circuit has 650
inner columns and 674 relations, 164,713 bytes of wire form — the `FIELD_IO` line of
`crates/constraints/tests/vectors/recursion.txt`, SHA-256 `e2ae7397…2dc3fd75`, which
`cargo run -p kat-gen -- recursion` writes and CI regenerates and diffs. Of those counts only the
list count, the top and the inner and relation totals depend on `n`: `8 + n` lists,
`inner = 578 + 4n`, `relations = 602 + 4n`. A height adds halving lists and nothing else, one
node per output each.

`artifact` asserts the memory and witness widths, `MEMORY_COLUMNS` (43) and `WITNESS_COLUMNS`
(39), and panics on a refusal of `lookup::check_copowers` over its 14 scaled columns (§24.6);
`memory::assemble` runs `validate`, `memory::check_memory` and, the family declaring a channel,
`lookup::check_discharge`, and panics on each. **There is no `check_shape`**: unlike the six base
delegation families, nothing at construction requires a relation by name or counts the
obligations, so what moves when a gate or an obligation is dropped is the digest in
`recursion.txt`.

**One row is one move.** `IMPORT` (op 1) sets the cell to `Σ_k w_k·2^{32k}` over `Fr` — that is,
mod `p` — from the eight RAM words `ptr, ptr + 4, …, ptr + 28`, and leaves the words as they
were. `EXPORT` (op 2) writes into those eight words eight limbs below `2^32` whose weighted sum is
congruent to the cell, and leaves the cell as it was. The frame `[op, cell, ptr]` is three words,
12 bytes, read-only. A recursion node's tapes take their inputs into the field memory through
`IMPORT` alone (`recursion.md` §7), and its journal leaves the field memory through `EXPORT`
(`recursion.md` §8.2).

**The height is `2^18`, a choice above a floor of 16.** `RANGE16`'s table needs sixteen
variables, so the derived minimum-height guard makes `recursion_circuit(21, n)` `None` below 16;
`DEFAULT_HEIGHTS[FIELD_IO]` is `2^18`, 262,144 moves a shard. The leaf `recursion.md` §8.3
measures over block 257510's first 32 base shards makes 81,137 `FIELD_IO` calls — one `2^18`
shard. The forward pass is 578 × 2^18 × 32 = 4.85 GB over the eight row-wise layers, the
eighteen halving layers adding 34 MB: **computed, not measured**. In the recursion format the
shard's 43 `M` and 39 `W` columns are **one stack each** at `n = 18`: `VmConfig::stack_vars` gives
`σ = 6`, which is both the wider phase's need (43 columns, 64 slots) and `24 − n`
(`recursion.md` §1.3).

**This family's §0.5 counts are at `n = 18`**: 203 `Linear`, 157 `Product`, 242 `Quadratic`, 54
`TreeProduct` (3 a halving list) and 18 `TreeCross` (1 a halving list), summing to 674.

### 24.2 Row kinds

Three, and none is an instruction: **this family is invoked, not decoded**. It claims no pc,
`program::lookup_tuple(21)` is empty, it owns no cycle, it is not in
`constants::family::CYCLE_OWNING`, and it is in a `VmConfig` exactly when the linked binary
declares it (`.rodata.apogee.delegations.field_io`). **One row is one move**, `IMPORT` or
`EXPORT`; there is no no-op kind.

| row kind | `live` | `import`, `export` | what the row holds | what it adds to the multiset |
| --- | --- | --- | --- | --- |
| an **import** | 1 | 1, 0 | the requesting cycle, the frame base, the three frame words read and written back, the eight data words read and written back unchanged, the cell's old value and its new one, two gap chunks for each of the twelve reads, and the frame pointer's four columns | 13 read tuples and 13 write tuples: the 3 frame words at `(RAM, base + 4j)`, the anchor pair at `(DELEGATION_FIELD_IO, base)`, the 8 data words at `(RAM, ptr + 4k)` and the cell at `(FIELD, cell)` |
| an **export** | 1 | 0, 1 | the same, but the cell written back unchanged and the eight words rewritten with limbs congruent to it, each with its high halfword | the same 13 and 13 |
| **padding** | 0 | 0, 0 | every committed cell 0 **as the honest fill writes it**, the multiplicity column excepted | nothing: all 32 leaves are 1 — 26 real ones collapse to the product's identity and 6 are pads that are literally 1 — and 70 gated zeros the channel counts |

An import row adds 16 gated zeros to the channel too: the eight exported-word pairs carry
`export`.

**The request is the recursion format's `ADD_SUB_LUI_AUIPC`**, an ecall row with `a7 = 0x050B`
whose `is_deleg` selector for registry row 8 puts tag 13 on the `deleg` mirror. It does not write
0 into `a0`: its `deleg_a0_rule` writes the base advanced past the frame, `a0 + 12`
(`recursion.md` §1.4, `constants::delegation::a0_after`), so back-to-back calls walk consecutive
frames. `crates/checker/tests/add_sub.rs`' `a_recursion_request_advances_a0_past_its_frame`
holds it.

**What is not provable**, and what refuses it first:

| what | the circuit | the executor |
| --- | --- | --- |
| an op word other than 1 or 2 | `op_word` with `one_op_a_live_row` and the two booleanities | `EmuError::DelegationFrame`, "the op is not one FIELD_IO answers" |
| a frame base not word-aligned, or a frame not inside `[RAM_ORIGIN, 2^31)` | `base_aligned`, `base_in_window` | `Misaligned`, `OutOfBounds` (`delegation.md` §4) |
| a data word no window initializes — `ptr` not a multiple of 4, or `ptr + 4k` outside every RAM, public and advice window | the multiset alone: the read tuple has no write to consume | `Misaligned` or `OutOfBounds` (`data_word`, over `trace::addressable`), and `ptr + 4k` past `2^32` as `OutOfBounds` |
| a cell no `FIELD_WINDOWS` window covers | the multiset alone (`recursion.md` §2.2) | nothing to refuse: `MemoryState::field_windows` takes as many windows as the highest touched cell needs |

**A padding row is all-zero because the fill writes it so, not because the gates force it.** On a
padding row `one_op_a_live_row` and the two booleanities force `import = export = 0`, `op_word`
then forces the op word's read value to 0, and the three `writes_back_w{j}` hold each frame
word's write value to its read value. Nothing else reaches the row: every other gate carries
`live`, `import` or `export` as a factor, and every obligation's selector is `live` or `export`,
so a padding row could legally carry anything in its data, cell, timestamp, gap and base
columns. It is harmless — every leaf is the product's identity, and the row requests nothing and
pairs with no anchor — and `zero_row_valid` is `true`, decided at construction from every
enforcing gate's constant being 0.

### 24.3 The base layer

**Memory-argument columns, `M[0..43]`** — filled by `fill::field_io` through the shared
`recursion_frame` (`delegation_frame_range16`, with the base columns after the gap chunks) and
`access_columns`; committed in `PublicInputs::memory_commitments`, absorbed at G8 before the
memory challenges.

| address | name | Rust | what it is | honest fill | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `delegation::CYCLE` | the requesting cycle | the cycle, `Fr`-backed | `read_anchor` and the twelve write leaves other than `write_anchor`, each as `4·cycle`; the twelve gap `_lo_range` obligations |
| `M[1]` | `live` | `delegation::LIVE` | the row's one mask: the frame, the anchor, the data words and the cell are one invocation | 1 on an invocation, 0 on padding | `live_boolean`, `addr_w{j}`, `base_aligned`, `base_in_window`, `one_op_a_live_row`; the mask of all 26 real leaves; the selector of 54 obligations |
| `M[2]` | `base` | `delegation::BASE` | the frame base, `a0` at the request | `u32` | both anchor leaves' address, `addr_w{j}`, `base_aligned`, `base_in_window` |
| `M[3]` | `anchor_value` | `delegation::ANCHOR_VALUE` | the anchor teardown's value, **free on both sides** | 0 | `read_anchor` alone |
| `M[4 + 4j + f]`, `j < 3` | `w{j}_addr`, `w{j}_read_ts`, `w{j}_read_value`, `w{j}_write_value` | `delegation::word(j, f)` | frame word `j`: 0 the op, 1 the cell, 2 `ptr` (`constants::field_io::{OP_WORD, CELL_WORD, PTR_WORD}`) | `base + 4j`; the last write's timestamp, `Fr`-backed; the word read, and the same word written back | `read_w{j}`, `write_w{j}`, `addr_w{j}`, `gap{j}_lo_range`, `writes_back_w{j}`; and as values: word 0 by `op_word`, word 1 as `read_cell`'s and `write_cell`'s address, word 2 as all sixteen data leaves' |
| `M[16 + 3k]`, `k < 8` | `data{k}_read_ts` | `field_io::data_read_ts(k)` | when word `ptr + 4k` was last written | `Fr`-backed | `read_data{k}`, `gap_data{k}_lo_range` |
| `M[17 + 3k]` | `data{k}_read` | `field_io::data_read(k)` | the word before the row | `Fr`-backed, the executor's `u32` | `read_data{k}`, `import_rule`, `import_keeps_word{k}` |
| `M[18 + 3k]` | `data{k}_write` | `field_io::data_write(k)` | the word after it | `Fr`-backed: the read word on an import, limb `k` of the cell's canonical bytes on an export | `write_data{k}`, `import_keeps_word{k}`, `export_rule`, `word{k}_lo_range` |
| `M[40]` | `cell_read_ts` | `field_io::CELL_READ_TS` | when the cell was last written | `Fr`-backed | `read_cell`, `gap_cell_lo_range` |
| `M[41]` | `cell_old` | `field_io::CELL_OLD` | the cell before the row — 0 if nothing wrote it, the `FIELD_WINDOWS` init | `Fr` | `read_cell`, `export_keeps_cell`, `export_rule` |
| `M[42]` | `cell_new` | `field_io::CELL_NEW` | the cell after it | `Fr`: the imported element, or `cell_old` on an export | `write_cell`, `import_rule`, `export_keeps_cell` |

**Witness columns, `W[0..39]`** — all filled by `fill::field_io` except the last; committed in
`ShardProof::witness_commitments`, absorbed at S3, with `g` drawn after them at S4.

| address | name | Rust | what it is | honest fill | read by |
| --- | --- | --- | --- | --- | --- |
| `W[2j + c]`, `j < 3`, `c < 2` | `gap{j}_c{c}` | `delegation::frame_witness_range16`'s layout; `fill::recursion_chunk` | chunk `c` of frame word `j`'s gap `4·cycle − 1 − w{j}_read_ts`, weight `2^{16(c+1)}` | bits 16–31, then 32–37, of the gap | its obligations alone |
| `W[6..10]` | `base_low`, `base_low_hi`, `base_room`, `base_room_hi` | — | `(base − RAM_ORIGIN)/4` and `2^31 − 12 − base`, each with its high halfword | | `base_aligned` reads `base_low` and `base_in_window` `base_room`; the rest, obligations alone |
| `W[10 + 2k + c]`, `k < 8` | `gap_data{k}_c{c}` | `field_io::gap_chunk(k, c)` | data word `k`'s gap `4·cycle − data{k}_read_ts` | as the frame's | its obligations alone |
| `W[26]`, `W[27]` | `gap_cell_c0`, `gap_cell_c1` | `field_io::gap_chunk(8, c)` | the cell's gap `4·cycle − 1 − cell_read_ts` | as the frame's | its obligations alone |
| `W[28]` | `import` | `field_io::IMPORT` | `IMPORT`'s selector | 1 on an import row | `import_boolean`, `one_op_a_live_row`, `op_word`, `import_rule`, the eight `import_keeps_word{k}` |
| `W[29]` | `export` | `field_io::EXPORT` | `EXPORT`'s selector, and the sixteen word obligations' | 1 on an export row | `export_boolean`, `one_op_a_live_row`, `op_word`, `export_keeps_cell`, `export_rule`; the selector of 16 obligations |
| `W[30 + k]` | `word{k}_hi` | `field_io::word_hi(k)` | exported word `k`'s high halfword | `data{k}_write >> 16` on an export row, 0 on every other | `word{k}_hi_range`, `word{k}_lo_range` alone |
| `W[38]` | `mult_range16` | `field_io::MULTIPLICITY` | the `RANGE16` table's count | `trace::build_multiplicities`, not the fill | `range16_table_num` alone |

**35 of the 39 witness columns are read by no enforcing gate.** The 24 gap chunks, `base_low_hi`,
`base_room_hi` and the eight `word{k}_hi` exist only to be the direct half of a range check, and
`mult_range16` is read only by the leaf `range16_table_num`. The four a gate reads are
`base_low`, `base_room`, `import` and `export`. Every value the fill writes is the executor's or
a function of it: the selectors read off the op word, the halfwords off the written words, and
the gap chunks and the base's four columns off the timestamps and the base.

**Where each value reads from.** An import's input is the eight words' `read` values and its
output the cell's `new`; an export's input is the cell's `old` value and its output the eight
words' `write` values. The side a move does not change is written back by a gate of its own —
`import_keeps_word{k}` on an import, `export_keeps_cell` on an export — and the frame by the
three `writes_back_w{j}`, so a move can rewrite neither its source nor its frame.

**No address column and no address bound.** A data word's address is the frame's `ptr`,
`w2_read_value` = `M[14]`, plus `4k`, read straight into its two leaves; the cell's is
`w1_read_value` = `M[10]`. There is no `addr` column for either, no alignment decomposition and no
range obligation: what makes `ptr + 4k` a word and the cell a cell is the multiset, a tuple at an
address no window initializes having no write to consume (`recursion.md` §5, §2.2). Every RAM
window's addresses are `4h·w + 4·row`, so a `ptr` that is not a multiple of 4 reaches no init
tuple. The executor admits exactly `trace::addressable`'s words: RAM, the two public windows and
the advice region up to its end. The recursion guest's tape inputs are imported straight out of
the advice region this way (`guest_sdk::recursion::import`).

**A data word and the frame may coincide.** The data words take `field_io::DATA_DELTA` = 1, the
frame `delegation::FRAME_DELTA` = 0, so a data word at a frame word's address reads what the
frame's write-back left at `4·cycle + 0` and writes at `4·cycle + 1`: an export over its own
frame overwrites the frame after the call has read it. `(RAM, 1)` is a slot no frame query of the
requesting row holds — a `const` assertion in `constraints/src/delegation.rs` — so a data event is
never filed into the requesting row. The data words are ordinary RAM events in the memory event
log; the cell, at `field_io::CELL_DELTA` = 0 in its own space, is not a log event, and
`trace::MemoryState` keeps its last `(ts, value)` (`recursion.md` §2.1).

### 24.4 Gate list 0: the 288 leaves

A leaf's relation number equals its `L1` offset, 0 to 287.

**The memory product trees**, `delegation::leaves_with(DELEGATION_FIELD_IO, 3, …)`: the three
frame words and the anchor, then the nine accesses of `field_io`'s private `accesses` — the eight
data words, then the cell — **13 real leaves a side, padded to 16**. Every real leaf is masked by
`live` and is the flat `Quadratic` of `delegation::masked_leaf`, §0.6's frame leaf with an
address offset:

```text
positional  1 + γ_M·M[1] − M[1] + AS·M[1] + (α_addr·M[1]) ×off + (α_ts·M[1]) ×Δ
              + α_addr·addr·M[1] + α_ts·ts·M[1]   (read side)
                                 | (α_ts·M[0]·M[1]) ×4   (write side)
              + α_val·value·M[1]
named       live·T(AS, addr + off, ts, value) + 1 − live
```

`write_data1`, relation 21, is
`1 + γ_M·M[1] − M[1] + 2·M[1] + (α_addr·M[1]) ×4 + α_ts·M[1] + α_addr·M[14]·M[1] + (α_ts·M[0]·M[1]) ×4 + α_val·M[21]·M[1]`,
which is `live·T(RAM, ptr + 4, 4·cycle + 1, data1_write) + 1 − live`. The anchor's two leaves are
every delegation family's: the teardown `T(13, base, 4·cycle + 3, anchor_value)`, its `+ 3` three
`α_ts·M[1]` terms, and the answer `T(13, base, 0, 0)`, with no `α_ts` or `α_val` term at all.

| `L1` | node | `AS` | addr | off | timestamp | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0–2 | `read_w{j}` | 2 | `M[4 + 4j]` | 0 | `M[5 + 4j]` | `M[6 + 4j]` |
| 3 | `read_anchor` | 13 | `M[2]` | 0 | `4·M[0] + 3` | `M[3]` |
| 4–11 | `read_data{k}` | 2 | `M[14]` | `4k` | `M[16 + 3k]` | `M[17 + 3k]` |
| 12 | `read_cell` | 10 | `M[10]` | 0 | `M[40]` | `M[41]` |
| 13–15 | `read_pad13` … `read_pad15` | — | — | — | — | the literal 1 |
| 16–18 | `write_w{j}` | 2 | `M[4 + 4j]` | 0 | `4·M[0] + 0` | `M[7 + 4j]` |
| 19 | `write_anchor` | 13 | `M[2]` | 0 | the literal 0 | the literal 0 |
| 20–27 | `write_data{k}` | 2 | `M[14]` | `4k` | `4·M[0] + 1` | `M[18 + 3k]` |
| 28 | `write_cell` | 10 | `M[10]` | 0 | `4·M[0] + 0` | `M[42]` |
| 29–31 | `write_pad13` … `write_pad15` | — | — | — | — | the literal 1 |

**The pads are named by their position in the side**, `read_pad13` to `read_pad15`:
`leaves_with` names a pad by its index there, as it does for the other recursion families that
pad (`P2_FIELD`'s are `read_pad14` and `read_pad15`), where `delegation::leaves` — §18's and
§20's — counts its pads from `read_pad0`. Names are documentation only (§0.2).

**The `range16` fraction tree**, `L1[32..288]`: 128 fractions — the table's, then the 70
obligations in `lookups` order, then 57 pads. Fraction `i` is `(L1[32 + 2i], L1[33 + 2i])`, named
`<node>_num` and `<node>_den`.

| fraction | `L1` | node | numerator | denominator |
| --- | --- | --- | --- | --- |
| 0 | 32, 33 | `range16_table` | `−W[38]`, `Linear` | `V[range16] + g`, `Linear` |
| 1–70 | 34–173 | the obligation's name (§24.6) | the literal 1, `Linear` | `g + s·e`, `Quadratic`: the selector times each term of the tuple, a constant folded onto `s` |
| 71–127 | 174–287 | `range16_pad_0` … `range16_pad_56` | the literal 0, `Linear` | the literal 1, `Linear` |

### 24.5 Gate list 0: the 24 enforcing gates

Relations 288–311, in list order. The first nine are the read-only `RANGE16` frame's,
`delegation::read_only_frame_range16(3, 12)` — `frame_gates_range16`'s six, then the three
write-backs; the last fifteen are `field_io`'s private `gates`.

| group | relations | count | degree | shape | what it says |
| --- | --- | --- | --- | --- | --- |
| `live_boolean` | 288 | 1 | 2 | `Quadratic` | the row's one mask is a bit |
| `addr_w{j}` | 289–291 | 3 | 2 | `Quadratic` | `live·(w{j}_addr − base − 4j)`: word `j` is at `base + 4j`. Degree 2 because it carries `live`, which vacates it on a padding row |
| `base_aligned`, `base_in_window` | 292–293 | 2 | 2 | `Quadratic` | `live·(base − RAM_ORIGIN − 4·base_low)` and `live·(2^31 − 12 − base − base_room)`: the base is 4-aligned and its 12-byte frame is inside RAM |
| `writes_back_w{j}` | 294–296 | 3 | 1 | `Linear` | `w{j}_write_value − w{j}_read_value`: the frame is read-only |
| `import_boolean`, `export_boolean` | 297–298 | 2 | 2 | `Quadratic` | each op selector is a bit |
| `one_op_a_live_row` | 299 | 1 | 1 | `Linear` | `import + export − live` |
| `op_word` | 300 | 1 | 1 | `Linear` | `import + 2·export − w0_read_value`: the op word is the selectors, `IMPORT` = 1 and `EXPORT` = 2 |
| `import_rule` | 301 | 1 | 2 | `Quadratic` | `import·(cell_new − Σ_k 2^{32k}·data{k}_read)` |
| `import_keeps_word{k}` | 302–309 | 8 | 2 | `Quadratic` | `import·(data{k}_write − data{k}_read)` |
| `export_keeps_cell` | 310 | 1 | 2 | `Quadratic` | `export·(cell_new − cell_old)` |
| `export_rule` | 311 | 1 | 2 | `Quadratic` | `export·(cell_old − Σ_k 2^{32k}·data{k}_write)` |

Positional, as stored — every `Quadratic` here has constant 0, every product is two committed
columns, and `addr_w0`'s `0·M[1]` is `neg(4·0)` kept as a term:

```text
288      live_boolean           0 = M[1] − M[1]·M[1]
289      addr_w0                0 = 0·M[1] + M[1]·M[4] − M[1]·M[2]
290      addr_w1                0 = −4·M[1] + M[1]·M[8] − M[1]·M[2]
291      addr_w2                0 = −8·M[1] + M[1]·M[12] − M[1]·M[2]
292      base_aligned           0 = −65536·M[1] + M[1]·M[2] − 4·M[1]·W[6]
293      base_in_window         0 = 2147483636·M[1] − M[1]·M[2] − M[1]·W[8]
294–296  writes_back_w{j}       0 = M[7 + 4j] − M[6 + 4j]
297      import_boolean         0 = W[28] − W[28]·W[28]
298      export_boolean         0 = W[29] − W[29]·W[29]
299      one_op_a_live_row      0 = W[28] + W[29] − M[1]
300      op_word                0 = W[28] + 2·W[29] − M[6]
301      import_rule            0 = W[28]·M[42] − W[28]·M[17] − 2^32·W[28]·M[20] − 2^64·W[28]·M[23]
                                    − 2^96·W[28]·M[26] − 2^128·W[28]·M[29] − 2^160·W[28]·M[32]
                                    − 2^192·W[28]·M[35] − 2^224·W[28]·M[38]
302–309  import_keeps_word{k}   0 = W[28]·M[18 + 3k] − W[28]·M[17 + 3k]
310      export_keeps_cell      0 = W[29]·M[42] − W[29]·M[41]
311      export_rule            0 = −W[29]·M[18] − 2^32·W[29]·M[21] − 2^64·W[29]·M[24]
                                    − 2^96·W[29]·M[27] − 2^128·W[29]·M[30] − 2^160·W[29]·M[33]
                                    − 2^192·W[29]·M[36] − 2^224·W[29]·M[39] + W[29]·M[41]
```

`65536` is `RAM_ORIGIN` and `2147483636` is `2^31 − 12`. `−2^{32k}` for `k ≥ 1` is a literal above
`2^32`, so the dump prints it as `p − 2^{32k}` in hex (§0.2): `−2^32` reads
`0x30644e72…43e1f592f0000001` and `−2^224` `0x30644e71e131a029…f0000001`.

**The move is ten gates, each under its own selector**, which is what keeps every product two
committed columns — `import·cell_new`, `import·data{k}_read` — and never three. A selector rather
than `live` gates them because the two kinds say opposite things about the same columns: on an
import the words stay and the cell moves, on an export the cell stays and the words move.

**`one_op_a_live_row` is load-bearing.** `op_word` pins the op word to the selectors, not the
selectors to the two codes: without this gate a live row may set both selectors to 0, and
`op_word` then asks only for an op word of 0 — a call the executor refuses, and one a guest's
frame can hold. Every one of the ten move gates vanishes and the sixteen word obligations switch
off, so `cell_new` and the eight `data{k}_write` are free: any element into the cell and any
eight values into eight RAM words, not even below `2^32`. The gate also refuses both selectors
at 1, whose op word would be 3 — no code either, though there the two kinds' rules, holding
together, change nothing. So it is this gate, and not `op_word`, that confines a live row to
`IMPORT` and `EXPORT`.

**`EXPORT` proves congruence and 32-bit limbs, not canonicity.** With each `data{k}_write` below
`2^32` by its pair (§24.6), `W = Σ_k 2^{32k}·data{k}_write` is an integer in `[0, 2^256)`, and
`export_rule` is the statement `W ≡ cell_old (mod p)`. `2^256` is about `5.29·p`, so `W` is
`cell_old + j·p` for some `j` in `0 … 5` when `cell_old < 2^256 − 5p` (about `0.29·p`) and in
`0 … 4` otherwise — **five or six representatives, and the circuit does not say which**. The
executor writes the canonical one, `j = 0`, as limbs of `Fr::to_bytes`, and the fill copies it;
a prover may write any of the others. A guest that needs the canonical limbs compares them with
`p` in RAM itself (`recursion.md` §5). Two readers in the tree need no such check: the recursion
guest's `read` accepts an exported cell as a `u32` only when its seven high words are 0, which
only the canonical representative of a value below `2^32` has; and an internal node reads each
of a child's 47 journal cells — each an `EXPORT`'s eight words (`recursion.md` §8.2) — back as
`Σ_i w_i·2^{32i}` over `Fr` (`verifier_core::node`), which is the element whichever
representative was written. A scalar's Pippenger digits need none of it, because
`(s + kr)·P = s·P`.

**`IMPORT` reduces, and needs no bound.** `import_rule` is an equation over `Fr`, so the cell is
`Σ_k 2^{32k}·data{k}_read mod p`: that is the move's definition, and there is no integer reading to
protect. No obligation reads an import row's words — the sixteen word pairs are `export`'s — so a
word is whatever the memory argument says was last written at `ptr + 4k`. A word read from the
advice region may be any `Fr`, the advice windows bounding nothing (§17); the import then takes
the weighted sum mod `p` like any other, an element eight `u32` limbs also reach. `guests/field-ops`
imports `p`'s own limbs, which land 0, and eight `0xffffffff` words, which land `2^256 − 1` reduced.

**Neither move rule needs `MOD_MUL`'s integer reading.** There a limb identity must not wrap, and
the operands' bounds are its soundness (§18.4). Here both rules are meant mod `p`, and the only
bound in the move is the export's. What it buys is that the family keeps the write-side
induction's shape (`memory-ops.md` §5.1): the one kind of word it computes into RAM, an exported
one, is bounded by its pair, and every other word it writes is a copy of the word it read there —
an imported word or a frame word, written back as read.

### 24.6 The 70 lookups and the channel

One channel, `RANGE16` = channel 1, table `V[range16]`, multiplicity `W[38]`. The tuple is
**one** expression wide, so the circuit reads `g` and **no** power of `β` and no neutral, and
`E + g = g + s·e_0` is every row denominator. The helpers are `delegation::{range16, bound32,
bound_chunked}`: the frame's obligations through `read_only_frame_range16`, the accesses' through
`Access::gap_lookups`, the words' through `bound32`.

| obligations | relations | count | selector | tuple, positional | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- |
| `gap{j}_c0_range`, `gap{j}_c1_range`, `gap{j}_top_scaled`, `gap{j}_lo_range`, `j < 3` | `34 + 8j` to `41 + 8j` | 12 | `M[1]` | `W[2j]`; `W[2j + 1]`; `1024·W[2j + 1]`; `4·M[0] − M[5 + 4j] − 65536·W[2j] − 2^32·W[2j + 1] − 1` | `4·cycle − 1 − w{j}_read_ts` in `[0, 2^38)` |
| `base_low_c0_range`, `base_low_top_scaled`, `base_low_lo_range` | 58–63 | 3 | `M[1]` | `W[7]`; `8·W[7]`; `W[6] − 65536·W[7]` | `base_low` in `[0, 2^29)` |
| `base_room_c0_range`, `base_room_top_scaled`, `base_room_lo_range` | 64–69 | 3 | `M[1]` | `W[9]`; `2·W[9]`; `W[8] − 65536·W[9]` | `base_room` in `[0, 2^31)` |
| `gap_data{k}_c0_range`, `_c1_range`, `_top_scaled`, `_lo_range`, `k < 8` | `70 + 8k` to `77 + 8k` | 32 | `M[1]` | `W[10 + 2k]`; `W[11 + 2k]`; `1024·W[11 + 2k]`; `4·M[0] − M[16 + 3k] − 65536·W[10 + 2k] − 2^32·W[11 + 2k]` | `4·cycle − data{k}_read_ts` in `[0, 2^38)` |
| `gap_cell_c0_range`, `_c1_range`, `_top_scaled`, `_lo_range` | 134–141 | 4 | `M[1]` | `W[26]`; `W[27]`; `1024·W[27]`; `4·M[0] − M[40] − 65536·W[26] − 2^32·W[27] − 1` | `4·cycle − 1 − cell_read_ts` in `[0, 2^38)` |
| `word{k}_hi_range`, `word{k}_lo_range`, `k < 8` | `142 + 4k` to `145 + 4k` | 16 | **`W[29]`** | `W[30 + k]`; `M[18 + 3k] − 65536·W[30 + k]` | `data{k}_write` in `[0, 2^32)` |

The relations are each obligation's `_num` and `_den` leaves, `34 + 2i` and `35 + 2i` for
obligation `i`. **70 obligations**, in that order: 12 for the frame's gaps, 3 and 3 for the base,
32 for the data words' gaps, 4 for the cell's, 16 for the exported words. The first 54 carry
`live`; the last 16 carry `export`, which `export_boolean` holds to booleanity, as `validate`
requires of any lookup's selector. `2^32` in a tuple above is the literal `−2^32` the dump prints
in hex.

**Two slots, two gap constants.** Each gap is `4·cycle + Δ − 1 − read_ts`, chunked as
`memory.md` §7's `38 = 16 + 16 + 6`, and is exact: the maximum is
`(2^16 − 1)(1 + 2^16) + 2^32(2^6 − 1) = 2^38 − 1`. The frame words and the cell are at `Δ = 0`,
which puts `−1` on the expression; the data words are at `Δ = 1`, which puts 0. The constant
folds onto the selector in the row denominator — `gap0_lo_range_den` carries `−1·M[1]`,
`gap_data0_lo_range_den` no linear term. So a frame word or the cell reads a write strictly
before `4·cycle`, and a data word one at or before `4·cycle` — which is what lets a data word
consume the frame's own write-back at `4·cycle + 0` when the two coincide. Every read is strictly
below its own write, so no access consumes its own tuple. The anchor's teardown has no gap: its
timestamp is `4·cycle + 3` by construction. **There is no `gap_w{j}` gate**: the obligations are
the bound and the decomposition at once, as `memory::gap_lookups` has it for an execution family.

**The scaled obligations alone bound nothing**, and `lookup::check_copowers` is what says so.
`artifact` passes it 14 columns, all under `live`: the three frame gap tops, `base_low_hi` and
`base_room_hi` (`delegation::frame_scaled_range16`) and the nine accesses' gap tops
(`Access::scaled`). Each has its direct obligation under the same selector — `gap*_c1_range`,
`base_low_c0_range`, `base_room_c0_range`. The scale is `2^{16−r}` for an `r`-bit top: 1024 for a
gap's 6 bits, 8 for `base_low`'s 13, 2 for `base_room`'s 15.

**The exported words are `bound32`'s 16+16 pairs**: `word{k}_hi` direct and
`data{k}_write − 2^16·word{k}_hi` derived, one committed column and two obligations a word. The
low expression is defined as the remainder, so `hi < 2^16` and `lo < 2^16` give
`data{k}_write < 2^32` with no wrap. Nothing is scaled, so nothing here is a copower.

**One multiplicity column, and no gate reads it.** `trace::build_multiplicities` counts each
`V[range16]` row's occurrences over the 70 gated tuples of every row of the shard — switched-off
ones included, a padding row contributing 70 zeros and an import row 16 — and appends `W[38]`
after the fill, which does not write it. At `n = 18` the table column repeats every `2^16` rows,
and each count sits on the lowest row holding its value (`lookup.md` §7), so rows `2^16` and
above hold 0. It exists because `artifact.committed()` names it, it is last in the witness
subtree because `lookup`'s own rule wants it there, and it is the ancestor of outputs 2 and 3.

`lookup::check_discharge`, which `memory::assemble` runs because the family declares a channel,
holds each obligation to one denominator leaf with a numerator of 1 beside it and the channel to
exactly one table fraction. `checker::violated_lookups` is the native reading of every obligation
on a row.

**Headroom.** 71 of the fraction tree's 128 leaves are used; 57 more obligations fit, and the
58th doubles the tree and adds a row-wise list (`R = 8`). The product trees have 3 spare leaves a
side, and a 17th leaf there would double them to 32 and leave `R` at 7.

### 24.7 The trees, the inner layers and the outputs

Three trees: `read` and `write`, 16 leaves each, and `range16`, 128 fractions. **`R = 7`, and the
fraction tree sets it alone** — a 16-leaf product tree is 4 deep — so the depth is
`N = 1 + 7 + n`, 26 at `n = 18`.

Layer `L1` is 288 wide: `read_*` at 0–15, `write_*` at 16–31, then the fraction tree's 128
`(num, den)` pairs at 32–287, the table's first and the 57 pads last. Widths:

```text
L1    288      L5     18      L9 … L{n+8}    4 each
L2    144      L6     10
L3     72      L7      6
L4     36      L8      4
```

so `inner = 578 + 4n` — 650 at `n = 18`, and 642 at the `n = 16` the row suite and the deferred
proof build it at (§24.8). The two product trees reach one node at `L5` and are carried as
`Linear` copies through `L6`–`L8`; the fraction tree reaches one pair at `L8`.

| list | writes | relations | `Product` | `Quadratic` | `Linear` |
| --- | --- | --- | --- | --- | --- |
| 1 | `L2`: `read_2_0` … `read_2_7`, `write_2_0` … `write_2_7`, `range16_2_{0…63}` | 312–455 | 16 + 64 | 64 | — |
| 2 | `L3`: `read_3_*` 4, `write_3_*` 4, `range16_3_*` 32 pairs | 456–527 | 8 + 32 | 32 | — |
| 3 | `L4`: 2, 2, 16 pairs | 528–563 | 4 + 16 | 16 | — |
| 4 | `L5`: `read_5_0`, `write_5_0`, 8 pairs | 564–581 | 2 + 8 | 8 | — |
| 5 | `L6`: `read_6_0`, `write_6_0` copied, 4 pairs | 582–591 | 4 | 4 | 2 |
| 6 | `L7`: copied, 2 pairs | 592–597 | 2 | 2 | 2 |
| 7 | `L8`: `read_8_0`, `write_8_0` copied, `range16_8_0` | 598–601 | 1 | 1 | 2 |

The `Product` column is product-tree nodes plus fraction denominators. A product node is
`out = a·b` and a fraction node `range16_{k}_{i}` is `num = a_num·b_den + b_num·a_den`,
`den = a_den·b_den` over the layer below's pairs `2i` and `2i + 1` (§0.6):
`define_range16_2_0_num` is `L1[32]·L1[35] + L1[34]·L1[33]`, the table fraction and
`gap0_c0_range`'s.

Relations: **0–287** list 0's leaves, **288–311** its 24 enforcing gates, **312–601** lists 1–7
as above, and halving list `k` (`8 ≤ k ≤ n + 7`) holds `602 + 4(k − 8)` to `605 + 4(k − 8)`. The
roots are relations `598 + 4n` to `601 + 4n`: **670–673** at `n = 18`. Every number but the
halving lists' is independent of `n`.

Each halving list is four gates: the `read_{k}_0` and `write_{k}_0` `TreeProduct`s, the channel's
numerator `TreeCross { num, den }` and its denominator `TreeProduct`; at `L26` they are
`read_root`, `write_root`, `range16_num_root` and `range16_den_root`. **The fraction tree is
exempt from the padding-identity clause**: `checker::check_padding_identity` requires every column
the first halving list reads to be 1 on the padding row except a `TreeCross`'s operands, a
padding row contributing 70 neutral entries the multiplicity counts.

**The outputs**, in output-map order: 0 `read_root` and 1 `write_root`, at `memory::READ_ROOT` and
`WRITE_ROOT`, read at `verify_shard` step 10a against `memory_roots[p]` for `p` the position of
`(21, shard_index)` in `verifier_core::statement_shards` — `INIT_TEARDOWN` and `ZERO_WINDOWS`
first and every other family ascending, so after every `P2_FIELD` shard and before every `FQ_OP`
one — and each a factor of `gkr_verify::reconciles` over the whole statement; 2
`range16_num_root` and 3 `range16_den_root`, read at step 9, the failure `Lookup { channel: 1 }`
and the check **both** `num == 0` and `den != 0`. In a recursion node the same checks are
`tape::shard_tape`'s, replayed over field cells (`recursion.md` §7).

### 24.8 What fixes each cell

| cell | what fixes it |
| --- | --- |
| `cycle`, `base` | the multiset: the request's mirror write is `T(DELEGATION_FIELD_IO, base, 4·cycle + 3, v)` and this row's `read_anchor` is its only reader (`delegation.md` §5.3); locally `base_aligned`, `base_in_window` and `addr_w{j}` against the words |
| `live` | `live_boolean`, every real leaf's mask, and `one_op_a_live_row` |
| `anchor_value` | **nothing local**: the request's mirror write value must equal it, and the memory argument is what says so |
| `w{j}_addr` | `addr_w{j}` |
| `w{j}_read_ts`, `data{k}_read_ts`, `cell_read_ts` | the memory argument alone; each access's four gap obligations only hold it below the access's own write |
| `w0_read_value` | the frame's read tuple, `writes_back_w0`, and `op_word` against the selectors |
| `w1_read_value`, `w2_read_value` | the frame's read tuples and `writes_back_w{j}`; as the cell's and the data words' address, the multiset, which has no init tuple for a cell or a word no window covers. No gate bounds or aligns either |
| `w{j}_write_value` | `writes_back_w{j}` |
| `import`, `export` | their booleanity, `one_op_a_live_row` and `op_word` — together exactly "one of the two codes on a live row, the one the frame names, and neither on a padding row" |
| `data{k}_read` | the memory argument alone: the last write to `ptr + 4k`. This family bounds no word it reads — an import's are reduced, an export's are read by nothing but their leaf |
| `data{k}_write` | on an import, `import_keeps_word{k}`; on an export, `export_rule` with the other seven and its own 16+16 pair, which fix the eight words as one of `cell_old`'s five or six representatives below `2^256` and nothing more (§24.5) |
| `cell_old` | the memory argument: the cell's last write, or the `FIELD_WINDOWS` init `(FIELD, cell, 0, 0)` |
| `cell_new` | on an import, `import_rule`; on an export, `export_keeps_cell` |
| `word{k}_hi` | on an export row, its two obligations and nothing else; on an import or padding row **nothing at all** — no gate reads it and both its obligations carry `export`. The fill writes 0 there |
| the 24 gap chunks, `base_low_hi`, `base_room_hi` | their own obligations and nothing else: no enforcing gate reads any of the 26 |
| `base_low`, `base_room` | `base_aligned` and `base_in_window`, and their `_lo_range` obligations |
| `mult_range16` | `trace::build_multiplicities`, and the channel's own root check — no gate reads it |
| the padding row | the seven gates §24.2's last paragraph names, and the fill writing zeros |

**The row suite is row-local at `n = 16`.** `crates/checker/tests/recursion.rs`'
`the_field_families_hold_and_the_field_memory_balances` fills a `FIELD_IO` shard from
`guests/field-ops`' real trace through `prover::family_fill` — 51 invocations, both moves among
them, an import of `p`'s own limbs and one of eight `0xffffffff` words included — and evaluates
every live row and the first padding row of `recursion_circuit(21, 16)` through
`checker::violated_relations` and `checker::violated_lookups`. Sixteen is the channel's floor and
not the default height, and relations 0–601 — every leaf, enforcing gate and row-wise node — are
the same at every `n`. The same test multiplies every live row's `read_cell` and `write_cell`
into the field memory's product, beside `FR_OP`'s, `P2_FIELD`'s and `FQ_OP`'s field leaves and the
field window's teardown and init, and requires reads and writes to cancel: a slot or an address
the circuit and the executor disagreed on would leave a tuple with no partner. The data words'
and the frame's RAM leaves are not in that product, and the multiplicity column reads 0 there —
the fill does not write it — so the channel's table side is not exercised by this test.

The executor's half is `crates/emulator/tests/guests.rs`'
`field_ops_checks_itself_under_the_recursion_ecalls`: the guest exits 26, every check passed, its
results read back through exports against literals, and its trace holds 51 `FIELD_IO`
invocations. `crates/constraints/tests/recursion.rs`'
`the_recursion_families_build_in_the_recursion_registry_alone` builds the circuit at its default
`2^18` — which runs `validate`, `check_memory`, the discharge rule and `artifact`'s own checks —
requires `zero_row_valid`, and requires `family_circuit(21, 18)` to be `None`; `recursion.txt`
pins the bytes. The request side is `crates/checker/tests/add_sub.rs`'
`a_recursion_request_advances_a0_past_its_frame`. What only a whole proof reaches — the data
words in the global multiset, the anchor pairing, the channel's roots over counted
multiplicities and the stacked opening — is `crates/prover/tests/field_ops.rs`, `#[ignore]`d and
deferred: `guests/field-ops` proved with one `FIELD_IO` shard at `2^16`, verified through
`verify_block`, and every shard's tape replayed against `verify_shard_local` and
`pcs::batch_verify_deferred`.

**No suite carries a negative control for this family.** Every row the row suite evaluates is
honest: no test corrupts a cell and names the gate or obligation that refuses it —
`one_op_a_live_row`, `import_keeps_word{k}`, `export_keeps_cell`, `export_rule` and the word pairs
among them — and none exhibits the non-canonical export the circuit admits.

---

## 25. `FQ_OP` — family 22

### 25.1 Header

`recursion_circuit(22, n)` is `fq_op::artifact(n)` with `fq_op::channels()`, which is **two
range channels**, `TIMESTAMP` then `RANGE16`. `family_circuit(22, n)` is `None` at every `n`:
this is one of the five families only the **recursion** registry holds (`recursion.md` §1.2,
`constraints::recursion_circuit` in `crates/constraints/src/lib.rs`), so a base-format key
cannot name it, and a statement holds it only in the recursion format. Like `MOD_MUL`,
`EC_ADD` and `FR_ARITH` it is built by `memory::assemble`: every constraint it makes is an
enforcing gate on gate list 0, so above the leaves it is two product trees, two fraction trees
and nothing else. Normative spec: `recursion.md` **§6**, with §1.2 (the registry), §1.4 (the
request's `a0`), §2 (the field memory) and §8.3 (why an operand is indirect); `delegation.md`
§4 and §5 for the frame and the anchor. Fill: `prover::family_fill(22)`, the private
`fill::fq_op`, over the field families' shared frame fill `fill::recursion_frame`. Ecall
`0x050C` (`ecall::PRECOMPILE_FQ_OP`), anchor space `address_space::DELEGATION_FQ_OP` = 14, and
every operand access in `address_space::FIELD` = 10. A request of this type leaves `a0 + 16`
in `a0`, its frame base advanced past its four words (`delegation::a0_after`, `recursion.md`
§1.4), which the recursion-format `ADD_SUB`'s `deleg_a0_rule` holds.

**121 committed columns (48 `M`, 73 `W`, no `S`) and two virtual tables, `V[range19]` and
`V[range16]`.** Gate list 0 writes 256 columns — 32 leaves a side of the two memory trees, the
`TIMESTAMP` tree's 32 fraction pairs and the `RANGE16` tree's 64 — and holds **38 enforcing
gates (6 degree-1, 32 degree-2)**. **80 obligations**, 30 on `TIMESTAMP` and 50 on `RANGE16`,
and **6 outputs**. At `n = 20`, its default height, there are 27 gate lists (7 row-wise and 20
halving), the top is `L27`, and the circuit has 630 inner columns and 668 relations, 158,326
bytes of wire form. **None of these counts depends on `n`** but the inner and relation totals,
`510 + 6n` and `548 + 6n`: a height adds halving lists and nothing else, one node per output
each.

The artifact is pinned by digest, as the six base delegation families' are:
`crates/constraints/tests/vectors/recursion.txt` carries the line
`FQ_OP 20 48 73 27 630 668 6 158326 af9dd8e9…f177d485` — `n`, memory, witness, gate lists,
inner, relations, outputs, bytes, SHA-256 — beside the other four recursion families' and the
recursion-format `ADD_SUB`'s. `cargo run -p kat-gen -- recursion` writes it, and the group is
one of kat-gen's defaults, so CI regenerates and diffs it. This section was read from a
`checker dump` of `recursion_circuit(22, 20).artifact.to_bytes()`, 2,300 lines.

`artifact` panics unless `M` is `MEMORY_COLUMNS` (48) and `W` is `WITNESS_COLUMNS` (73), unless
`TIMESTAMP` carries exactly 30 obligations and `RANGE16` exactly 50, and on any refusal of
`lookup::check_copowers` over the frame's six scaled columns. `memory::assemble` runs
`validate` (through `build::assemble`), `memory::check_memory` and, the family declaring
channels, `lookup::check_discharge`, and panics on any refusal of each.

**The height is `2^20`, and it is forced rather than chosen.** `TIMESTAMP`'s table is
`V[range19]`, nineteen variables, so `recursion_circuit`'s derived floor is 19 — the most any
of the family's channels needs, `lookup::table_vars` — and the range is `19 ≤ n ≤ 30`;
Mercury's even variable count makes `2^20` the least height a key can carry
(`constants::family::DEFAULT_HEIGHTS`: "forced, its TIMESTAMP table needing 19 variables";
`recursion.md` §6). **It is the first delegation family to carry `TIMESTAMP`.** That table fits
`2^20` and `2^22` on this menu and no lower height, and every base delegation family is below
it — `POSEIDON2` and `FR_ARITH` at `2^8`, `MOD_MUL` and `EC_ADD` at `2^16`, `KECCAK_F` and
`SHA256_COMP` at `2^18` — so `FQ_OP`, at `2^20`, is the one delegation family that carries
it. What the channel buys is a 19-bit chunk: a field access's 38-bit gap is two of
them, exactly, where `RANGE16` takes three with a scaled one, and the quotient's top limb and
each carry, 76 bits apiece, are four (§25.7).

**One row is one operation over elements of BN254's base field**, `ops/row = 1`. An element is
four consecutive field cells holding 64-bit limbs, `v = Σ_i v_i·2^{64i} < 2^256`, congruent to
the element mod `q` and **not necessarily below it**: reduction is lazy (`recursion.md` §6). It
cannot be one cell, `q` being larger than `p`. The family serves a recursion node's fold: the
MSMs' per-point template is 396 `FQ_OP` calls, and on block 257510's first 32 base shards the
leaf made 901,276 of them, one `2^20` shard with about 147k rows to spare (`recursion.md`
§8.3).

**A recursion-format shard commits stacks, not columns** (`recursion.md` §1.3). At `n = 20`,
`σ = min(24 − 20, 8) = 4`, so the 48 `M` columns are three full stacks of 16 and the 73 `W`
columns five, the last holding nine. `shard-proof.md` §9's per-column closed form,
`proof_bytes`, therefore does not give this family's proof length, and this section gives none.

**One shard is a computed 20.8 GB** by §18.1's accounting: 17.1 GB of forward pass (the seven
row-wise layers' 510 columns at `2^20` rows and 32 bytes; the twenty halving layers add
0.2 GB), 1.5 GB of committed base (88 small-type columns at 4 bytes and 33 `Fr` ones at 32 —
`cycle`, the eleven read timestamps, `digit`, the sixteen limbs of `a`, `b`, `d` and `d′`, and
`y`'s four), and 2.0 GB of transition 0's first bind, a half-height `Fr` table over 121
columns. It is a model, not a measurement.

**This family's §0.5 counts are at `n = 20`, §0.5's own height**: 150 `Linear`, 156
`Product`, 242 `Quadratic`, 80 `TreeProduct` (4 a halving list) and 40 `TreeCross` (2 a halving
list), summing to 668.

### 25.2 Row kinds

Two, and neither is an instruction: **this family is invoked, not decoded**. It claims no pc,
`program::lookup_tuple(22)` is empty, it is not in `constants::family::CYCLE_OWNING`, and it is
in a `VmConfig` exactly when the linked binary declares it — which, as for every field family,
also puts `FIELD_WINDOWS` in the config and the statement in the recursion format
(`recursion.md` §1.1, §2.2).

| row kind | `live` | what the row holds | what it adds to the multiset |
| --- | --- | --- | --- |
| an **operation** | 1 | the requesting cycle, the frame base, the four frame words, the digit cell and its value, the three elements' addresses, read timestamps and limbs, `d′`'s limbs, the op's selector, the three indirection flags, `y`, the quotient's chunks, three carries' chunks, and eleven gaps' chunks | 18 read tuples and 18 write tuples: the four frame words at `(RAM, base + 4j)`, read and written back at `4·cycle`; the anchor pair at `(DELEGATION_FQ_OP, base)`; and 13 field tuples — the digit cell at `(FIELD, g_addr)` at `Δ0`, `a`'s four cells at `(FIELD, a_addr + i)` at `Δ1`, `b`'s at `Δ2` and `d`'s at `Δ3`, every one written back with the value it read but `d`'s, which take `d′` |
| **padding** | 0 | every committed cell 0 **as the honest fill writes it**, the two multiplicity columns excepted | nothing: all 64 leaves are 1 — 36 real ones collapse to the product's identity and 28 are pads that are literally 1 — and 80 gated zeros the two channels count, 30 and 50 |

**A live row is one of five operations, and all five make the same 36 tuples.** Each access
is masked by `live` and by nothing else, which is `recursion.md` §6's first guest rule seen
from the circuit: every operand names an element, including one the op ignores. The four
slots are distinct, so any two operands may name one element, the later slot reading what the
earlier wrote back.

The op word, frame word 0, is `code + 8·ind_d + 16·ind_a + 32·ind_b + 64·g_addr` (`op_word`):
the code in bits 0–2 (`fq_op::CODE_BITS`), the three flags in bits 3, 4 and 5 (`IND_D`,
`IND_A`, `IND_B`), and the **digit cell** above them (`DIGIT_SHIFT` = 6). Each operand is
**direct** — its element starts at its frame word — or **indirect**, starting at its word plus
`8·digit`, the digit being the digit cell's value: a word names a window's buckets, eight
cells apiece (`BUCKET_CELLS`, `x` then `y`), and the digit picks one (`recursion.md` §8.3). The
flags are independent, so one digit may index any of the three elements.

Every operation is one identity, `a·y + z = q·K + d′` over the integers (§25.6), with `y` and
`z` chosen by the selector:

| op | code | selector | `y` | `z`'s limb `k` | `d′` | what the row says |
| --- | --- | --- | --- | --- | --- | --- |
| `MUL` | 1 | `op1` | `b` | 0 | written | `d′ ≡ a·b (mod q)` |
| `ADD` | 2 | `op2` | `(1, 0, 0, 0)` | `b_k` | written | `d′ ≡ a + b` |
| `SUB` | 3 | `op3` | `(1, 0, 0, 0)` | `6q_k − b_k` | written | `d′ ≡ a + 6q − b ≡ a − b`; `6q > 2^256`, so `z` is positive for every `b < 2^256` |
| `MULEQ` | 4 | `op4` | `b` | 0 | `d`, kept by `muleq_keeps_d{i}` | `a·b ≡ d`: an assertion; nothing new is written |
| `FROM128` | 5 | `op5` | 0 | `d′_k` | written, with `d′₀ + 2^64·d′₁ = a₀` and `d′₂ + 2^64·d′₃ = a₁` | `0 = q·K`, so `K = 0` and `d′ = a₀ + 2^128·a₁` exactly |

`FROM128` turns a point coordinate's two transcript limbs, the cells `a` and `a + 1`, into an
element. Its `a` is not an element and does not enter the identity; its two `from128_half`
gates with `d′`'s ranges are what bound each limb below `2^128` (`recursion.md` §6).

**What is not provable.**

- A code the selectors do not spell — 0, 6 or 7 in the low three bits. `op_word` solves for
  `g_addr = (w0 − code − flags)/64` over `Fr`, which is a small integer only when the word's
  low six bits are a code and its flags; any other word puts the digit cell's tuple at an
  address no field window initializes, and the multiset refuses it (`recursion.md` §5:
  addressability is the multiset's).
- An operand outside every field window, named directly or through a digit that is not a
  small integer, for the same reason.
- A `b` or `d` element whose four cells were last written at different timestamps: their four
  read leaves share one `read_ts` column, so no single value pairs all four.
- A `FROM128` whose `a₀` or `a₁` is not below `2^128`.
- A `MULEQ` whose `a·b ≢ d (mod q)` — and one whose kept `d` exceeds `a·b` as an integer, the
  quotient's chunks being nonnegative. A reduced `d` never does (§25.6).

The executor refuses more, and earlier, by name (the emulator's `fq_op`, which `delegate`
calls after writing the read-only frame back): a digit cell holding no value below `2^24`, on
a direct row too; an element leaving the cell range; an operand limb at or above `2^64` on the
four arithmetic ops; `FROM128`'s cells past `2^128`; a `MULEQ` that does not hold; a code it
does not answer. It writes the **reduced** `d′`, the honest representative. The fill refuses
an element whose cells were last written apart, which the executor does not check, and an
operand or a `d′` that is not an element.

Three things hold the all-zero row and are worth spelling out. `one_op_a_live_row` forces
every selector to 0 there, so the four `y{j}_rule` gates force `y` to 0 and every `z` term
vanishes with its selector; each group equation then reads `−q·K − d′ + c_{g−1} − 2^128·c_g`
and holds at zero. The carries' offset carries `live`, so a padding row's carry is the chunk
sum less `2^75·0`, not less `2^75`. And the three `_addr_rule` gates and `op_word` are
ungated with every term a column, so each reads `0 = 0`. `zero_row_valid` is `true`, which
`crates/constraints/tests/recursion.rs` asserts.

**The padding row is all-zero because the fill writes it so, not because the gates force
it.** Every obligation's selector is `live`, so on a padding row no bound applies: `d′`, the
quotient and the carries need only satisfy the four group equations over `Fr` with `y` and
`z` at 0, and the flags, the addresses and the digit only `op_word` and the address rules. It
is harmless — the row's leaves are the identity, it requests nothing, pairs with no anchor and
writes no register — but a test asserting "a padding row's columns are zero" asserts a
property of the fill.

The two multiplicity columns are the committed columns whose row `y` is not this shard's
`y`-th invocation: each is row `y` of its channel's table (§0.3).

### 25.3 The base layer

**Memory-argument columns, `M[0..48]`** — filled by `fill::fq_op`, the frame through
`fill::recursion_frame`; committed as stacks in `PublicInputs::memory_commitments`, absorbed
at G8 before the memory challenges. `Fr`-backed: `cycle`, the eleven read timestamps, `digit`
and every limb. The rest are `u32`.

| address | name | Rust | what it is | honest fill | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0..4]` | `cycle`, `live`, `base`, `anchor_value` | `delegation::{CYCLE, LIVE, BASE, ANCHOR_VALUE}` | as §18.3 and §12.3: the requesting cycle, the row's one mask, the `a0` the request passed, and the anchor teardown's value, **free on both sides** | the cycle; 1; the base; 0 | `cycle`: the 17 write leaves stamping `4·cycle + Δ`, `read_anchor`, and the eleven gap `_lo` obligations. `live`: every real leaf's mask, every obligation's selector, and twelve gates — `live_boolean`, the four `addr_w{j}`, `base_aligned`, `base_in_window`, `one_op_a_live_row` and the four `group{g}`. `base`: the four `addr_w{j}`, both base bounds, both anchor leaves. `anchor_value`: `read_anchor` alone |
| `M[4 + 4j + f]`, `j < 4` | `w{j}_addr`, `w{j}_read_ts`, `w{j}_read_value`, `w{j}_write_value` | `delegation::word(j, f)` | frame word `j`: 0 the op word, 1 `d`'s word, 2 `a`'s, 3 `b`'s (`fq_op::{OP_WORD, D_WORD, A_WORD, B_WORD}`) | the word's address, its last write, its value, and the same value | `addr`: both leaves and `addr_w{j}`; `read_ts`: `read_w{j}` and `gap{j}_lo_range`; `read_value`: `read_w{j}`, `writes_back_w{j}`, and `op_word` for word 0, `d_addr_rule`, `a_addr_rule` and `b_addr_rule` for words 1, 2 and 3; `write_value`: `write_w{j}` and `writes_back_w{j}` |
| `M[20]` | `g_addr` | `fq_op::G_ADDR` | the digit cell: the op word shifted down six bits | `w0 >> 6` | `op_word`, `read_g`, `write_g` |
| `M[21]` | `g_read_ts` | `G_READ_TS` | the digit cell's last write | the log's | `read_g`, `gap_g_lo_range` |
| `M[22]` | `digit` | `DIGIT` | the digit cell's value | the cell's value | `read_g`, `write_g`, and the three `_addr_rule` gates under their flags |
| `M[23]` | `a_addr` | `addr(1)` | `a`'s first cell | `w2 + 8·ind_a·digit` | `a_addr_rule`, `a`'s eight leaves |
| `M[24 + i]` | `a_read_ts{i}` | `a_read_ts(i)` | the last write to `a`'s cell `i` — **one a cell** | the log's | `read_a{i}`, `gap_a{i}_lo_range` |
| `M[28 + i]` | `a{i}` | `a(i)` | limb `i` of `a`, as read | the cell's value | `read_a{i}`, `write_a{i}`, the group gates multiplying it by `y`, and, for `a0` and `a1`, the two `from128_half` gates |
| `M[32]` | `b_addr` | `addr(2)` | `b`'s first cell | `w3 + 8·ind_b·digit` | `b_addr_rule`, `b`'s eight leaves |
| `M[33]` | `b_read_ts` | `read_ts(2)` | the last write to `b`'s four cells — **one for the element** | the first cell's, asserted equal to the other three's | `read_b0` … `read_b3`, `gap_b_lo_range` |
| `M[34 + i]` | `b{i}` | `b(i)` | limb `i` of `b` | the cell's value | `read_b{i}`, `write_b{i}`, `y{i}_rule`, and through `z` `group0` (`i < 2`) or `group1` (`i ≥ 2`) |
| `M[38]` | `d_addr` | `addr(3)` | `d`'s first cell | `w1 + 8·ind_d·digit` | `d_addr_rule`, `d`'s eight leaves |
| `M[39]` | `d_read_ts` | `read_ts(3)` | the last write to `d`'s four cells, one for the element | as `b_read_ts` | `read_d0` … `read_d3`, `gap_d_lo_range` |
| `M[40 + i]` | `d{i}` | `d_old(i)` | limb `i` of `d` before the row | the cell's value | `read_d{i}`, `muleq_keeps_d{i}` |
| `M[44 + i]` | `n{i}` | `d_new(i)` | limb `i` of `d′`, `d` after the row | the executor's write | `write_d{i}`, `muleq_keeps_d{i}`, `from128_half0` (`i < 2`) or `from128_half1`, `group0` (`i < 2`) or `group1`, and `n{i}_c0_range` |

**Witness columns, `W[0..73]`** — all filled by `fill::fq_op` but the last two; committed as
stacks in `ShardProof::witness_commitments`, absorbed at S3, with `g` drawn after them at S4.

| address | name | Rust | what it is | read by |
| --- | --- | --- | --- | --- |
| `W[2j + c]`, `j < 4`, `c < 2` | `gap{j}_c{c}` | `fill::recursion_chunk(j, c)` | chunk `c` of frame word `j`'s timestamp gap, weight `2^{16(c+1)}` — `delegation::frame_witness_range16`'s layout, `MOD_MUL`'s | its obligations alone |
| `W[8..12]` | `base_low`, `base_low_hi`, `base_room`, `base_room_hi` | — | `(base − RAM_ORIGIN)/4` and `2^31 − 16 − base`, each with its high halfword | `base_low` and `base_room` by `base_aligned` and `base_in_window` and their `_lo_range`; the two halfwords by their three obligations alone |
| `W[12 + k]`, `k < 7` | `gap_g_hi`, `gap_a0_hi` … `gap_a3_hi`, `gap_b_hi`, `gap_d_hi` | `gap_hi(k)` | the high 19 bits of access `k`'s gap, `fq_op::GAPS` = 7: the digit cell's, `a`'s four, `b`'s, `d`'s | its two `TIMESTAMP` obligations alone |
| `W[19 + i]`, `i < 5` | `op1` … `op5` | `selector(i)` | the op selectors in `fq_op::OPS` order, code `i + 1` | its booleanity, `one_op_a_live_row`, `op_word`, and the gates its op reads (§25.5) |
| `W[24..27]` | `ind_d`, `ind_a`, `ind_b` | `IND_D`, `IND_A`, `IND_B` | the three indirection flags | its booleanity, `op_word`, its `_addr_rule` |
| `W[27 + j]` | `y0` … `y3` | `y(j)` | the multiplicand's limb `j` | `y{j}_rule` and the group gates |
| `W[31 + 3i + c − 1]`, `c = 1, 2, 3` | `n{i}_c{c}` | `d_chunk(i, c)` | bits `16c … 16c + 15` of `d′`'s limb `i`; bits 0–15 are derived | its own obligation and `n{i}_c0_range` |
| `W[43 + 4j + c]` | `k{j}_c{c}` | `k_chunk(j, c)` | chunk `c` of the quotient's limb `j`: 16 bits for `j < 3`, 19 for `K3` | the group gates and its own obligation |
| `W[59 + 4g + c]`, `g < 3` | `carry{g}_c{c}` | `carry_chunk(g, c)` | 19-bit chunk `c` of carry `g` plus `2^75` | `group{g}` and `group{g+1}`, and its own obligation |
| `W[71]`, `W[72]` | `mult_timestamp`, `mult_range16` | `MULT_TIMESTAMP`, `MULT_RANGE16` | the two channels' multiplicities, last in the witness | each its table's numerator leaf alone; filled by `trace::build_multiplicities`, not by the fill |

**31 of the 73 witness columns are read by no gate at all**: the 8 frame gap chunks,
`base_low_hi`, `base_room_hi`, the 7 `gap_*_hi`, the 12 `n{i}_c{c}` and the two
multiplicities. Each of the first 29 exists to be the direct half of a bound. **The
quotient's and the carries' chunks are the other way round: the group gates read them
directly**, as weighted sums, so there is no `K` or carry value column — where `MOD_MUL` has
`carry{k}` — and every one of their chunks is committed, with no derived chunk and no scaled
obligation. `d′` is a third shape: its value is the `M` column `n{i}` that the write leaf
needs, its three upper chunks are witnesses, and its low chunk is derived.

**`a` has four read timestamps and `b` and `d` one each**, which is the asymmetry
`recursion.md` §6 records. `b`'s and `d`'s cells are only ever written together — by this
family, all four at one `4·cycle + 3` — so one timestamp and one gap serve an element.
`FROM128`'s `a` is two transcript limbs that `FIELD_IO` imported one at a time, so `a`'s
cells are not, and the price is three more timestamps, three more gaps and six more
`TIMESTAMP` obligations.

**This family names address columns, where `FR_OP` names none.** An `FR_OP` cell is its frame
word's value; an `FQ_OP` element is its frame word plus `8·digit` where indirect, which takes
a column and a gate. Every address it names — `g_addr` and the three elements' — is bounded by
nothing local; that a cell lies inside a field window is the multiset's business.

**Where each value reads from.** `a`, `b` and the old `d` are read values; `d′` alone is a
written one. The frame is read-only — four `writes_back_w{j}` — and so are the digit cell, `a`
and `b`, whose write leaves take the read column as their value: the row cannot change them.

### 25.4 Gate list 0: the 256 leaves

A leaf's relation number equals its `L1` offset, 0 to 255.

**The memory product trees**, read side `L1[0..32]` and write side `L1[32..64]`, are
`delegation::leaves_with(DELEGATION_FQ_OP, 4, accesses)`: the four frame words and the anchor
(`delegation::leaves`, its pads removed), then the 13 field accesses in
`fq_op::accesses()`' order — 18 real leaves a side, padded to 32 with **14 pads a side**.
Every real leaf's mask is `M[1]`.

| `L1` | node | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- |
| 0–3 | `read_w0` … `read_w3` | 2 (`RAM`) | `M[4 + 4j]` | `M[5 + 4j]` | `M[6 + 4j]` |
| 4 | `read_anchor` | 14 | `M[2]` | `4·M[0] + 3` | `M[3]` |
| 5 | `read_g` | 10 (`FIELD`) | `M[20]` | `M[21]` | `M[22]` |
| 6–9 | `read_a0` … `read_a3` | 10 | `M[23] + i` | `M[24 + i]` | `M[28 + i]` |
| 10–13 | `read_b0` … `read_b3` | 10 | `M[32] + i` | `M[33]` | `M[34 + i]` |
| 14–17 | `read_d0` … `read_d3` | 10 | `M[38] + i` | `M[39]` | `M[40 + i]` |
| 18–31 | `read_pad18` … `read_pad31` | — | — | — | the literal 1 |
| 32–35 | `write_w0` … `write_w3` | 2 | `M[4 + 4j]` | `4·M[0] + 0` | `M[7 + 4j]` |
| 36 | `write_anchor` | 14 | `M[2]` | the literal 0 | the literal 0 |
| 37 | `write_g` | 10 | `M[20]` | `4·M[0] + 0` | `M[22]` |
| 38–41 | `write_a0` … `write_a3` | 10 | `M[23] + i` | `4·M[0] + 1` | `M[28 + i]` |
| 42–45 | `write_b0` … `write_b3` | 10 | `M[32] + i` | `4·M[0] + 2` | `M[34 + i]` |
| 46–49 | `write_d0` … `write_d3` | 10 | `M[38] + i` | `4·M[0] + 3` | `M[44 + i]` |
| 50–63 | `write_pad18` … `write_pad31` | — | — | — | the literal 1 |

**A field access's leaf is the memory tuple at an offset** (`delegation::masked_leaf`):
`live·T(FIELD, addr + i, ts, value) + 1 − live`, stored as one `Quadratic` with constant 1 —
linear terms `(γ_M, live)`, `(−1, live)`, `(10, live)`, then `(α_addr, live) ×i` for the
offset and, on the write side, `(α_ts, live) ×Δ`; products `(α_addr, addr, live)`, then
`(α_ts, read_ts, live)` or `(α_ts, cycle, live) ×4`, then `(α_val, value, live)`. The offset is
a repeated term for the reason `4·cycle` is (§0.2). The frame and anchor leaves are §18.6's.
The pads are named by their leaf index, `read_pad18` … `read_pad31`, where `delegation::leaves`
numbers a frame-only family's from 0.

Three in full:

```text
L{1}[7]   read_a1
  positional  1 + γ_M·M[1] − M[1] + 10·M[1] + α_addr·M[1] + α_addr·M[23]·M[1]
                + α_ts·M[25]·M[1] + α_val·M[29]·M[1]
  named       live·T(FIELD, a_addr + 1, a_read_ts1, a1) + 1 − live

L{1}[48]  write_d2
  positional  1 + γ_M·M[1] − M[1] + 10·M[1] + α_addr·M[1] ×2 + α_ts·M[1] ×3
                + α_addr·M[38]·M[1] + α_ts·M[0]·M[1] ×4 + α_val·M[46]·M[1]
  named       live·T(FIELD, d_addr + 2, 4·cycle + 3, n2) + 1 − live

L{1}[4]   read_anchor
  positional  1 + γ_M·M[1] − M[1] + 14·M[1] + α_ts·M[1] ×3 + α_addr·M[2]·M[1]
                + α_ts·M[0]·M[1] ×4 + α_val·M[3]·M[1]
  named       live·T(DELEGATION_FQ_OP, base, 4·cycle + 3, anchor_value) + 1 − live
```

**The `timestamp` fraction tree**, `L1[64..128]`: 32 fractions — the table's, the 30
`TIMESTAMP` obligations in artifact order, one pad. Fraction `f` is
`(L1[64 + 2f], L1[65 + 2f])`, named `<node>_num` and `<node>_den`.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 64, 65 | `timestamp_table` | `−mult_timestamp` | `V[range19] + g` |
| 1, 2 | 66–69 | `gap_g_hi_range`, `gap_g_lo_range` | 1 | `g + live·gap_g_hi`; `g − live + 4·live·cycle − live·g_read_ts − 2^19·live·gap_g_hi` |
| 3–10 | 70–85 | `gap_a{i}_hi_range`, `gap_a{i}_lo_range`, `i < 4` | 1 | `g + live·gap_a{i}_hi`; `g + 4·live·cycle − live·a_read_ts{i} − 2^19·live·gap_a{i}_hi` |
| 11, 12 | 86–89 | `gap_b_hi_range`, `gap_b_lo_range` | 1 | `g + live·gap_b_hi`; `g + live + 4·live·cycle − live·b_read_ts − 2^19·live·gap_b_hi` |
| 13, 14 | 90–93 | `gap_d_hi_range`, `gap_d_lo_range` | 1 | `g + live·gap_d_hi`; `g + 2·live + 4·live·cycle − live·d_read_ts − 2^19·live·gap_d_hi` |
| 15–18 | 94–101 | `k3_c0_range` … `k3_c3_range` | 1 | `g + live·k3_c{c}` |
| 19–30 | 102–125 | `carry{g}_c{c}_range` | 1 | `g + live·carry{g}_c{c}` |
| 31 | 126, 127 | `timestamp_pad_0` | 0 | 1 |

**The `range16` fraction tree**, `L1[128..256]`: 64 fractions — the table's, the 50 `RANGE16`
obligations in artifact order, 13 pads. Fraction `f` is `(L1[128 + 2f], L1[129 + 2f])`.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 128, 129 | `range16_table` | `−mult_range16` | `V[range16] + g` |
| 1–16 | 130–161 | `gap{j}_c0_range`, `gap{j}_c1_range`, `gap{j}_top_scaled`, `gap{j}_lo_range`, `j < 4` | 1 | `g + live·gap{j}_c0`; `g + live·gap{j}_c1`; `g + 2^10·live·gap{j}_c1`; `g − live + 4·live·cycle − live·w{j}_read_ts − 2^16·live·gap{j}_c0 − 2^32·live·gap{j}_c1` |
| 17–19 | 162–167 | `base_low_c0_range`, `base_low_top_scaled`, `base_low_lo_range` | 1 | `g + live·base_low_hi`; `g + 2^3·live·base_low_hi`; `g + live·base_low − 2^16·live·base_low_hi` |
| 20–22 | 168–173 | `base_room_c0_range`, `base_room_top_scaled`, `base_room_lo_range` | 1 | `g + live·base_room_hi`; `g + 2·live·base_room_hi`; `g + live·base_room − 2^16·live·base_room_hi` |
| 23–38 | 174–205 | `n{i}_c1_range`, `n{i}_c2_range`, `n{i}_c3_range`, `n{i}_c0_range`, `i < 4` | 1 | `g + live·n{i}_c{c}`; and `g + live·n{i} − 2^16·live·n{i}_c1 − 2^32·live·n{i}_c2 − 2^48·live·n{i}_c3` |
| 39–50 | 206–229 | `k{j}_c{c}_range`, `j < 3` | 1 | `g + live·k{j}_c{c}` |
| 51–63 | 230–255 | `range16_pad_0` … `range16_pad_12` | 0 | 1 |

The linear term on a `gap_<x>_lo` denominator's `live` is `Δ − 1` — `−1` for the digit cell,
none for `a`'s four, `+1` for `b`, `+2` for `d` — and `−1` on every frame gap, the frame
writing at `Δ0`. In positional form `gap_d_lo_range`'s denominator (`L1[93]`) is
`g + 2·M[1] + 4·M[1]·M[0] − M[1]·M[39] − 2^19·M[1]·W[18]`, and `n0_c0_range`'s (`L1[181]`)
is `g + M[1]·M[44] − 2^16·M[1]·W[31] − 2^32·M[1]·W[32] − 2^48·M[1]·W[33]`, the dump printing
`−2^32` and `−2^48` as `0x30644e72…f592f0000001` and `0x30644e72…43e0f593f0000001`.

### 25.5 Gate list 0: the 38 enforcing gates

Relations 256–293, in `artifact`'s order: the frame's eleven
(`delegation::frame_gates_range16`, then `read_only_frame_range16`'s write-backs), then the
private `fq_op::gates()`' 27, built from `delegation::{booleanity, linear, quadratic}` and the
private `fq_op::group`. Six are `Linear` — the four write-backs, `one_op_a_live_row` and
`op_word` — and the other 32 `Quadratic`.

| relations | name | count | degree | positional | named |
| --- | --- | --- | --- | --- | --- |
| 256 | `live_boolean` | 1 | 2 | `M[1] − M[1]·M[1]` | the row's one mask is a bit |
| 257–260 | `addr_w{j}` | 4 | 2 | `−4j·M[1] + M[1]·M[4 + 4j] − M[1]·M[2]` | `live·(w{j}_addr − base − 4j)`; `addr_w0` stores its `−4j` as `0·M[1]` |
| 261 | `base_aligned` | 1 | 2 | `−65,536·M[1] + M[1]·M[2] − 4·M[1]·W[8]` | `live·(base − 4·base_low − RAM_ORIGIN)` |
| 262 | `base_in_window` | 1 | 2 | `2,147,483,632·M[1] − M[1]·M[2] − M[1]·W[10]` | `live·(2^31 − 16 − base − base_room)`: the 16-byte frame is inside RAM |
| 263–266 | `writes_back_w{j}` | 4 | 1 | `M[7 + 4j] − M[6 + 4j]` | the frame is read-only |
| 267–271 | `op{c}_boolean` | 5 | 2 | `W[18 + c] − W[18 + c]·W[18 + c]` | each op selector is a bit |
| 272–274 | `ind_d_boolean`, `ind_a_boolean`, `ind_b_boolean` | 3 | 2 | over `W[24]`, `W[25]`, `W[26]` | each flag is a bit |
| 275 | `one_op_a_live_row` | 1 | 1 | `−M[1] + W[19] + W[20] + W[21] + W[22] + W[23]` | `Σ op_c = live` |
| 276 | `op_word` | 1 | 1 | `−M[6] + W[19] + 2·W[20] + 3·W[21] + 4·W[22] + 5·W[23] + 8·W[24] + 16·W[25] + 32·W[26] + 64·M[20]` | `w0_read_value = Σ c·op_c + 8·ind_d + 16·ind_a + 32·ind_b + 64·g_addr` |
| 277 | `d_addr_rule` | 1 | 2 | `M[38] − M[10] − 8·W[24]·M[22]` | `d_addr = w1 + 8·ind_d·digit` |
| 278 | `a_addr_rule` | 1 | 2 | `M[23] − M[14] − 8·W[25]·M[22]` | `a_addr = w2 + 8·ind_a·digit` |
| 279 | `b_addr_rule` | 1 | 2 | `M[32] − M[18] − 8·W[26]·M[22]` | `b_addr = w3 + 8·ind_b·digit` |
| 280 | `y0_rule` | 1 | 2 | `W[27] − W[20] − W[21] − W[19]·M[34] − W[22]·M[34]` | `y0 = op2 + op3 + (op1 + op4)·b0` |
| 281–283 | `y{j}_rule` | 3 | 2 | `W[27 + j] − W[19]·M[34 + j] − W[22]·M[34 + j]` | `y_j = (op1 + op4)·b_j` |
| 284–287 | `muleq_keeps_d{i}` | 4 | 2 | `W[22]·M[44 + i] − W[22]·M[40 + i]` | `op4·(n_i − d_i)`: `MULEQ` writes `d` back |
| 288 | `from128_half0` | 1 | 2 | `W[23]·M[44] + 2^64·W[23]·M[45] − W[23]·M[28]` | `op5·(n0 + 2^64·n1 − a0)` |
| 289 | `from128_half1` | 1 | 2 | `W[23]·M[46] + 2^64·W[23]·M[47] − W[23]·M[29]` | `op5·(n2 + 2^64·n3 − a1)` |
| 290–293 | **`group{g}`** | 4 | 2 | §25.6 | the identity, one 128-bit group of limb positions each |

**There is no `gap_w{j}` gate, and none for a field access's gap**: each gap's obligations are
the bound and the decomposition at once, exactly as `memory::gap_lookups` has it for an
execution family (§25.7).

**`one_op_a_live_row` is load-bearing twice**, as `MOD_MUL`'s `one_modulus_a_live_row` is.
The codes are 1 to 5, consecutive, so two selectors spell a third code and `op_word` cannot
see it: `ADD` and `SUB` together spell 5, `FROM128`'s. Such a row has `y = (2, 0, 0, 0)` and
`z = 6q`, so it proves `d′ ≡ 2a` under a `FROM128` word, and every other gate and all 80
obligations hold on it — checked for this section on the artifact's own formulas, where
`one_op_a_live_row` is the one relation that row breaks. It is also what bounds `y`:
`y{j}_rule` makes `y_j` a selector-weighted sum of copies of `b_j` and 1, which is `b_j`, 1 or
0 only while the selectors are one-hot.

**`op_word` is the op word's whole decode, and it bounds nothing.** It fixes the selectors and
the flags from the word's low six bits and `g_addr` from the rest. `g_addr` carries no range
check: a word whose low bits are not a code is refused by the multiset, not by a gate (§25.2).

**The three address rules are degree 2** because a flag multiplies the digit, and ungated,
because both sides are columns. On a direct row the digit is multiplied by 0, and nothing
local reads it.

**The two `from128_half` gates are integer equations.** With `d′`'s limbs below `2^64`,
`d′₀ + 2^64·d′₁ < 2^128 < p`, so a `FROM128` whose `a₀` is a field element at or above `2^128`
has no witness. Each term carries `op5`, which is what makes them degree 2.

### 25.6 The identity, and why no group equation wraps

**One identity serves all five ops**: `a·y + z = q·K + d′` over the integers, with `y` and `z`
per §25.2's table, `K` the quotient — the one value in the row the execution did not record —
and `q = Σ_i q_i·2^{64i}` the literal limbs of `constants::fq_op::Q`, which a `const`
assertion holds to `MOD_MUL`'s BN254 base-field modulus limb for limb. It is checked as four
equations over 128-bit groups of limb positions, `(0, 1)`, `(2, 3)`, `(4, 5)` and `(6)`, with
three signed carries between them — where `MOD_MUL` checks fifteen 32-bit positions with
fourteen. Write

```text
T_k = Σ_{i+j=k} (a_i·y_j − q_i·K_j)  +  [k < 4]·(op2·b_k − op3·b_k + 6q_k·op3 + op5·n_k − n_k)
K_j = Σ_c 2^{16c}·k{j}_c{c}   (j < 3),          K_3 = Σ_c 2^{19c}·k3_c{c}
c_g = Σ_c 2^{19c}·carry{g}_c{c} − 2^75·live
```

and gate `group{g}` is

```text
T_{2g} + 2^64·T_{2g+1} + c_{g−1} − 2^128·c_g = 0
```

with `c_{−1}` absent, `c_3` absent — which is the closing condition — and `T_7` empty, no
`(i, j)` pair reaching position 7. Weight group `g` by `2^{128g}` and sum: the carries
telescope and what is left is `a·y + z − q·K − d′ = 0`. **The absence of a fourth carry is
the identity.**

Each gate is one `Quadratic`, every product a pair of committed columns — `a_i·y_j` an `M` and
a `W`, `op·b_k` and `op·n_k` a `W` and an `M` — so the degree is 2. The stored form merges a
column's two positions and expands `K` and the carries into their chunks:

| gate | relation | linear terms | products | what it reads |
| --- | --- | --- | --- | --- |
| `group0` | 290 | 16 | 9 | positions 0 and 1: `a0`, `a1`, `y0`, `y1`; `K0`, `K1`; `b0`, `b1`, `n0`, `n1` through `z` and `d′`; `carry0` out |
| `group1` | 291 | 28 | 13 | positions 2 and 3: all four of `a` and `y`; all four `K` limbs; `b2`, `b3`, `n2`, `n3`; `carry0` in, `carry1` out |
| `group2` | 292 | 21 | 5 | positions 4 and 5: `a1` … `a3`, `y1` … `y3`; `K1`, `K2`, `K3`; `carry1` in, `carry2` out |
| `group3` | 293 | 9 | 1 | position 6: `a3·y3`, `K3`; `carry2` in |

In `group0`, `k0_c{c}` carries `−2^{16c}·(q_0 + 2^64·q_1)` — at `c = 0` the dump's
`0x30644e72…178302ba`, which is `p − 0x97816a91…d87cfd47` — `k1_c{c}` carries
`−2^{64+16c}·q_0`, `op3` carries `6·(q_0 + 2^64·q_1)`, each `carry0_c{c}` carries
`−2^{128+19c}`, and `live` carries `+2^203`, the carry out's offset `−2^128·(−2^75)`. In
`group1` and `group2`, with a carry in and a carry out, `live` carries `2^203 − 2^75`; in
`group3` it carries `−2^75`. The shortest in full:

```text
group3  [293]
  positional  −q_3·W[55] − 2^19·q_3·W[56] − 2^38·q_3·W[57] − 2^57·q_3·W[58]
                + W[67] + 2^19·W[68] + 2^38·W[69] + 2^57·W[70] − 2^75·M[1] + M[31]·W[30]
  named       a3·y3 − q_3·K3 + c_2 = 0
```

**Why the equations over `Fr` are the equations over ℤ.** Take every column at the most its
bound admits — `a`'s, `b`'s and `d′`'s limbs below `2^64`, `y`'s therefore below `2^64` too,
every 16-bit chunk below `2^16` and every 19-bit one below `2^19`, `live` and the selectors at
most 1. The absolute values of a group's terms then sum below `2^204.6`, `2^204.8`, `2^205.2`
and `2^137.6` for groups 0 to 3. The largest single term is a carry out's top chunk,
`2^185·(2^19 − 1) < 2^204`, beside the offset's `2^203`, and `p` is above `2^253`. So no group
equation wraps, the four together are the integer identity, and there is no
modular-arithmetic loophole to argue about. `recursion.md` §6 states the argument as "every
term below `2^208`"; the figures here were computed term by term from the dump's own
coefficients.

**Two of those bounds are not on this row, and that is the design.** `d′`, `K` and the carries
are bounded here, by 44 obligations (§25.7), and `y` by `y{j}_rule` over `b` and one-hot
selectors — but **nothing on the row bounds `a`'s or `b`'s limbs**. That is the element
invariant of `recursion.md` §6: only this family writes an element, and every limb it writes
is range-checked here as `d′`; `a` and `b` are written back as read; a cell nothing has written
holds its window's 0. So, by induction over the field memory, an element a program names as an
operand has limbs below `2^64` — provided every operand **is** an element, which is the
guest's rule and not the circuit's. A program that hands this family cells another family
wrote — an `IMPORT`'s, an `FR_OP`'s — leaves the premise, and the integer reading with it; the
executor refuses such a row by name ("an operand is not an element"), and so does the fill. On
a `FROM128` row neither `a` nor `b` enters the identity — `y` is 0 and `z` is `d′` — so the
transcript limbs need no such bound, and the `from128_half` gates bound them instead.

**`d′` is fixed modulo `q`, not uniquely.** The identity says `d′ ≡ a·y + z (mod q)`, the
ranges say `d′ < 2^256`, and `K`'s nonnegative chunks say `d′ ≤ a·y + z`. `2^256/q` is 5.29, so
up to six representatives satisfy all three, and nothing in the circuit chooses among them:
there is no `< q` chain here, where `MOD_MUL`'s `out_below_modulus` is what makes its result
unique. A `MUL` row carrying the reduced result plus `q`, with `K` one lower, satisfies every
gate and all 80 obligations — checked for this section on the artifact's formulas. That is
lazy reduction, `recursion.md` §6's "congruent to the element mod `q` and not necessarily below
it", and the executor writes the reduced representative. Given `d′`, `K` is
`(a·y + z − d′)/q`, unique, and each carry is its group's sum over `2^128`, unique.

**`K ≥ 0` has one consequence worth knowing.** On `MUL`, `ADD` and `SUB` a reduced `d′` never
exceeds `a·y + z` — `SUB`'s `6q − b` is what keeps `a + z` positive — so every honest row has a
witness. A `MULEQ` whose kept `d` is a non-canonical representative above `a·b` has none: the
executor checks only `d ≡ a·b (mod q)` and accepts the call, and `fq_op::witness` panics on
the row ("a difference goes negative"). `FROM128` is the one op that writes an element
without reducing it.

**The quotient and the carries.** `K` reaches `(2^256 − 1)²/q < 2^259` on a product, so its
top limb passes `2^64`: `K3` is limbs 3 and 4 of `K` together, four 19-bit chunks,
`[0, 2^76)`, so `K < 2^268`, which `witness` asserts. A carry is read as its committed chunk
sum less `2^75·live`, a value in `[−2^75, 2^75)`; `fq_op::CARRY_OFFSET_BITS`' doc says an
honest carry stays below `2^71`, and `witness` asserts each fits the offset. A random
canonical `MUL` re-derived for this section has carries near `−2^63`.

### 25.7 The 80 lookups and the two channels

Two channels, both **range** channels: `TIMESTAMP` = channel 0, table `V[range19]`,
multiplicity `W[71]`; `RANGE16` = channel 1, table `V[range16]`, multiplicity `W[72]`
(`fq_op::channels()`, in that order). A range tuple is one expression wide, so every row
denominator is `g + live·e_0`: the family reads `g`, no power of `β` and no neutral (§0.4).
Every obligation's selector is `live`. The frame's obligations are
`delegation::read_only_frame_range16`'s; the family's own are the private `fq_op::lookups()`.

| obligation | channel | count | tuple | shape |
| --- | --- | --- | --- | --- |
| `gap{j}_c0_range`, `gap{j}_c1_range` | `RANGE16` | 8 | `gap{j}_c{c}` | direct: each chunk below `2^16` |
| `gap{j}_top_scaled` | `RANGE16` | 4 | `2^10·gap{j}_c1` | scaled: the top chunk below `2^6` |
| `gap{j}_lo_range` | `RANGE16` | 4 | `4·cycle − w{j}_read_ts − 1 − 2^16·gap{j}_c0 − 2^32·gap{j}_c1` | the derived low sixteen bits: a frame word's read precedes the frame's write at `4·cycle` |
| `base_low_c0_range`, `base_low_top_scaled`, `base_low_lo_range` | `RANGE16` | 3 | `base_low_hi`, `2^3·base_low_hi`, `base_low − 2^16·base_low_hi` | `[0, 2^29)` |
| `base_room_c0_range`, `base_room_top_scaled`, `base_room_lo_range` | `RANGE16` | 3 | `base_room_hi`, `2·base_room_hi`, `base_room − 2^16·base_room_hi` | `[0, 2^31)` |
| `gap_<x>_hi_range` | `TIMESTAMP` | 7 | `gap_<x>_hi` | direct: below `2^19` |
| `gap_<x>_lo_range` | `TIMESTAMP` | 7 | `4·cycle + Δ − 1 − <x>_read_ts − 2^19·gap_<x>_hi` | the derived low 19 bits: the access's read precedes its write at `4·cycle + Δ` |
| `n{i}_c1_range`, `n{i}_c2_range`, `n{i}_c3_range` | `RANGE16` | 12 | `n{i}_c{c}` | direct |
| `n{i}_c0_range` | `RANGE16` | 4 | `n{i} − 2^16·n{i}_c1 − 2^32·n{i}_c2 − 2^48·n{i}_c3` | the derived low sixteen bits: `d′`'s limb below `2^64` |
| `k{j}_c{c}_range`, `j < 3` | `RANGE16` | 12 | `k{j}_c{c}` | direct: `K0`, `K1`, `K2` below `2^64` |
| `k3_c{c}_range` | `TIMESTAMP` | 4 | `k3_c{c}` | direct: `K3` below `2^76` |
| `carry{g}_c{c}_range` | `TIMESTAMP` | 12 | `carry{g}_c{c}` | direct: each carry's offset value below `2^76` |

`<x>` is `g`, `a0` … `a3`, `b` and `d`, with `Δ` = 0, 1, 1, 1, 1, 2 and 3, so the `lo`
tuple's constant `Δ − 1` is −1, 0, 0, 0, 0, 1 and 2; the denominator folds it onto `live`.

**80 obligations**, in `artifact`'s order: the frame's 22 on `RANGE16`, the 14 field gaps on
`TIMESTAMP`, `d′`'s 16 and `K0`–`K2`'s 12 on `RANGE16`, then `K3`'s 4 and the carries' 12 on
`TIMESTAMP`. Each channel's fraction tree takes its own in that order (§25.4).

**Every bound is exact, and only the frame's needs a scaled obligation.** A field gap is two
19-bit chunks, `38 = 19 + 19` — `memory.md` §7's timestamp gadget exactly, the one the
execution families use; a frame gap is §18.5's `38 = 16 + 16 + 6`; `d′`'s limbs and `K0`–`K2`
are `64 = 4·16`, and `K3` and each carry `76 = 4·19`. So `lookup::check_copowers` is handed the
frame's six scaled columns — the four gap tops and the two base halfwords, each under `live`
(`delegation::frame_scaled_range16`) — and nothing of the family's own.

**The frame's gaps and the field accesses' gaps are bounded in different channels.** The
frame's come from `delegation::read_only_frame_range16`, the four field families' shared
frame, which bounds a gap in three `RANGE16` pieces — the one range channel the two families
at `2^18` can carry, `V[range19]` not fitting there — and this family's own accesses take
`TIMESTAMP`'s two.

**The two trees and their headroom.** `TIMESTAMP`'s 30 obligations and its table fraction
fill 31 of a 32-leaf tree — `artifact` asserts the 30, and its comment notes that two more
would double the tree — to 64 leaves, `RANGE16`'s size, which would widen `L1` through `L6`
and add no list. `RANGE16`'s 50 fill 51 of 64: thirteen more fit, and a fourteenth would double
it to 128 leaves and add a row-wise list, `R` being that tree's.

**The two channels gate identically**, `g + live·e_0`, so one channel's denominator gate is
byte for byte what the other's would be over the same column. `lookup::check_discharge`
counts each obligation's leaf and each table fraction **inside its own channel's cone**, which
is what keeps one channel from discharging another's obligation. This is the first delegation
family carrying both range channels, a pairing every execution family already has.

**Two multiplicity columns, and no gate reads either.** `trace::build_multiplicities` counts
each table row's occurrences over that channel's gated tuples on every row of the shard — a
padding row contributing 30 and 50 zeros, so table row 0's counts are large — and credits the
lowest row holding a tuple. `V[range19]` repeats its `2^19` values twice in `2^20` rows and
`V[range16]` its `2^16` sixteen times, so `mult_timestamp` is 0 on every row from `2^19` up and
`mult_range16` on every row from `2^16` up. `fill::fq_op` writes neither: both are `trace`'s,
counted after the fill. Each is read by its table's numerator leaf alone.
`checker::violated_lookups` is the native reading of all 80, both channels being range
channels.

### 25.8 The trees, the inner layers and the outputs

Four trees: `read` and `write`, 32 leaves each (18 real, 14 pads); `timestamp`, 32 fractions
(31 real, one pad); `range16`, 64 (51 real, 13 pads). **`R = 6`, the `range16` tree setting it
alone** — a 32-leaf tree is five deep — so the depth is `N = 1 + 6 + n`, 27 at `n = 20`.

Layer `L1` is 256 wide: `read_*` 0–31, `write_*` 32–63, the `timestamp` tree's 32
`(num, den)` pairs at 64–127 and the `range16` tree's 64 at 128–255, each tree's table first
and its pads last. Widths:

```text
L1   256      L4    32      L7     6      L8 … L{n+7}   6 each
L2   128      L5    16
L3    64      L6     8
```

so `inner = 510 + 6n` — 630 at `n = 20`. The two product trees and the `timestamp` tree reach
one node at `L6` and are carried to `L7` by four `Linear` copies in list 6 (`read_7_0`,
`write_7_0`, `timestamp_7_0_num`, `timestamp_7_0_den`); the `range16` tree reaches one pair at
`L7`. Layer `L{k}`'s nodes, `2 ≤ k ≤ 7`, run `read_{k}_*`, `write_{k}_*`,
`timestamp_{k}_*_num`/`_den`, then `range16_{k}_*_num`/`_den`, and a fraction node is §0.6's
pair: `timestamp_2_0` is `num = L1[64]·L1[67] + L1[66]·L1[65]`,
`den = L1[65]·L1[67]`.

Relations: **0–255** are list 0's leaves, **256–293** its 38 enforcing gates, **294–421**
list 1, **422–485** list 2, **486–517** list 3, **518–533** list 4, **534–541** list 5,
**542–547** list 6, and halving list `k` (`7 ≤ k ≤ n + 6`) holds `548 + 6(k − 7)` to
`553 + 6(k − 7)`. The roots are relations `542 + 6n` to `547 + 6n`: **662–667** at `n = 20`.
Every number before the halving lists is independent of `n`.

Each halving list is six gates, in output order: the read and write sides' `TreeProduct`s,
then for each channel a `TreeCross` numerator and a `TreeProduct` denominator. **The two
fraction trees are exempt from the padding-identity clause**, and
`checker::check_padding_identity` makes the exemption by shape: every column the first halving
list reads must be 1 except a `TreeCross`'s operands, a fraction tree's identity being
`(0, 1)` and a padding row not idle in a channel — it contributes 80 neutral entries the
multiplicities count.

**The outputs**, in output-map order: 0 `read_root` and 1 `write_root` at `memory::READ_ROOT`
and `WRITE_ROOT`, read at `verify_shard` step 10a against `memory_roots[p]` for `p` the
position of `(22, shard_index)` in `verifier_core::statement_shards` — **last** in every
statement it appears in, 22 being the highest family id and the order ascending after
`INIT_TEARDOWN` and `ZERO_WINDOWS` — and each a factor of `gkr_verify::reconciles`; 2
`timestamp_num_root` and 3 `timestamp_den_root`, read at step 9, the failure
`Lookup { channel: 0 }`; 4 `range16_num_root` and 5 `range16_den_root`, the failure
`Lookup { channel: 1 }`; each pair checked **both** `num == 0` and `den != 0`, a leaf pair of
`(0, 0)` otherwise annihilating its tree. Six is `2 + 2·2`, the one length at which
`reduce_shard`'s step 9, reading channel `j`'s pair at `outputs[2 + 2j]`, and
`lookup::channel_cones`, counting down from the end, name the same pairs
(`ProverSetup::new`'s comment says why that matters); `recursion.txt`'s shape line pins the
six. A node makes these same checks over cells, in this shard's tape (`recursion.md` §7).

### 25.9 Witness rows

**There is no row table here**: a live row is 121 committed cells, and its cycle, timestamps
and addresses belong to an execution. What stands in its place is a chain of readings, as
§20.7's does for `EC_ADD`.

1. **`crates/checker/tests/recursion.rs`**' `the_field_families_hold_and_the_field_memory_balances`
   fills `guests/field-ops`' `FQ_OP` buffer — **eleven** invocations — through
   `prover::family_fill(22)` at `2^20`, and evaluates every live row and the first padding
   row through `checker::violated_relations`, over scratch `gkr::gate_values` computes, and
   `checker::violated_lookups`, both channels. Its `d′` is the emulator's own reduction mod
   `q` and its quotient and carries are `fq_op::witness`'s, so a reduction the circuit spelled
   differently would break a `group` gate there. It then multiplies every row's 13 field
   access leaves into the field memory's product, beside `FR_OP`'s, `P2_FIELD`'s and
   `FIELD_IO`'s and the field window's teardown and init, and requires
   reads × teardowns = writes × inits: a slot or an offset the circuit and the executor
   disagreed on would be a tuple with no partner.
2. **`crates/emulator/tests/guests.rs`**' `field_ops_checks_itself_under_the_recursion_ecalls`
   runs the guest to exit 26 and pins the eleven calls. The guest's expectations are literals,
   checked on exported limbs: `x = 2^128 + 5` and `y = 7` built by `FROM128` from their limb
   cells, `x·y = [35, 0, 7, 0]`, a `MULEQ` re-asserting it, `x + y = [12, 0, 1, 0]`, `y − x`
   wrapping mod `q`, `(q − 1)² = 1`, an indirect read — `ADD | IND_A`, the digit 2 at cell
   240 picking bucket 2 of the buckets at 300 — and an indirect write, `MUL | IND_D`.
3. **`constraints::fq_op`'s unit tests**: `the_inverse_inverts`, `q·q⁻¹ = 1 mod 2^576`, on
   which `witness`'s exact 2-adic division of `a·y + z − d′` by `q` rests, and
   `the_arithmetic_is_mod_q`. `witness` itself asserts `q·K` back, the `2^268` bound, each
   carry's offset and the top group's closing.
4. **`crates/constraints/tests/recursion.rs`**: the family builds at its default height —
   which runs `validate`, `check_memory` and the discharge rule — its all-zero row pads, and
   the base registry refuses it.

**What those eleven rows exercise, and what they do not.** Re-derived for this section and
evaluated on the dump's own `group` coefficients:

| row | op | `a` | `b` | `d′` | `K` | carries |
| --- | --- | --- | --- | --- | --- | --- |
| `x` | `FROM128` | cells 200, 201: 5, 1 | four cells nothing writes | `[5, 0, 1, 0]` | 0 | 0, 0, 0 |
| `x·y` | `MUL` | `x` | `y = [7, 0, 0, 0]` | `[35, 0, 7, 0]` | 0 | 0, 0, 0 |
| `y − x` | `SUB` | `y` | `x` | `q + 2 − 2^128` | 5 | 0, 0, 0 |
| `(q − 1)²` | `MUL` | `q − 1` | `q − 1` | `[1, 0, 0, 0]` | `q − 2` | 0, 0, 0 |

The eleven are four `FROM128`, three `MUL` (one indirect in `d`), one `MULEQ`, two `ADD` (one
indirect in `a`) and one `SUB`. **In all eleven every carry is 0** — stored as
`carry{g}_c3 = 2^18` and zero below it, the offset's chunk — and `K` is nonzero on two, the
`SUB` and `(q − 1)²` rows. None sets `ind_b`. So CI holds the circuit to honest rows that never
pass a nonzero value through a carry and never index `b`; §25.10's probe does both on one
row. **No suite carries a negative control for this family.**

**The one whole proof is deferred.** `crates/prover/tests/field_ops.rs` proves
`guests/field-ops`' recursion-format block over a `2^24` toy SRS — `field_ops_params` puts this
family at `2^20` beside the execution families, its `TIMESTAMP` channel needing 19 variables,
and the other three field families at `2^16` — and accepts it through `verify_block`. It
asserts one shard of each field family, this one included, that every shard's witness
commitments are its stacks — five for this family, `stack_count(73, 4)` — and that every
shard's tape replays under `tape::run` and leaves what the native verifier computes
(`recursion.md` §7). It is `#[ignore]`d, run in the end-of-progression batch, and the only
place this family's shard is proved and verified.

An honest live row, in words:

| column group | value |
| --- | --- |
| `cycle`, `live`, `base`, `anchor_value` | the requesting cycle; 1; the frame pointer, 4-aligned, in `[RAM_ORIGIN, 2^31 − 16]`; 0 |
| `w{j}_addr`, `w{j}_read_ts` | `base + 4j`, and the last write to that word |
| `w{j}_read_value` = `w{j}_write_value` | the four frame words |
| `gap{j}_c{c}` | bits `[16(c+1), 16(c+2))` of `4·cycle − w{j}_read_ts − 1` |
| `base_low`, `base_room`, and their halfwords | `(base − RAM_ORIGIN)/4` and `2^31 − 16 − base` |
| `g_addr`, `digit` | `w0 >> 6`, and that cell's value |
| `a_addr`, `b_addr`, `d_addr` | the frame word, plus `8·digit` where the flag is set |
| `g_read_ts`, `a_read_ts{i}`, `b_read_ts`, `d_read_ts` | each access's last write: one per `a` cell, one per `b` and `d` element |
| `gap_<x>_hi` | bits `[19, 38)` of `4·cycle + Δ − 1 − <x>_read_ts` |
| `a{i}`, `b{i}`, `d{i}` | the cells as read: 64-bit limbs, but a `FROM128`'s `a₀` and `a₁`, which are 128-bit transcript limbs |
| `n{i}` | `d′`'s limbs: the result reduced below `q` on `MUL`, `ADD` and `SUB`, `d` itself on `MULEQ`, `a₀`'s and `a₁`'s halves on `FROM128` |
| `op{c}`, `ind_d`, `ind_a`, `ind_b` | the word's code one-hot, and its three flag bits |
| `y{j}` | `b`'s limbs on `MUL` and `MULEQ`, `(1, 0, 0, 0)` on `ADD` and `SUB`, 0 on `FROM128` |
| `n{i}_c{c}` | bits `[16c, 16c + 16)` of `n{i}`, `c = 1, 2, 3` |
| `k{j}_c{c}` | `K`'s chunks: 16-bit for `K0`–`K2`, 19-bit for `K3 = K >> 192` |
| `carry{g}_c{c}` | the 19-bit chunks of `c_g + 2^75` |
| `mult_timestamp`, `mult_range16` | `trace`'s counts; 0 on a row the table does not hold |

and a padding row is 0 in every one of them.

### 25.10 What fixes each cell

| cell | what fixes it |
| --- | --- |
| `cycle` | the multiset: every write leaf stamps `4·cycle + Δ` and the anchor teardown reads `4·cycle + 3`, which the request's mirror write fixes (`delegation.md` §5). Locally only the eleven gap obligations read it, against the read timestamps |
| `base` | the multiset, through the anchor; locally `base_aligned`, `base_in_window` and the four `addr_w{j}` against the words |
| `live` | `live_boolean`, and every leaf's mask |
| `anchor_value` | **nothing local**: the request's `deleg_write_value` must equal it, and the memory argument is what says so (§26 observation 19) |
| `w{j}_read_ts`, `g_read_ts`, `a_read_ts{i}`, `b_read_ts`, `d_read_ts` | the memory argument alone; each gap's obligations only hold it below this row's write at `4·cycle + Δ` |
| the four frame words | the frame's read tuples and `writes_back_w{j}`; word 0's value also `op_word`, and words 1, 2, 3's the three `_addr_rule` gates |
| `op1` … `op5` | booleanity, `one_op_a_live_row` and `op_word`: together "exactly one of the five codes, the one the word's low three bits spell" |
| `ind_d`, `ind_a`, `ind_b` | booleanity and `op_word`; each also its `_addr_rule` |
| `g_addr` | `op_word`: the word shifted down six bits. That it is a cell at all is the multiset's: a word whose low bits no code and flags spell puts it outside every field window |
| `digit` | the memory argument alone — it is a cell's value; on an indirect row it also scales that operand's address through `_addr_rule`. The executor refuses a digit cell holding no value below `2^24`, direct rows included |
| `a_addr`, `b_addr`, `d_addr` | their `_addr_rule`: the frame word, plus `8·digit` where the flag is set |
| `a{i}`, `b{i}` | the memory argument — what the cell holds — and their write leaves, which write the same column back, so the row cannot change them; their `2^64` bound is the element invariant, not the row's (§25.6). `b` is copied into `y` on `MUL` and `MULEQ` and read by the identity on `ADD` and `SUB`; `a0` and `a1` are also held by `from128_half` on `FROM128` |
| `d{i}` | the memory argument alone, but on `MULEQ`, where `muleq_keeps_d{i}` ties it to `n{i}` |
| `n{i}` | the group equations **modulo `q`**, and its four obligations below `2^64`: one of at most six representatives (§25.6); `d` itself on `MULEQ`; on `FROM128`, the `from128_half` gates exactly, the identity's `op5·n_k − n_k` cancelling there |
| `y{j}` | `y{j}_rule` |
| `k{j}_c{c}` | the group equations — given `d′`, `K` is unique, and so are its base-`2^16` and base-`2^19` digits — and its own obligation |
| `carry{g}_c{c}` | `group{g}` and `group{g+1}`, which the carry joins — it is its group's sum over `2^128` — and its own obligation |
| `gap{j}_c{c}`, `base_low_hi`, `base_room_hi`, `gap_<x>_hi`, `n{i}_c{c}` | **their own obligations and nothing else**: no gate reads any of the 29, so a wrong chunk breaks no relation and the channel alone refuses it |
| `base_low`, `base_room` | `base_aligned` and `base_in_window`, and their `_lo_range` |
| `mult_timestamp`, `mult_range16` | `trace::build_multiplicities`, and the channels' root checks — no gate reads them |
| the padding row | `check_padding`'s all-zero row and §25.2's gates that hold there, subject to §25.2's last paragraph |

**This table is read off the artifact, not off a committed tamper table.** No suite carries a
negative control for this family, so what stands behind it is the dump's readers — which leaf,
gate and obligation reads each column — beside a probe over the dump's own formulas: one honest
live row, a random canonical `MUL` with nonzero carries and `ind_b` set, each committed cell
moved by one, every enforcing gate and obligation evaluated; then the same over `ADD`, `SUB`,
`MULEQ` and `FROM128` rows. The probe is not committed. What it shows, beyond the table:

- `cycle`, every read timestamp, `anchor_value`, the old `d` on any op but `MULEQ`, the digit on
  a direct row, and on a `FROM128` row `a2`, `a3` and all of `b` — moved by one, **no gate and
  no obligation fires**. Each is the memory argument's alone.
- `n{i}` moved by one breaks only its group gate on `MUL`, `ADD` and `SUB`, its group gate and
  `muleq_keeps_d{i}` on `MULEQ`, and only `from128_half` on `FROM128`.
- A chunk moved by one is refused by the identity where a gate reads it — every `k{j}_c{c}`
  and `carry{g}_c{c}` — and by a derived low obligation where none does: the `n{i}` chunks,
  every gap chunk and both base halfwords. A chunk's own direct obligation fires only on a
  value outside its range.
- `b{i}` moved by one on `MUL` breaks `y{i}_rule` alone, and on `ADD` its group gate alone.

---

## 26. Observations

Facts this accounting turned up. None changes a circuit.

1. **The registry and the height menu disagree both ways.** `family_circuit` builds
   all **seven** registered execution circuits at every `n` from 19 to 30, the **five**
   window circuits, `POSEIDON2` and `FR_ARITH` at every `n` from 0 to 30, and the other four
   delegation circuits at every `n` from 16 to 30. A key's heights
   come from `VmConfig`, which `VmConfig::from_bytes` holds to `HEIGHT_MENU` (`n` = **8**, 16,
   18, 20, 22 since S21, and **12** since S-STREAM).
   So the seven execution circuits are reachable only at 20 and 22, which is `shard-proof.md` §8's,
   `jump-branch-slt.md` §2's, `shift-bitwise.md` §2's, `mul-div.md` §2's and `memory-ops.md`
   §7.1's `trace_vars ≥ 20`: the timestamp channel's 19 variables, made even for Mercury.
   `INIT_TEARDOWN` and `ZERO_WINDOWS` are reachable only at 16, 18, 20 and 22, never at
   `n ≤ 14`, where `V[ram_live]` is 0 on every row and `INIT_TEARDOWN` would mask its whole
   window — and since S-IO `verifier_core::window_height` refuses a window height below `2^16`
   for a second reason, that both public windows must lie inside RAM window 0;
   `ADVICE_WINDOWS` shares that height. **S-STREAM's `2^12` does not widen that**, which is
   worth checking rather than assuming, because growing the public windows is exactly the
   change that could have moved the floor: `window_height` requires
   `4h ≥ PUBLIC_OUTPUT_ORIGIN + PUBLIC_WINDOW_BYTES`, whose right-hand side went from `0x8800`
   to `0x10000`, so the rule went from `h ≥ 8,704` to `h ≥ 2^14` — and the smallest menu entry
   above either is the same `2^16`. **`PUBLIC_INPUT` and `PUBLIC_OUTPUT` are the opposite
   case**: reachable over the whole 0–30 range, like `POSEIDON2` and `FR_ARITH` and for the
   same reason — no channel, so no `BITS ≤ trace_vars` guard — but derivable at `2^12` and nowhere
   else, because the height is what places their windows (§15.1). Conversely, no execution
   circuit exists at the menu's 16 and 18, so a `VmConfig` placing one there decodes but no key
   for it loads (`VerifyingKey::check`) — and since S19 the `trace_vars < 19 ⇒ None` arm names
   all seven, so such a key is a clean `Err` and not a panic inside `lookup::channel_trees`,
   in the `no_std` crate the recursion guest links (`memory-ops.md` §7.2). **`MUL_DIV`'s and
   `ATOMICS`' default heights are `2^20`, not `2^22`** (`constants::family::DEFAULT_HEIGHTS`),
   the two execution families whose default is not the maximum; `ATOMICS`' was `2^16` until
   S19, which is the stage that gave it a circuit and so the stage that had to raise it.
   **`POSEIDON2` and `FR_ARITH` are the other way round**: each is *reachable*
   over the whole 0–30 range, because a family with no channel meets no `BITS ≤ trace_vars`
   assertion, and each is reachable at the menu's 8, 12, 16, 18, 20 and 22 with nothing
   deriving a height for it but `2^8`. The 12 is S-STREAM's, and these two are the only
   families it widened anything for: a key may declare it, nothing derives it, and it bought
   them nothing. **`KECCAK_F` was among them until S26d and `SHA256_COMP` until S26e**, and
   each is now `16 ≤ n ≤ 30` like `MOD_MUL` and `EC_ADD`, both of its channels' tables needing
   16 variables (§12.1, §19.1). That
   the menu's `2^8` entry is an *even* power is not a coincidence a stage may spend: Mercury
   needs `n` even for `b = sqrt(2^n)` to exist, so the menu below `2^16` had exactly `2^8`,
   `2^10`, `2^12` and `2^14` to choose from — and S-STREAM spent a second of the four, on the
   two public families and on nothing else. **The recursion registry adds five ranges.**
   `recursion_circuit` builds `FIELD_WINDOWS` at every `n` from 0 to 30, no channel giving it a
   floor, and nothing pins its height: `verifier_core::window_height` reads the five RAM window
   families and not this one, so a key may carry it at any menu height — `field-ops`' suites put
   it at `2^12` and `2^16`, and its default is `2^20` (§21.1). `FR_OP`, `P2_FIELD` and
   `FIELD_IO` it builds from 16, as the base families carrying `RANGE16` are built, and `FQ_OP`
   from **19**, an execution family's floor: `FQ_OP` is reachable at the menu's 20 and 22
   alone, exactly as the seven execution circuits are (§25.1).
2. **No registered family carries an inert column any more, and add/sub was the last.**
   Eighteen of its `M` and `W` columns used to be: the `arg1`, `arg2` and `ram` queries were
   held absent on every row by three `mask = 0` gates, yet `frame_queries` fixed the frame, so
   they were committed, opened and carried by every shard. They were the I/O-binding stage's,
   and what that stage did with them was **delete them** — `read` and `write` are retired, the
   two ecall-argument roles left the query table with them, and the `ram` query, which was the
   transfer row's alone, went when the transfer row did (`ecall-abi.md` §4). The frame is five
   queries, and every one of them some row of the family makes. Every other family was already
   clean: the three four-query frames — jump/branch/slt's, shift/bitwise's and mul/div's — are
   the same 21 `M` columns and the same bare frame artifact, `memory_frame_reg.bin` (§2.2); the
   two six-query frames, mem_word's and mem_subword's, share `memory_frame_mem.bin`, and every
   one of their six queries is used by some kind — a load's `load` and `rd`, a store's `rs2` and
   `ram`; and atomics' five-query frame, `memory_frame_atomics.bin`, has `rs2` used by ten kinds
   of eleven. **The three gates went with the columns**, and that is the part worth keeping:
   `arg1_mask_rule`, `arg2_mask_rule` and `ram_mask_rule` each refused something the family
   could not represent once the query was gone, so deleting the query deleted the gate's whole
   subject matter.
3. **`rd_is_zero_boolean` (relation 77 in §3, 92 in §4, 132 in §5, 124 in §6, 79 in §7, 131 in
   §8, 141 in §9) is implied** by the two gates before it
   with a boolean `rd_mask`: `rd_is_zero_at_nonzero` makes `rd_is_zero` 0 wherever
   `rd_addr ≠ 0`, and `rd_is_zero_inverse` makes it `rd_mask` wherever `rd_addr = 0`. It remains
   as S14's must-be-exact 7 lists it; `jump-branch-slt.md` §3.1 gives the same argument for the
   `is_zero` gadget, which carries no booleanity gate.
4. **No enforcing gate and no lookup reads `pc_addr`**; only the leaves `read_pc` and
   `write_pc` do (§3.3, §4.3, §5.3, §6.3, §7.3, §8.3, §9.3). It is 0 because the memory argument
   has initial and final pc tuples at address 0 only (§3.10); the same holds for every family's
   frame. **`rd_read_value` is read by the leaf `read_rd` alone in every registered family but
   add/sub**, whose `exit_status` reads it, so in six of the seven execution families it is
   fixed by the memory argument alone; **no** window family carries an `rd` query — none has a
   frame at all. `MEM_WORD` adds a second such column: **`ram_read_value`, the word a store
   overwrites, is read by `read_ram` and by nothing else** — no gate, no obligation, no table
   (§7.3). That is exactly the property `memory-ops.md` §9 wants of a tamper target, and it is
   why the `MEM_WORD` twin moves that cell and is refused as `MemoryArgument` rather than as
   `Constraint`. The other two families read their `ram_read_value`: mem_subword's `word_rule`
   copies it, and six of atomics' gates do. **S21 adds two more such columns, and they are a
   pair**: add/sub's `deleg_write_value` (`M[25]`, §3.3) and keccak's `anchor_value` (`M[3]`,
   §12.3) are each read by one leaf and by nothing else, and the memory argument is the only
   thing that says they are equal — which is observation 19. **`P2_FIELD` adds three more**:
   `next{i}_old` (`M[37 + 3i]`), what a destination cell held before the duplex step writes
   it, is read by `read_next{i}` and by nothing else, a destination's old value being no input
   of the duplex (§23.10).
5. **A `sub` row's `decoded_imm` is fixed by the decoder table alone.** No gate constrains it
   there: `sub` has no `imm` term, and the gates that read it (`add_addi_auipc`, `lui`,
   `ecall_code`, `fence_code`) are gated off by bits that are 0 on a sub row. On an `add` row
   `add_addi_auipc` reads it, and the table row's 0 is what `shard-proof.md` §8.4 relies on
   ("an R-type row's `imm` is 0 … so no third addend is live"); on a `sub` row nothing relies
   on it. The same holds in jump/branch/slt on `slt` and `sltu` rows, whose `imm` is 0, and on
   a branch that falls through, whose displacement no gate reads: `cmp_rhs_rule` reads `imm`
   only under the `slti` and `sltiu` bits, and `next_pc_rule` only under `taken` and the jump
   bits (§4.10).
6. **`INIT_TEARDOWN`'s cells below `RAM_ORIGIN` are unconstrained.** On its `2^14` rows
   `y < 2^14`, `V[ram_live]` is 0, so `teardown_ts` and `teardown_value` reach nothing (§10.4).
   They are committed and opened, and only the honest fill makes them 0; no check depends on
   their value.
7. **`jalr_drop` is free on every row but a `jalr` row.** `next_pc_rule` reads it only times
   `kind_jalr`, so elsewhere `jalr_drop_boolean` alone holds it, to 0 or 1 (§4.10: a taken
   `beq` row with `jalr_drop = 1` breaks nothing). No check depends on its value there; the
   honest fill writes 0. Add/sub's `wrap` is the same on its lui, fence, exit and padding rows.
8. **Jump/branch/slt compares on every live row, whatever the kind.** `cmp_order`, `eq_inverse`
   and `eq_at_nonzero` are ungated, and the comparison's six range obligations and two sign
   lookups are selected by `pc_mask`. So a `jal` row compares 0 with 0 (`eq = 1`), a `jalr` row
   compares `rs1` with 0 (`cmp_gap = rs1`), and an unsigned or non-comparing row still looks
   both signs up. There `sc = 0`, so `cmp_order`'s sign terms vanish and the generic table
   alone fixes the signs (§4.10); `taken_rule` and `rd_value_rule` read `eq` and `lt` only
   under branch and `slt` bits. The honest fill computes all of it on every live row.
9. **A jump/branch/slt padding row leaves `lt` and `cmp_gap` free together.** `cmp_order` holds
   on every row, but `cmp_gap`'s range pair is off where `pc_mask = 0`, so `lt = 1` with
   `cmp_gap = 2^32` breaks nothing there (§4.10). No leaf and no table reads either on a
   padding row, so no check depends on the pair; the honest fill writes 0 in both.
10. **S18's stage prompt's Shape paragraph and what was built diverge on the memory-column
    count.** The prompt guessed 15 memory columns for `SHIFT_BITWISE`; the frozen four-query
    frame gives 21 (`1 + 5·4`, `memory.md` §2.1 and §2.2), which is what both new circuits
    carry. The frame is not a stage's to choose — `memory::frame_queries` is frozen, and a
    frame narrower than its family cannot balance — so the circuits are right and the estimate
    was an estimate. It changes nothing; `docs/handoff/S18-shift-mul.md` carries the detail.
11. **The `RANGE16` tree is what sets both new circuits' depth, from opposite sides.**
    Shift/bitwise's carries 24 obligations, comfortably past 16 (§5.6); mul/div's carries 16,
    which with its table fraction is **seventeen** leaves — one past a 16-leaf tree — and pads
    to 32 all the same, so half of its `L2` `range16` nodes combine two pads (§6.7). The extra
    row-wise level costs each circuit one gate list and one proof transition — at `n = 20`, a
    20-round transition over a 12-column layer, 2,952 bytes of the two proofs' 68,564 and 67,412
    (§1.2); the rest of their length over §3's and §4's is their wider layers. Mul/div is the
    circuit where a single dropped obligation would take the level back; §6.6 says why none is
    droppable.
12. **`abs_d` is computed on every live mul/div row, multiply rows included.** `abs_d_rule` and
    `abs_r_rule` are ungated, so a `mulhsu` of `0xffffffff` carries `abs_d = 0xffffffff`
    (§6.9's row `C`); nothing reads either magnitude there, `gap_rule`'s `f_div` factor being
    0. The same shape as observation 8's: the cheaper gate is the ungated one, and the family
    bit is what makes it vacuous.
13. **Three columns of mul/div are boolean without a booleanity gate, and one of shift/bitwise
    carries one it does not need.** `rz` and `dz` are boolean by the is-zero gadget's
    construction and `d1` by the two boolean columns it multiplies, so none carries one — S17's
    argument for `eq`, unchanged. Conversely `se_boolean` (relation 164 in §5) is implied by
    `se_rule` over a boolean `rs1_sign` and one-hot kind bits, and is written anyway because
    S18's must-be-exact 5 asks a sign bit's sign-weighted form to carry one. Neither choice
    costs a degree.
14. **`check_copowers` had exactly one circuit under its tightened form at S18, and has five
    callers and eighteen columns at S19.** S17 introduced it for `next_pc`'s halved obligation in
    jump/branch/slt; S18 made it take each scaled column with the selector its scaled obligation
    carries and demand the direct pair under *that same* selector (`shift-bitwise.md` §3.4), and
    shift/bitwise passes six columns to it. S19 adds three callers: mem_word one column
    (`word_index_hi` under `pc_mask`), mem_subword five (`word_index_hi`, `high`, `sub`, `low`
    and `src_sub`, all under `pc_mask`) and atomics five (`word_index_hi` under `pc_mask` and
    the four `byte_a` keys under `f_bitwise`). Mul/div is the one registered execution circuit
    that passes none: it bounds nothing by scaling, so `assemble` does not call the check at all
    (§6.6).
15. **`MEM_WORD` is the second registered family with no generic channel, and the last one that
    will be cheap to add.** `ADD_SUB_LUI_AUIPC` was the first. Between them they are the only
    two whose `FamilyCircuit::reads_generic_table` is false, the only two whose setup subtree is
    identity's decoded table alone, and the only two whose shard proof carries `2 + 2·3` outputs
    rather than `2 + 2·4` (§7.1, §7.8). Everything the family needs is either a copy or a
    16-bit decomposition, and a sign, a power or a bytewise AND is what pulls a family into the
    packed table.
16. **Two families make two queries in one `Δ` slot, and `ATOMICS` is no longer alone.** Its
    `ram` query writes at `4·cycle + 3` in address space 2 and its `rd` query at `4·cycle + 3`
    in address space 1, which is what lets one row be one read-modify-write
    (`execution-trace.md` §4). **Since S21 a delegation request does the same**: its `rd` query
    writes `a0` at `4·cycle + 3` in space 1 and its `deleg` mirror at `4·cycle + 3` in a space
    from 4 to 9 — 11 to 14 besides in the recursion format's form — the delegation family's own
    (§3.4, §3.11). Add/sub's frame *held* two Δ-3 queries from
    S16 to S21 without ever making two — `ram` beside `rd`, with `ram_mask_rule` pinning the
    first to 0 on every row — and the `ram` query has since gone (observation 2). What both
    cases rest on is §3 of `execution-trace.md`: queries at distinct addresses may share a slot,
    and two queries at one address never do.
    **`ADD_SUB_LUI_AUIPC` and `ATOMICS` are the two families with three pads a side.** Five
    queries in an eight-leaf product tree leave three pads on each side, where the memory
    families' six leave two and the three four-query families leave none (§3.4, §9.4);
    add/sub's eight left none either, from S21 until the frame narrowed.
    `ATOMICS` has no `load` query at all, `lr.w` included, though `lr.w` is a plain word load:
    the whole extension keeps its RAM query at slot 3, frozen at S12 (`execution-trace.md` §7).
17. **Three of S19's columns are free on a padding row, and each is free for a different
    reason.** `mem_subword`'s `pcopow` is free because `p_rule`'s constant is `m_pc`, so `p` is
    0 there and `pcopow_rule` reads `0 = 0` — which is what makes it acceptance 8's negative
    control (`memory-ops.md` §9). `atomics`' `f_bitwise` is a free boolean, as §5's `f_shift`
    and `f_bitwise` are, so a padding row may look the byte table up and pay a multiplicity for
    it. `atomics`' `lt` and `cmp_gap` are free together, exactly as §4's are (observation 9):
    `cmp_order` holds on every row, but the gap's range pair is off where `pc_mask = 0`.
    `mem_word` has none of this: its two kind bits and its wrap are free booleans and nothing
    else is, every other column of the family being held to 0 by a gate with a kind bit or a
    mask in it.
18. **S19's statement is the first of any stage with a `ZERO_WINDOWS` shard.** `guests/mem`
    writes near the top of RAM as well as inside window 0, so `trace::init_windows` derives
    `[8191]` at `h = 2^16` and the statement carries seven shards where S18's carried five
    (§1.1). Until S19 §11's circuit was registered, built into every key and never proved.
19. **The anchor's value is free on both sides, and that is the whole of the answer tuple's
    argument.** Add/sub's `deleg_write_value` and keccak's `anchor_value` are each read by one
    leaf and by no gate, obligation or table (§3.10, §12.10). Nothing makes either 0; what makes
    the pair *balance* is that the request writes `T(4, base, 4c+3, v)` and the invocation reads
    `T(4, base, 4c+3, v')`, and the multiset cancels them only at `v = v'`. A prover that writes
    7 on both sides proves the same statement and is honest; a prover that writes 7 on one is
    refused as `MemoryArgument`, never as `Constraint`. Three gates pin the *other* three fields
    instead — `deleg_read_ts_zero`, `deleg_read_value_zero` and `deleg_addr_rule` — which is why
    `delegation.md` §5.2 calls them the three request-side zeroings and stops there. The same
    shape as observation 4's tamper targets, and deliberately so.
20. **A frame's gate list is a step at eight queries, and `ADD_SUB_LUI_AUIPC` has now climbed
    it and come back down.** `2w` gap obligations with the table fraction is `2w + 1` leaves, so
    the timestamp tree fits 16 while `2w + 1 ≤ 16` — true at `w = 7`, false at `w = 8`. S21's
    eighth query put the family over: seventeen leaves padded to 32 and the circuit went from
    five row-wise lists to six, while the same eight queries filled an eight-leaf product tree
    exactly and removed its two pad leaves. The POSIX layer's deletion undid both at once
    (observation 2): at `w = 5` the timestamp tree is eleven leaves in a 16-leaf tree and the
    row-wise list came off, and the product trees pay three pads a side again (§1.3, §3.4,
    §3.6). **A family taking the step a second time pays the list and nothing more** — 19 leaves
    at `w = 9` still pad to 32 — so the cost is a step, not a slope, and no registered frame is
    standing on it today.
21. **`KECCAK_F` was the one registered circuit `build::assemble` did not build, and S26d gave
    the exception back.** S21's was a 168-layer permutation with two trees reducing underneath
    it, so `keccak.rs` carried its own `Assembly`; the reason was not taste, but that
    `build::push_list` resolves an inner address to a scratch slot by scanning every slot pushed
    so far, which is quadratic, and at 354,762 columns that alone took `keccak::artifact(8)` past
    ten minutes. One round a row is flat — 385 enforcing gates and no layer of its own — so it
    goes through `memory::assemble` like every other family, and `keccak.rs`'s private
    `Assembly` is deleted. **What the width bought stays**: S21's quadratic scans in `checker`'s
    validators and in `constraints::laws` were replaced with `BTreeSet`s and tallies, which took
    `validate` from 17.6 s to 0.87 s. Nothing about those fixes was keccak-specific — they were
    latent in every artifact and only a wide one showed them.
22. **A delegation shard's ts window overlaps a CPU shard's by construction, and the block rule
    is scoped so that it may.** An invocation rides the cycle of the request that made it, so
    `KECCAK_F`'s window is a sub-interval of `ADD_SUB_LUI_AUIPC`'s whenever the guest calls the
    shim at all, and `crates/prover/tests/keccak.rs` asserts exactly that containment.
    `verify_block`'s `check_ts_windows` therefore requires non-emptiness, ordering and pairwise
    disjointness **per cycle-owning family** (`constants::family::CYCLE_OWNING`), which is
    `false` for this family as it is for every other delegation family, the recursion
    registry's four included, and for all **six** window families — and for a different
    reason: a window family owns no cycle because its rows are addresses or field cells, and a
    delegation family because its rows are invocations of someone else's cycle (§12.8, §21.3,
    `block-proof.md` §4).
23. **A forgery's error class depends on which entry point verifies it, and S21 is where
    that first mattered.** `verify_shard`'s order is `Statement`, `Malformed`, `Constraint`,
    `Lookup`, `MemoryArgument`; `verify_block` runs `verify_global_memory` — the memory
    argument's statement half — **before** any shard's own checks (`block-proof.md` §3), so
    a witness that both breaks a gate and unbalances the multiset reads `Constraint` through
    one entry point and `MemoryArgument` through the other. Every anchor tamper is such a
    witness: a mirror read that is stamped breaks `deleg_read_ts_zero` *and* matches no
    write. So `checker::assert_anchor_twins_refused` runs the three zeroings at shard level,
    where the gate is the answer, and the dropped-invocation twins at block level, where the
    multiset is — and the helper's doc comment says why, because a twin asserting
    `Constraint` at block level is asserting something false. It did, until S21's first full
    deferred run. No earlier stage met this: every tamper before S21 either broke a gate
    without unbalancing anything or was run through `verify_shard` alone.
24. **Two families share one artifact byte for byte, and the sharing is the soundness
    argument.** `family_circuit(13, n)` and `family_circuit(8, n)` are the same bytes at every
    `n`, so `crates/constraints/tests/vectors/zero_window.bin` pins both. That is not reuse for
    economy: the journal's window takes `ZERO_WINDOWS`' artifact **because** its init leaf is
    the literal 0, leaving a prover no init column to pre-load the answer into at timestamp 0
    (§16.1). `PUBLIC_INPUT` and `ADVICE_WINDOWS` likewise share `value_window_artifact` and
    differ only in what `verify_shard_local` step 10c does with `M[2]` — holds it to the
    statement's `input`, or does not look at it at all. So three of the five S-IO-era window
    families are two artifacts, and **what tells them apart is a verifier step and a window
    id, not a gate**. It is the first place in this registry where two `FamilyId`s carry
    identical circuits, and `VerifyingKey::check` is untroubled by it: a key's circuits are the
    registry's, family by family, and two families returning equal bytes is not a collision.
    **`FIELD_WINDOWS` is the counter-case**: it shares `ZERO_WINDOWS`' constructor and not its
    bytes — the private `memory::zero_window` at a stride of one cell, where `ZERO_WINDOWS` and
    `PUBLIC_OUTPUT` take four bytes — so its two leaves carry one `(α_addr, V[row])` term where
    theirs carry four, 444 bytes fewer at every `n` (§21.1). Neither artifact names an address
    space: what separates field cell `x` from RAM word `x` is the 10 against the 2 in slot 5's
    derived window constant, and nothing in either artifact.
25. **`ADVICE_WINDOWS`' `M[2]` is the only committed column in the whole registry that nothing
    binds.** Every other committed column is reached by a gate, a leaf, a lookup, an opening
    against identity or the SRS digest, or a verifier step. `M[2]` is reached by its init leaf
    alone, and a leaf constrains nothing by itself — it balances against whatever the guest read
    (§17.2). That is the definition of advice and not a gap, but it is worth writing down beside
    §26 observation 6's unconstrained `INIT_TEARDOWN` cells and §26 observation 19's free anchor
    value, because the three are the registry's whole inventory of deliberately free committed
    cells, and each is free for a different reason: masked off, paired by the multiset, or
    chosen by the prover on purpose.
26. **`FQ_OP` is the one delegation family that carries `TIMESTAMP`, and its height is why.**
    `TIMESTAMP`'s table is `V[range19]`, nineteen variables, which on this menu is `2^20` or
    `2^22`. Every base delegation family is below it — `2^8`, `2^16` or `2^18` — and `FQ_OP` is
    at `2^20` (§25.1), so its channels are an execution family's two range channels without the
    decoder, and it is the one circuit carrying `TIMESTAMP` that reads no `β` (§0.4). It spends
    the 19-bit chunk where the chunk is exact: a field access's 38-bit gap is two of them, and
    `K`'s top limb and each 76-bit carry four, while its frame's gaps stay three `RANGE16`
    pieces, the field families' shared frame being built for the two of them at `2^18`
    (§25.7). `FR_OP`, at `2^20` too, carries `RANGE16` alone.
27. **Three field families tie their op selectors to `live` with one gate, and each would lose
    a different thing without it.** `FR_OP`'s `one_op_a_live_row` is the only tie between a
    field access and an invocation: without it a padding row could set `op7` and write a free
    value into a free cell at a cycle of its choosing, and the multiset would balance it as an
    ordinary read-modify-write (§22.5). `FIELD_IO`'s is what confines a live row to `IMPORT`
    and `EXPORT`: with both selectors 0, `op_word` asks only for an op word of 0, every move
    gate vanishes and the cell and the eight words are free (§24.5). `FQ_OP`'s is the partition
    `op_word` cannot see, its codes 1 to 5 being consecutive: `ADD` and `SUB` together spell
    `FROM128`'s 5 and prove `d′ ≡ 2a` under a `FROM128` word (§25.5) — `MOD_MUL`'s
    `one_modulus_a_live_row` and `EC_ADD`'s `one_code_a_live_row` again. `P2_FIELD` has no op
    selectors; its `x_needs_live` does the first of those jobs (§23.5).
28. **Two field families fix a value only up to a multiple of the modulus, and the executor's
    choice is what makes it canonical.** `FIELD_IO`'s `EXPORT` proves eight limbs below `2^32`
    whose weighted sum is congruent to the cell mod `p`, which five or six representatives
    below `2^256` satisfy (§24.5). `FQ_OP`'s `d′` is fixed mod `q` with limbs below `2^64` and a
    nonnegative quotient, which up to six satisfy (§25.6). Neither carries a `< modulus` chain,
    where `MOD_MUL`'s and `EC_ADD`'s results do; each executor writes the reduced
    representative, and a reader that needs the canonical one checks or reduces it itself.
    `FR_OP`'s `DIGIT` is the same shape a third time: its gates admit 256 digits a row, and
    what gives a chain of digits its meaning is the caller's last check that the rest is 0
    (§22.5).
29. **`FQ_OP`'s executor and circuit disagree at two edges, in opposite directions.** The
    executor accepts a `MULEQ` whose kept `d` is a representative above `a·b`, checking only
    `d ≡ a·b (mod q)`, and the circuit has no witness for it: `K` would be negative, and
    `fq_op::witness` panics on the row (§25.6). Only `FROM128` writes an unreduced element, so
    the case needs a `MULEQ` whose `d` came from one. The other way, the executor refuses a
    digit cell holding no value below `2^24` on a direct row too, where the circuit multiplies
    the digit by 0 and nothing local reads it (§25.2, §25.5); `guests/field-ops`' direct rows
    name cell 0, which nothing writes.
30. **An access a row does not make leaves its cells free, in the two field families that mask
    accesses by op.** On an `FR_OP` row whose op skips an access, that access's leaves are the
    product's identity, its four obligations are off and no live gate reads its values
    (§22.9); on a `P2_FIELD` row with `n < 2`, `x` or `y`, its read timestamp and its gap chunks
    are free the same way (§23.5). Observation 7's shape: nothing depends on the cells, and the
    honest fill writes 0. `FIELD_IO` and `FQ_OP` mask every access by `live` alone, so a live
    row makes all of them — `FQ_OP` names an element for every operand, including one the op
    ignores (§25.2).
31. **A `P2_FIELD` padding row is constrained where no leaf can see it.** Its 352 permutation
    gates are ungated, and `lane0_rule` and `lane1_rule` hold with both masks 0, so a padding
    row's lanes are its state's and every intermediate and `next0`–`next2` are the
    constant-free permutation of `(state0, state1, state2)`, while the rest of the row is free
    but for four cells (§23.2). It is harmless — no leaf publishes any of it — and it is read
    off the gates: no suite evaluates a padding row other than the all-zero one.
32. **A booleanity gate can be implied and still be owed.** `FR_OP`'s `a_live_boolean`,
    `b_live_boolean` and `d_live_boolean` follow from `one_op_a_live_row` and the nine op
    booleanities, each mask being a sum of selectors at most one of which is set; but
    `check_memory` requires a booleanity gate for every committed leaf mask and `validate` one
    for every lookup selector, and each of the three is both. Its `z_boolean` is implied by the
    is-zero gadget and written anyway, where `FR_ARITH`'s `is_zero` carries none (§22.5,
    §14.3). Observations 3 and 13 are the same shape; none of the four costs a degree.

---

## 27. Maintaining this page

A stage that adds a circuit family, or changes one, updates this page in the same pull request
(`prompts/00-master.md`, implementation rule 12). **Changing one is the same obligation as
adding one**: S21 added §12 and rewrote §3 from the new artifact, because the eighth memory
query moved every relation number in it, and §3 was rewritten again when the POSIX layer's
deletion took three queries back out — a change that added no circuit at all and still moved
every `M` and `W` index, every relation number, both fixture digests, the depth and the proof
length (§3.1). **A retired ecall is a circuit change**, and this is where it lands, and **so is
a pinned height**, even one that moves no gate: S-STREAM moved `family::PUBLIC_WINDOW_HEIGHT`
from `2^8` to `2^12`, which added four halving lists to two artifacts and changed nothing else
about either, and that alone moved §1.1's two registry rows and its menu sentence, §1.2's two
master-table rows and their byte lengths, §1.3's five-windows bullet, §15 and §16 throughout,
§26 observation 1 and Appendix A's dump recipe. The test for whether this page owes an edit is
not "did a gate change" but "did a number here come from something that moved".

A new family's entry is a section like §3, §4, §5 or §6 and holds:

1. **A header**: the family id and constant, the constructor, the channels, the fill, the spec
   section that is normative for it, the committed and virtual column counts, and the depth,
   inner-column and relation counts at the heights its stage proves.
2. **Its row kinds**: the kind bits and codes, which queries each kind makes, what each writes,
   and what is not provable.
3. **Every base column**: `PolyAddress`, artifact name, Rust identifier, a descriptive name,
   what the honest fill writes, who fills it, where it is committed, and every gate, leaf and
   obligation that reads it. The frame's columns may cite §2.
4. **Every gate of list 0**, leaves and enforcing gates, by relation number, with its purpose,
   shape, degree, constructor, positional form and named form, factored where it helps. Leaves
   built by one pattern (§0.6) may be given as a table of their operands under that pattern,
   with the pattern's positional form shown once.
5. **Every lookup**: channel, selector and tuple in both forms, and the channel table with
   output positions, table columns and multiplicity column.
6. **Every inner layer**: each row-wise layer in full, and the halving pattern with its relation
   numbers and root names.
7. **The outputs**, and which `verify_shard` step reads each.
8. **Witness rows** taken from a test that holds them to the circuit in CI, and the per-cell
   accounting of §3.10 and §4.10 — or, where the family's suite carries a committed tamper
   table of its own (§5.10, §6.10), that table read as a cell-by-cell account, which is the
   better source: it runs in CI and a probe does not. A family too wide for a row table says so
   and gives the chain that stands in for one instead (§12.9).
9. **Its rows in §1.1, §1.2 and §1.3, its counts in §0.5, the challenge slots it reads in
   §0.4**, and any §26 observation the accounting turns up — a family only the recursion
   registry holds marked as `recursion_circuit`'s there, and pinned by its line in
   `recursion.txt`. A family whose decoded tuple is not
   seven wide also moves §0.4's `β⁶` and `g_dec` rows, as `MUL_DIV`'s and `ATOMICS`' six-wide
   ones did; a family that reads or does not read the generic channel moves §0.4's `β` and `β²`
   rows, as `MEM_WORD`'s absence from them records.

Appendix A's commands print every `n = 22` name, position and formula, and the `n = 22` counts
follow from them; the `n = 8`, `n = 16`, `n = 18` and `n = 20` counts and the §3.10 and §4.10
probes were read from `family_circuit` and the suites' `honest_rows` directly and have no
committed command (Appendix A, last paragraph). **§12's artifact is not committed as bytes**:
like the other five delegation families it is committed by digest
(`crates/constraints/tests/vectors/keccak.txt`), and what this page was read from is
`keccak::artifact(18)` itself — small enough to dump since S26d (Appendix A). **Neither is any
circuit only the recursion registry returns**: `crates/constraints/tests/vectors/recursion.txt`
pins §3.11's and §21–§25's by digest, and what this page was read from is a `checker dump` of each
artifact written to a file (Appendix A). §7.9's, §8.9's
and §9.9's rows are the three fills' own output over `guests/mem`, which
`crates/checker/tests/mem_fill.rs` holds to every gate and both table channels in ordinary CI.
The `checker dump` of the family's committed fixture is the machine view to check the entry
against.

---

## Appendix A. Reproducing

```text
cargo run -p checker -- dump crates/constraints/tests/vectors/add_sub.bin           # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/jump_branch_slt.bin   # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/shift_bitwise.bin     # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/mul_div.bin           # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/mem_word.bin          # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/mem_subword.bin       # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/atomics.bin           # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/image_window.bin      # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/zero_window.bin       # n = 22
#   zero_window.bin is PUBLIC_OUTPUT's circuit too: family_circuit(13, n) and
#   family_circuit(8, n) are one constructor and agree byte for byte at every n.
# PUBLIC_INPUT's and ADVICE_WINDOWS' artifact has NO committed fixture, value_window_artifact
#   being S-IO's one new constructor. To read §15 and §17 from it, write the bytes and dump them:
#     memory::value_window_artifact(12).to_bytes() -> value_window_12.bin  (2,455 bytes)
#     memory::value_window_artifact(22).to_bytes() -> value_window_22.bin  (3,535 bytes)
#     memory::zero_window_artifact(12).to_bytes()  -> zero_window_12.bin   (2,338 bytes)
#   then `checker dump`, `checker laws` and `checker padding` over each. The 12 is S-STREAM's
#   pinned public-window height; at S-IO the same three reads were n = 8, 22 and 8, and the
#   artifacts were 2,027, 3,535 and 1,910 bytes.
# §13, §14, §18 and §20 have no dump: a delegation family's artifact is megabytes --
# `poseidon2::artifact(8).to_bytes()` is 2,056,361 -- so what is committed is a SHA-256 and the
# shape line beside it, and what this page was read from is the constructor itself. **§19's is
# small enough to dump since S26e**: `sha256::artifact(18).to_bytes()` is 845,456 bytes, where
# S26c's `sha256::artifact(8)` was 10,895,760. **§12's is small enough to dump since S26d**: write
# `keccak::artifact(18).to_bytes()` to a file (1,900,468 bytes) and `checker dump` it; at the
# `n = 16` §1.2 also pins it is 1,899,700 bytes and 20,333 readable lines, the two differing
# only in the halving phase. S21's was 100,254,040 bytes and had no dump at all.
cat crates/constraints/tests/vectors/keccak.txt
cat crates/constraints/tests/vectors/poseidon2.txt
cat crates/constraints/tests/vectors/fr_arith.txt
cat crates/constraints/tests/vectors/mod_mul.txt      # 2^16 since S26c; §18
cat crates/constraints/tests/vectors/sha256.txt       # §19
cat crates/constraints/tests/vectors/ec_add.txt       # §20
cargo run -p kat-gen -- delegation              # rewrites all six lines from the constructors
cat crates/constraints/tests/vectors/recursion.txt   # §3.11 and §21–§25: the recursion registry's
                                                     # six circuits, by shape line and SHA-256
cargo run -p kat-gen -- recursion               # rewrites recursion.txt from recursion_circuit
# §3.11's and §21–§25's dumps: no CLI writes the bytes. Write
#   constraints::recursion_circuit(family, n).unwrap().artifact.to_bytes() to a file and
#   `checker dump` it:
#     (0, 20)    77,987 bytes  §3.11, diffed against family_circuit(0, 20)'s 70,974
#     (18, 20)    2,758 bytes  §21
#     (19, 20)   89,741 bytes  §22
#     (20, 18)  294,425 bytes  §23, 2,531 lines
#     (21, 18)  164,713 bytes  §24, 2,278 lines
#     (22, 20)  158,326 bytes  §25, 2,300 lines
#   `checker laws` and `checker padding` over the (0, 20) bytes hold as well.
for f in alu reg mem atomics; do
  cargo run -p checker -- dump crates/constraints/tests/vectors/memory_frame_$f.bin    # §2.2's four bare frames
done
cargo run -p checker -- laws crates/constraints/tests/vectors/add_sub.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/jump_branch_slt.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/shift_bitwise.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/mul_div.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/mem_word.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/mem_subword.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/atomics.bin
cargo test -p checker --test add_sub            # §3.9's rows against every gate and bound, and
                                                # §3.11's three recursion requests
cargo test -p checker --test jump_branch_slt    # §4.9's rows against every gate, bound and table
cargo test -p checker --test shift_bitwise      # §5.9's and §5.10's, 17 tests
cargo test -p checker --test mul_div            # §6.9's and §6.10's, 17 tests
cargo test -p checker --test mem_word           # §7.10's, 12 tests
cargo test -p checker --test mem_subword        # §8.10's, 17 tests
cargo test -p checker --test atomics            # §9.10's, 15 tests
cargo test -p checker --test mem_fill           # §7.9's, §8.9's and §9.9's rows: the three
                                                # fills over guests/mem's trace, in ordinary CI
cargo test -p checker --test keccak             # §12.9's forward pass and §12.10's ten
                                                # negative controls, 13 tests, in ordinary CI
cargo test -p emulator --test keccak            # emulator::keccak_f against tiny-keccak, which
                                                # is what §12.9's chain rests on
cargo test -p constants --test keccak           # ROTATIONS and ROUND_CONSTANTS re-derived
cargo test -p checker --test mod_mul            # §18's rows and controls, 14 tests, in ordinary
                                                # CI -- row-local at n = 16, this family having
                                                # exactly one height since S26c
cargo test -p checker --test sha256             # §19's rows and controls, 23 tests, in ordinary
                                                # CI -- row-local at n = 18, this family carrying
                                                # two channels since S26e
cargo test -p constants --test sha256           # IV and ROUND_CONSTANTS re-derived from the
                                                # square and cube roots of the first primes
cargo test -p checker --test ec_add             # §20's rows and controls, 21 tests, in ordinary
                                                # CI -- row-local at n = 16
cargo test -p prover --test fills               # §18's, §19's and §20's fills: every address
                                                # written once for SHA256_COMP, whose gates the
                                                # checker's fill test evaluates, and sampled rows
                                                # for the two at 2^16, whose passes are 4.6 GB
                                                # and 18.3 GB
cargo test -p checker --test public_values      # §15's, §16's and §17's shapes, both public
                                                # windows' and the advice region's layouts, and
                                                # the window rules, in ordinary CI
cargo test -p constraints --test recursion      # the five recursion families build in the
                                                # recursion registry alone, and the registries
                                                # differ in ADD_SUB alone
cargo test -p checker --test recursion          # §21–§25's rows and the field memory's balance,
                                                # and §3.11's form over field-ops' 105 field
                                                # requests, in ordinary CI
cargo test -p constraints --lib p2_field        # §23.9's the_witness_is_the_permutation
cargo test -p emulator --test guests field_ops  # field-ops' literal checks and its invocation
                                                # counts, in ordinary CI
cargo test --release -p prover --test field_ops -- --include-ignored --test-threads=1
                                                # the one recursion-format proof: field-ops proved
                                                # and verified, every shard's tape replayed.
                                                # DEFERRED
cargo test -p prover --test public_io -- --include-ignored --test-threads=1
                                                # S-IO's statement: guests/public-io proved and
                                                # verified, step 10c isolated, and the advice
                                                # shown unbound. DEFERRED; a 2^20 statement
```

The dump prints the header, the committed columns, the virtual tables, every gate list with
each gate as a formula over addresses and its relation number and name, the flat relation list,
the scratch bijection, the output map, the lookups, the padding contract and the gate
catalogue. A relation number, an `L{k}[j]` and a node name in this page are the dump's, except
that the leaf and inner-layer subsections write a fraction node by its stem `x`: the dump names
its two columns `x_num` and `x_den`, defined by relations `define_x_num` and `define_x_den`. The
halving lists repeat one pattern, so the dump at `n = 22` gives every `n`: the row-wise layers do
not depend on `n` — `L1`–`L5` for add/sub, jump/branch/slt and mem_word, `L1`–`L6` for the two
S18 families and for mem_subword and atomics — nor do relations 0–200 of add/sub, 0–213 of
jump/branch/slt, 0–305 of shift/bitwise, 0–297 of mul/div, 0–170 of mem_word, 0–304 of
mem_subword and 0–317 of atomics, and the halving lists follow §3.8's, §4.8's, §5.8's, §6.8's,
§7.8's, §8.8's and §9.8's formulas.

The counts at `n = 16`, `n = 18` and `n = 20` were read from `family_circuit` directly (its artifact's
`depth()`, layer widths, `relations`, `lookups` and `to_bytes()`), which has no CLI; §15's,
§16's and §17's counts were read the same way, from `family_circuit(12, 12)`,
`family_circuit(13, 12)`, `family_circuit(14, 16)` and `family_circuit(14, 22)`, and their
columns, gates, relation numbers, outputs and padding contracts from the dumps above. §3.11's
and §21–§25's were read the same way from `recursion_circuit`, and the recursion form's
relations 0–212 do not depend on `n` either. The §3.10
probe is add/sub's `honest_rows` with one cell moved at a time, run through
`violated_relations` and `violated_lookups`; the §4.10 probe is the same over
jump/branch/slt's `honest_rows`, run also through that suite's own table check,
`violated_tables`. §5.10, §6.10, §7.10, §8.10 and §9.10 need no probe: they are their
suites' `each_gate_is_the_one_that_refuses_its_row` read as a cell-by-cell account, and that
test runs in ordinary CI. §1.2's proof byte lengths are `crates/prover/tests/acceptance.rs`',
`control.rs`', `alu.rs`' and `mem.rs`', all of which are `#[ignore]`d and run with
`--include-ignored --test-threads=1`; the formula they check them against is
`shard-proof.md` §9's over the circuit's own shape, written out as `mem.rs`' `proof_bytes`.
§12's **381,100** is that same formula over `keccak::artifact(18)`, which
`crates/prover/tests/keccak.rs` asserts against the real `ShardProof::to_bytes().len()` — a
derived figure until that deferred suite runs, the same formula's 373,276 at `2^16` having been
measured.
