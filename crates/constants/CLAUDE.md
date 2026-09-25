# `crates/constants`

## What this crate owns
Every frozen numeric constant and domain-separation tag in the protocol, and nothing
else. If a later stage needs a magic number that outlives one function, it belongs
here.

## Frozen invariants
- **Zero logic, forever.** `src/` holds constant items and doc comments only: no
  functions, no `const fn`, no traits, no macros, no dependencies. A test that checks a
  constant lives in the crate that consumes it (see
  `crates/field/tests/constants_check.rs`).
- **One exception, added at S10:** `tests/ecall_abi.rs`. `docs/spec/ecall-abi.md` *is* the
  ABI, and acceptance 9 wants the document checked against the numbers rather than
  maintained beside them. An integration test is a separate crate, so `src/` is still
  `#![no_std]` with nothing in it but constants.
- **A third, added at S21:** `tests/keccak.rs`, which re-derives `keccak::ROTATIONS` from the
  `(t+1)(t+2)/2 mod 64` walk and `keccak::ROUND_CONSTANTS` from the degree-8 LFSR, rather than
  trusting the transcription. Two tables of 25 and 24 numbers copied from a reference are
  exactly the kind of constant a test must re-derive; the same rule as the Poseidon2 round
  constants and the pairing tables below.
- **A second, added at S14:** `tests/memory.rs`, because `RAM_LIVE_BIT` and `HALT_PC` are
  claims about `guest_memory::RAM_ORIGIN`: `RAM_ORIGIN == 4 << RAM_LIVE_BIT`, and
  `HALT_PC` odd and below it; `lookup_channel::BITS[TIMESTAMP]` is one about
  `memory::TS_BITS`, two chunks of it being the clock; and two `BITS[RANGE16]` halfwords
  are a 32-bit word.
- **`#![no_std]`, forever.** Guest-side code links this crate.
- **From the first registered program identity on**, changing any value here is a
  protocol-version change and must bump `PROTOCOL_VERSION`. Until then `PROTOCOL_VERSION`
  is the unregistered placeholder 0, and `family::CODE_VERSION` stays 0 with it: S12
  (`guest_memory::RAM_LENGTH`) and S14 (`family::DEFAULT_HEIGHTS[INIT_TEARDOWN]`,
  `family::COUNT`, `challenge_slot::NAMES`, `lookup_channel`) changed values without
  bumping either, by the owner's decision (`docs/handoff/S14-multiset.md`). S15 appended
  only — two channels, eight challenge slots and one tag — and changed no value, except
  `lookup_channel::BITS`, which grew from two entries to four. **S21 changed four values and
  appended three modules**, under the same pre-registration licence: `family::COUNT` 9 → 10,
  `family::CYCLE_OWNING` and `family::DEFAULT_HEIGHTS` each one entry longer, and
  `family::HEIGHT_MENU` gained `2^8` at its front — the one that is a real amendment, since it
  widens what a `VmConfig` may carry. The new modules are `keccak` (the permutation's frozen
  tables and sizes), `delegation` (the frame and anchor deltas and the declaration record's
  magic) and one tag-free addition to `address_space`. **S23 appended two more delegation
  families**, `POSEIDON2` and `FR_ARITH`, taking `family::COUNT` to 12 with their tags,
  heights and `CYCLE_OWNING` entries. **S25b appended one family and one address space**:
  `family::ADVICE_WINDOWS = 12` with `COUNT` 12 → 13 and one more entry in `CYCLE_OWNING`
  and `DEFAULT_HEIGHTS`, the new frozen list `family::WINDOW_FAMILIES`,
  `address_space::ADVICE = 7`, and `guest_memory::ADVICE_ORIGIN` / `ADVICE_LENGTH`. It
  changed no existing value: the advice tag took the next unclaimed number rather than
  displacing one, which is why the delegation tags are no longer contiguous and why
  `address_space::DELEGATION` is a list rather than a range. S16 appended seven tags and
  changed nothing. S17 appended one tag and the `generic_table` module, whose three values
  S15 had frozen in `crates/program` and which moved here unchanged. S20 appended no tag
  and changed no value: it added two documentation tables, `family::CYCLE_OWNING` and
  `transcript_tags::NAMES`.

## Contents as of S25b
| Item | Meaning |
| --- | --- |
| `PROTOCOL_VERSION: u32` | Placeholder, `0`, until the first registered identity. First item absorbed into every transcript. |
| `FR_MODULUS: [u64; 4]` | BN254 **scalar** field modulus `p`, little-endian limbs. |
| `FR_MODULUS_MINUS_TWO: [u64; 4]` | `p - 2`, the Fermat exponent for inversion. |
| `FR_R: [u64; 4]` | `2^256 mod p`. Also the Montgomery form of `1`. |
| `FR_R2: [u64; 4]` | `2^512 mod p`. Converts canonical → Montgomery in one multiply. |
| `FR_INV: u64` | `-p^{-1} mod 2^64`, the CIOS reduction multiplier. |
| `FQ_MODULUS: [u64; 4]` | BN254 **base** field modulus `q`, little-endian limbs. |
| `FQ_MODULUS_MINUS_TWO: [u64; 4]` | `q - 2`, the Fermat exponent for inversion. |
| `FQ_MODULUS_PLUS_ONE_DIV_FOUR: [u64; 4]` | `(q+1)/4`, the square-root exponent (`q = 3 mod 4`). |
| `FQ_R`, `FQ_R2`, `FQ_INV` | Fq's Montgomery radix, its square, and the CIOS multiplier. |
| `FQ2_NONRESIDUE: &str` | `q - 1`, so `Fq2 = Fq[u]/(u^2+1)`. |
| `FQ6_NONRESIDUE_C0/_C1: &str` | `xi = 9 + u`, the Fq6 nonresidue: `Fq6 = Fq2[v]/(v^3 - xi)`. |
| `G1_B: &str` | `3`: `E/Fq: y^2 = x^3 + 3`. |
| `G2_B_C0/_C1: &str` | `3/xi = 3/(9+u)`: the D-type sextic twist. |
| `G1_GENERATOR_X/_Y: &str` | The standard G1 generator `(1, 2)`. |
| `G2_GENERATOR_X_C0/_C1`, `_Y_C0/_C1: &str` | EIP-197's G2 generator, coordinate for coordinate. |
| `FQ6_FROBENIUS_C1/_C2: [[&str; 2]; 6]` | `xi^((q^i-1)/3)` and `xi^((2q^i-2)/3)`: the Fq6 Frobenius twists. |
| `FQ12_FROBENIUS_C1: [[&str; 2]; 12]` | `xi^((q^i-1)/6)`: the Fq12 Frobenius twist. |
| `TWIST_FROBENIUS_X/_Y: [&str; 2]` | `xi^((q-1)/3)` and `xi^((q-1)/2)`: the `psi` endomorphism on G2. |
| `BN_PARAMETER_X: u64` | `4965661367192848881`, the BN parameter both moduli come from. |
| `ATE_LOOP_NAF: [i8; 66]` | the NAF of `6x + 2`, least-significant digit first. |
| `FINAL_EXP_LAMBDA_0/_1/_2: [u64; 4]` | the base-`q` decomposition of `(q^4-q^2+1)/r`; 0 and 1 are negative and stored as magnitudes. |
| `FR_TWO_ADICITY: u32` | 28: `p - 1 = 2^28 * c`, the ceiling on every radix-2 FFT. |
| `FR_TWO_ADIC_ROOT_OF_UNITY: &str` | `5^((p-1)/2^28)`, a generator of the order-`2^28` subgroup. |
| `G1_INFINITY_SENTINEL: &str` | `2^128`: the limb a G1 point at infinity absorbs in each of its four lanes. |
| `POSEIDON2_RC3_INITIAL: [[&str; 3]; 4]` | Round constants, 4 initial full rounds. |
| `POSEIDON2_RC3_INTERNAL: [&str; 56]` | Round constants, 56 partial rounds, lane 0. |
| `POSEIDON2_RC3_TERMINAL: [[&str; 3]; 4]` | Round constants, 4 terminal full rounds. |
| `transcript_tags` | The frozen tag table: 41 tags as of S17, sequential from 1; and S20's `NAMES`, one per tag indexed by `tag - 1`, **documentation and never semantics**, as `challenge_slot::NAMES` is. `checker::tape` renders a transcript's absorb sequence with them, which is what makes a tape diffable against `docs/spec/shard-proof.md` §2; the lookup itself lives there, because this crate holds no logic. |
| `challenge_slot` | S13's `TOY = 0`; S14's memory slots `MEM_GAMMA` 1, `MEM_ALPHA_ADDR` 2, `MEM_ALPHA_TS` 3, `MEM_ALPHA_VAL` 4, and the derived `MEM_WINDOW_CONSTANT` 5; S15's `LOOKUP_G` 6 and `LOOKUP_BETA` 7, drawn per shard, with the derived powers `LOOKUP_BETA_2..6` 8–12 (also as `LOOKUP_BETA_POWERS`) and `LOOKUP_DECODER_NEUTRAL` 13; `NAMES`. Append-only. |
| `lookup_channel` | S14's `TIMESTAMP = 0` and `RANGE16 = 1`, S15's `GENERIC = 2` and `DECODER = 3`; `COUNT`, `IS_RANGE`, the bounds `BITS = [19, 16, 0, 0]` — 0 where `IS_RANGE` is false, which is the absence of a bound and not a bound of `[0, 1)` — `NAMES`, and `MAX_TUPLE = 7`, past which `β` has no slot. Append-only; `docs/spec/memory.md` §7 freezes the range convention `RANGE16` serves and `docs/spec/lookup.md` the rest. |
| `generic_table` | S15's packed generic table, moved from `program::lookup_tables` at S17 because a circuit now builds a key into it: `WIDTH = 3`, `AND_BASE = 0`, `SIGN_BASE = 256`, and S18's `SHIFT_BASE = SIGN_BASE + 2^16`, `SHIFT_ROWS = 32`, `SHIFT_COPOWER_BITS = 31`. Appending a table here moves the table's three commitments and so every verifying key's SRS digest; `SHIFT_COPOWER_BITS` is 31 and not 32 because `2^32` does not fit the table's `u32` columns, so the copower is stored halved and the two gates that read it carry a factor 2. `docs/spec/lookup.md` §9, `docs/spec/shift-bitwise.md` §3.1. |
| `address_space` | S12. `REG = 1`, `RAM = 2`, `PC = 3`: nonzero, so no real memory tuple is all zeros. S21 added `DELEGATION_KECCAK_F = 4`, **one space per delegation family**: an anchor tuple must be unreachable from RAM and from any other family's, so a space is what separates them (`docs/spec/delegation.md` §3, §5); S23 added `DELEGATION_POSEIDON2 = 5` and `DELEGATION_FR_ARITH = 6`, and `DELEGATION`, the ascending list a reader tells an anchor by — **never a range**, which is what made the next addition free. **S25b's is `ADVICE = 7`** (`docs/spec/advice.md` §1): memory in every way `RAM` is — word-granular, chaining, initialized by a window family — and private in the one way that matters, its initial values being the prover's. It cannot alias RAM twice over: the tags differ, so no two tuples are equal, and the *addresses* are disjoint too, which is what stops a guest pointer walking from one region into the other. The next delegation family takes 8. |
| `memory` | S12's clock, `TS_STEP` and `TS_BITS`; S14's `HALT_PC = 1`, the tuple part order `PART_AS/ADDR/TS/VAL`, the root positions `READ_ROOT = 0` and `WRITE_ROOT = 1`, and `RAM_LIVE_BIT = 14`. `docs/spec/memory.md`. |
| `family` | S11. The append-only `FamilyId` table (0 add/sub/lui/auipc … 6 atomics, 7 `INIT_TEARDOWN`, since S14 RAM window 0 only; S14's 8 `ZERO_WINDOWS`; **S21's 9 `KECCAK_F`**, the first delegation family and the first family above the two window ones; S23's 10 `POSEIDON2` and 11 `FR_ARITH`; **S25b's 12 `ADVICE_WINDOWS`**, the RAM window families' third sibling, which differs from them in exactly one thing — its rows' initial values are a **free** committed column, nothing in identity, the statement or the key saying what they must be, `docs/spec/advice.md` §5), `COUNT` = 13, the height menu, the default heights, `DEFAULT_BYTECODE_SIZE_WORDS`, the decoded-table `CODE_VERSION`, S20's `CYCLE_OWNING`: whether a family's rows are execution cycles, `true` for the seven instruction families and `false` for the three window families **and for every delegation family**, append-only beside the ids; and **S25b's `WINDOW_FAMILIES`**, the ascending list of families present in every `VmConfig` whose rows are addresses. That list is what let advice join `program::decode_program`'s three presence rules rather than need a fourth, and it is what `trace::archive`'s part check now reads instead of naming two ids — naming them one by one is how the third slipped in with a buffer full of rows. The three are **not** held to one height: `verifier_core::window_height` holds the two RAM ones to one because they tile one region between them, and advice is a region of its own. Only cycle-owning families' shards partition an execution in time (`docs/spec/block-proof.md` §4). **`HEIGHT_MENU` opens with `2^8` since S21** and `DEFAULT_HEIGHTS[KECCAK_F]` is that: a delegation family's rows are invocations, not halfwords, and `2^16` of them is 744 GB of forward pass (`docs/spec/delegation.md` §9). It is an even power because Mercury needs one. |
| `delegation` | **S21.** The delegation ABI's numbers: `FRAME_DELTA = 0`, the in-cycle slot an invocation's frame accesses ride — a `(space, Δ)` pair no role takes, which is how `trace`'s frame builder tells them from the requesting row's; `ANCHOR_DELTA = 3`, the slot the request's mirror query writes at; and `MARKER_MAGIC` / `MARKER_BYTES`, the 12-byte `.rodata` record a linked shim emits so the preprocessor can see a family no pc claims (`docs/spec/delegation.md` §4, §5, §7). |
| `keccak` | **S21.** keccak-f[1600] and keccak-256 as data: `LANES`, `LANE_BITS`, `STATE_BITS`, `STATE_BYTES`, `FRAME_WORDS = 50`, `ROUNDS = 24`, `RATE_BYTES = 136`, `DIGEST_BYTES = 32`, the sponge's `PAD_FIRST`/`PAD_LAST`, and the two tables `ROTATIONS` and `ROUND_CONSTANTS`. The circuit, the emulator and the guest SDK all read them, which is the point: one permutation, three consumers, no second copy. `tests/keccak.rs` re-derives both tables. |
| `extra_mask` | S11. Every family's `family_extra_mask` bit positions, one-hot per mnemonic, append-only, and the system codes `ecall`/`ebreak`/`fence` carry in `imm`. |
| `guest_memory` | The frozen guest memory map: `RAM_ORIGIN` and `RAM_LENGTH`; since S12, `STACK_RESERVE`, the 8 MiB at the top of RAM guest-sdk's allocator leaves to the stack; and, since S25b, `ADVICE_ORIGIN = 0x8000_0000` and `ADVICE_LENGTH = 0x8000_0000`, the advice region. The origin is **not a free choice**: `RAM_ORIGIN + RAM_LENGTH` is exactly `0x8000_0000` and `verifier_core::check_memory_windows` caps a RAM window id at `2^29/h − 1`, the same ceiling in window units, so the two regions are disjoint on both sides. Sitting on a power of two is also what makes the circuit's selector one bit of a column the memory families already commit, rather than a comparison against a base (`docs/spec/advice.md` §1.1, §3.1). |
| `ecall` | The guest ecall ABI: syscall numbers, range boundaries, file descriptors. |

S11 added `PROGRAM_IDENTITY` (22), `VM_CONFIG` (23) and `SHARD_COUNTS` (24), all scalars:
the program-identity sponge's opening message, and the first two of the statement
descriptor's three messages. S14 added `MEMORY_WINDOWS` (30), the third; `MEMORY_BOUNDARY`
(31), the 64 register and pc boundary scalars; and `PROGRAM_ENTRY` (32), the entry pc in
the identity sponge — all scalars, `docs/spec/memory.md` §6. S15 added
`LOOKUP_CHALLENGE` (33), of **challenge** kind: a shard draws `g` then `β` under it, after
every witness and multiplicity commitment of the shard is absorbed
(`docs/spec/lookup.md` §2). One tag, one kind; the two roles are separated by their fixed
position in the shard's script, as `SUMCHECK_CHALLENGE`'s are. S16 added the statement's
own seven (`docs/spec/shard-proof.md` §2–§4): `SRS_DIGEST` (34, scalars), the digest the
global transcript absorbs at G2; `SRS_VERIFIER` (35, **bytes**), the 320-byte verifier
points, the first message of the SRS digest's own sponge; `MEMORY_GROUP` (36, scalars),
`[family, count]` ahead of each family's memory commitments; `MEMORY_CHALLENGE` (37,
**challenge**), the four memory challenges; `GLOBAL_STATE_DIGEST` (38, **challenge**), the
squeeze every shard seeds from; and `SHARD_SEED` (39) and `SHARD_TS_WINDOW` (40), scalars,
the first two messages of a shard's own transcript. S17 added `GENERIC_TABLE` (41,
scalars): the packed generic table's three commitments that every verifying key carries,
one message of twelve limbs, absorbed right after `SRS_VERIFIER` inside the SRS digest's
sponge and nowhere else — the global transcript has no message under it
(`docs/spec/shard-proof.md` §3, `docs/spec/jump-branch-slt.md` §6). `family` and
`extra_mask` are numbers the decoded tables and the identity recipe are built from, so the
same rule applies to them as to tags: **append, never renumber** — a renumbered family or
mask bit is a different program identity for every program. `crates/program/CLAUDE.md` is
the design record for both, and `crates/program/tests/tables.rs` pins the masks and checks
every bit names one mnemonic.

`FR_MODULUS_MINUS_TWO` is an additive extension beyond S01's enumerated list; it is a
property of the modulus and belongs next to it. The same reasoning puts
`FQ_MODULUS_MINUS_TWO` and `FQ_MODULUS_PLUS_ONE_DIV_FOUR` beside `FQ_MODULUS`, and
`FR_TWO_ADICITY` / `FR_TWO_ADIC_ROOT_OF_UNITY` beside `FR_MODULUS`. Both of the latter are
re-derived rather than trusted, in `crates/pcs/src/fft.rs`'s unit tests: the root is
recomputed as `5^((p-1)/2^28)` from the modulus and its order is shown to be exactly
`2^28`.

`G1_INFINITY_SENTINEL` sits immediately above `transcript_tags` and is **not** part of it.
It is the one constant in this crate whose value is chosen rather than derived: `2^128` is
the smallest value no 128-bit coordinate half can take, which is what makes it collide with
no G1 point, on the curve or off it. `docs/spec/mercury.md` §4 is normative.

The pairing tables are all powers of `xi`, so each is re-derivable from one number, and
`crates/curve/tests/constants_check.rs` re-derives every entry as an integer exponent, checks
the relations that tie the tables to each other (`C2 = C1^2`, `FQ12_C1[i]^2 = FQ6_C1[i mod 6]`,
`gamma_x = FQ6_C1[1]`, `gamma_y = FQ12_C1[1]^3`) and compares each against arkworks-bn254's own
table. `crates/curve/tests/tower.rs` then checks all 24 entries a fourth way with no oracle at
all, by raising a random element to `q^i` directly. The `ATE_LOOP_NAF` digits are checked to be
in `{-1, 0, 1}`, non-adjacent, and to sum to `6x + 2`; the lambdas are re-derived from `x` and
their recomposition checked against `(q^4 - q^2 + 1)/r` as integers.

The Fq tower and curve parameters are **hex string literals read big-endian** by
`curve::Fq::from_hex`, the same one accepted spelling `field::Fr::from_hex` defines, so each
diffs against EIP-197 and arkworks-bn254 by eye. Their Montgomery-form counterparts live
privately in `crates/curve` — a `const GENERATOR` needs limbs at const-evaluation time and
`from_hex` is not a `const fn` — and every one of them is pinned against the canonical hex
here by `crates/curve/tests/constants_check.rs`.

The `POSEIDON2_RC3_*` tables are the upstream HorizenLabs `RC3` constants as **hex string
literals, copied from upstream character for character**, split by the permutation phase
that reads them. `field::Fr::from_hex` reads them big-endian, as upstream writes them, so
the vendored table diffs against its source by eye. Their provenance and the reason the
partial rounds store one lane are in the source comment, and
`crates/transcript/tests/poseidon2.rs` checks them against a committed dump of the full
upstream table rather than trusting the transcription — which is also where the two
textual conventions meet, since the dump is little-endian canonical bytes.

Tags are sequential from 1, never renumbered, never reused, and `0` is not a tag. Every
tag names exactly **one** message kind — scalars, bytes or a challenge — because the
typed layer's `tag, length, payload` framing is only injective under that rule. See
`docs/spec/transcript.md` section 8. S10 added `PUBLIC_INPUT_STREAM` (20) and
`PUBLIC_OUTPUT_STREAM` (21), both bytes: the two domain tags of the public I/O digest.

The `ecall` module holds the guest syscall numbers, the two non-Linux range boundaries and
the four file descriptors. It obeys the same rule as the tags, for a sharper reason:
**once a program's identity is published its ABI is frozen**, and redefining a number does
not fail loudly — it quietly makes an old program compute something else. The standard
calls keep their Linux numbers (`READ` 63, `WRITE` 64, `EXIT` 93) so `qemu-riscv32` runs a
guest unmodified. `ZKVM_IO_FIRST..=ZKVM_IO_LAST` is `0x0400..=0x04FF` and
`PRECOMPILE_FIRST..=PRECOMPILE_LAST` is `0x0500..=0x05FF`; both sit above the whole Linux
number space and are disjoint from each other, because a host call is nondeterministic
prover advice and a precompile is a deterministic function of memory, and a reviewer has
to tell them apart at a glance. `docs/spec/ecall-abi.md` is normative, and
`tests/ecall_abi.rs` holds it to this module in both directions.
