# `crates/constants`

## What this crate owns
Every frozen numeric constant and domain-separation tag in the protocol, and nothing
else. If a later stage needs a magic number that outlives one function, it belongs
here.

## Frozen invariants
- **Constants first, and logic only where it derives one.** `src/` is constant items and
  their doc comments, and a `const fn` belongs here only when it computes a value from
  frozen constants: `delegation::a0_after`, and `ec_add`'s and `mod_mul`'s helpers. *S01's
  rule was "zero logic, forever" — no functions, no `const fn`, no traits, no macros; the
  owner withdrew it at S-RECURSION as too restrictive.* A test that checks a constant
  usually lives in the crate that consumes it (see `crates/field/tests/constants_check.rs`).
- **`tests/ecall_abi.rs`, added at S10.** `docs/spec/ecall-abi.md` *is* the
  ABI, and acceptance 9 wants the document checked against the numbers rather than
  maintained beside them. An integration test is a separate crate, so `src/` stays
  `#![no_std]`.
- **`tests/keccak.rs`, added at S21**, which re-derives `keccak::ROTATIONS` from the
  `(t+1)(t+2)/2 mod 64` walk and `keccak::ROUND_CONSTANTS` from the degree-8 LFSR, rather than
  trusting the transcription. Two tables of 25 and 24 numbers copied from a reference are
  exactly the kind of constant a test must re-derive; the same rule as the Poseidon2 round
  constants and the pairing tables below.
- **`tests/memory.rs`, added at S14**, because `RAM_LIVE_BIT` and `HALT_PC` are
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
  `lookup_channel::BITS`, which grew from two entries to four and, at S26d, to five. **S21 changed four values and
  appended three modules**, under the same pre-registration licence: `family::COUNT` 9 → 10,
  `family::CYCLE_OWNING` and `family::DEFAULT_HEIGHTS` each one entry longer, and
  `family::HEIGHT_MENU` gained `2^8` at its front — the one that is a real amendment, since it
  widens what a `VmConfig` may carry. The new modules are `keccak` (the permutation's frozen
  tables and sizes), `delegation` (the frame and anchor deltas and the declaration record's
  magic) and one tag-free addition to `address_space`. S16 appended seven tags and
  changed nothing. S17 appended one tag and the `generic_table` module, whose three values
  S15 had frozen in `crates/program` and which moved here unchanged. S20 appended no tag
  and changed no value: it added two documentation tables, `family::CYCLE_OWNING` and
  `transcript_tags::NAMES`. **S-STREAM changed three values**, under the same
  pre-registration licence: `family::PUBLIC_WINDOW_HEIGHT` `2^8` → `2^12`,
  `guest_memory::PUBLIC_OUTPUT_ORIGIN` `0x8400` → `0xC000`, and `family::HEIGHT_MENU`
  gained `2^12` at **index 1** — the second real amendment to the menu, for S21's reason:
  it widens what a `VmConfig` may carry. **S-RECURSION changed six values**, `PROTOCOL_VERSION`
  still 0: `family::COUNT` 18 → 23, and `family::CYCLE_OWNING`, `family::DEFAULT_HEIGHTS`,
  `transcript_tags::NAMES`, `address_space::DELEGATION` and `delegation::TYPES` each four or
  five entries longer. Everything else it added was appended: four tags, five family ids, five
  address spaces, four ecall numbers, `delegation::BASE_TYPES` and `delegation::a0_after`, and
  the four frame modules `fr_op`, `p2_field`, `field_io` and `fq_op`. `HEIGHT_MENU` did not
  move.

## Contents as of S-RECURSION
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
| `transcript_tags` | The frozen tag table: 45 tags since S-RECURSION's four, 41 as of S17, sequential from 1; and S20's `NAMES`, one per tag indexed by `tag - 1`, **documentation and never semantics**, as `challenge_slot::NAMES` is. `checker::tape` renders a transcript's absorb sequence with them, which is what makes a tape diffable against `docs/spec/shard-proof.md` §2; the lookup itself lives there, because this crate holds no logic. |
| `challenge_slot` | S13's `TOY = 0`; S14's memory slots `MEM_GAMMA` 1, `MEM_ALPHA_ADDR` 2, `MEM_ALPHA_TS` 3, `MEM_ALPHA_VAL` 4, and the derived `MEM_WINDOW_CONSTANT` 5; S15's `LOOKUP_G` 6 and `LOOKUP_BETA` 7, drawn per shard, with the derived powers `LOOKUP_BETA_2..6` 8–12 (also as `LOOKUP_BETA_POWERS`) and `LOOKUP_DECODER_NEUTRAL` 13; `NAMES`. Append-only. |
| `lookup_channel` | S14's `TIMESTAMP = 0` and `RANGE16 = 1`, S15's `GENERIC = 2` and `DECODER = 3`, S26d's `XOR8 = 4`; `COUNT = 5`, `IS_RANGE`, the bounds `BITS = [19, 16, 0, 0, 0]` — 0 where `IS_RANGE` is false, which is the absence of a bound and not a bound of `[0, 1)` — `NAMES`, and `MAX_TUPLE = 7`, past which `β` has no slot. **`XOR8` is the first table channel whose table is a closed form** and not committed setup: the 65,536 triples `(a, b, a ^ b)` read off the row index, three columns wide (`docs/spec/lookup.md` §14). Append-only; `docs/spec/memory.md` §7 freezes the range convention `RANGE16` serves and `docs/spec/lookup.md` the rest. |
| `generic_table` | S15's packed generic table, moved from `program::lookup_tables` at S17 because a circuit now builds a key into it: `WIDTH = 3`, `AND_BASE = 0`, `SIGN_BASE = 256`, and S18's `SHIFT_BASE = SIGN_BASE + 2^16`, `SHIFT_ROWS = 32`, `SHIFT_COPOWER_BITS = 31`. Appending a table here moves the table's three commitments and so every verifying key's SRS digest; `SHIFT_COPOWER_BITS` is 31 and not 32 because `2^32` does not fit the table's `u32` columns, so the copower is stored halved and the two gates that read it carry a factor 2. `docs/spec/lookup.md` §9, `docs/spec/shift-bitwise.md` §3.1. |
| `address_space` | S12. `REG = 1`, `RAM = 2`, `PC = 3`: nonzero, so no real memory tuple is all zeros. S21 added `DELEGATION_KECCAK_F = 4`, **one space per delegation family**: an anchor tuple must be unreachable from RAM and from any other family's, so a space is what separates them (`docs/spec/delegation.md` §3, §5). Six spaces by S26c, tags 4 through 9. **S-RECURSION took 10 for `FIELD`, the field memory, and it is not a delegation space**: cells of whole `Fr` elements addressed by a `u32`, which no instruction reaches — a load or store names `RAM` — and only the recursion families' rows read and write (`docs/spec/recursion.md` §2). It took 11 through 14 for the four recursion families' anchors, so `DELEGATION`, the ascending list of every delegation tag that the `deleg` frame query takes, is ten long and does not hold 10. 15 is the next unclaimed. |
| `memory` | S12's clock, `TS_STEP` and `TS_BITS`; S14's `HALT_PC = 1`, the tuple part order `PART_AS/ADDR/TS/VAL`, the root positions `READ_ROOT = 0` and `WRITE_ROOT = 1`, and `RAM_LIVE_BIT = 14`. `docs/spec/memory.md`. |
| `family` | S11. The append-only `FamilyId` table (0 add/sub/lui/auipc … 6 atomics, 7 `INIT_TEARDOWN`, since S14 RAM window 0 only; S14's 8 `ZERO_WINDOWS`; **S21's 9 `KECCAK_F`**, the first delegation family and the first family above the two window ones; S23's 10 `POSEIDON2` and 11 `FR_ARITH`; **S-IO's 12 `PUBLIC_INPUT`, 13 `PUBLIC_OUTPUT` and 14 `ADVICE_WINDOWS`**, the three window families of `docs/spec/public-values.md`; **S26's 15 `MOD_MUL`**, the fourth delegation family, whose id is 15 and not 12 because the three window families took 12, 13 and 14 in between — which is what append-only means; and **S26c's 16 `SHA256_COMP` and 17 `EC_ADD`**; then **S-RECURSION's 18 `FIELD_WINDOWS`**, the field memory's zero-initialized windows, in a `VmConfig` exactly when the program declares a field delegation — which is what puts a statement in the recursion format (`docs/spec/recursion.md` §1.1) — **and its four field families, 19 `FR_OP`, 20 `P2_FIELD`, 21 `FIELD_IO` and 22 `FQ_OP`** — so `COUNT = 23`), `COUNT`, the height menu, the default heights, `DEFAULT_BYTECODE_SIZE_WORDS`, the decoded-table `CODE_VERSION`, and S20's `CYCLE_OWNING`: whether a family's rows are execution cycles, `true` for the seven instruction families and `false` for the two RAM window families, **for every delegation family, for S-IO's three and for S-RECURSION's five**, append-only beside the ids. S-RECURSION's defaults are `2^20` for `FIELD_WINDOWS`, `FR_OP` and `FQ_OP` and `2^18` for `P2_FIELD` and `FIELD_IO`; only `FQ_OP`'s is forced, its `TIMESTAMP` table needing 19 variables, the other three field families choosing above the floor of 16 their `RANGE16` channel sets. Only cycle-owning families' shards partition an execution in time (`docs/spec/block-proof.md` §4). **`HEIGHT_MENU` opens with `2^8` since S21 and carries `2^12` at index 1 since S-STREAM**, so it is six entries — `[2^8, 2^12, 2^16, 2^18, 2^20, 2^22]` — and the smallest height an *instruction* table may take is the **third**, `2^16`, where it was the second. Neither low entry is an execution height. `2^8` is the delegation one, and no delegation family needs it any more but `POSEIDON2` and `FR_ARITH` — `SHA256_COMP` left it at S26e for `2^18`, `KECCAK_F`'s height and for its reason: a delegation family's rows are invocations, not halfwords, and `2^16` of S21's whole-permutation keccak rows was 744 GB of forward pass (`docs/spec/delegation.md` §9). `2^12` is the two public families' and nothing else's — it is below every channel floor an execution family reaches, and a **window** family at `2^12` would reach only `0x4000`, short of where the public windows end, so `verifier_core::window_height` refuses it there. What it does widen is what a key may declare for the three channel-free delegation families, which is benign and bought nothing. `DEFAULT_HEIGHTS[KECCAK_F]` is **`2^18`** since S26d made one row one *round* — ~5,490 inner columns against 354,762 — and `MOD_MUL` and `EC_ADD` take `2^16`, which their `RANGE16` channel forces, where keccak's two channels give it only a **floor** of 16 and its `2^18` is a choice above that floor, because a shard's proof barely grows with its height — 381,100 bytes at `2^18` against 373,276 at `2^16` — so fewer, fatter shards cut a keccak-heavy block's proof bytes: two reasons `DEFAULT_HEIGHTS` is per family and not one number. It is an even power because Mercury needs one. **S-IO added three more items beside the ids, and S-STREAM moved every one of them**: `PUBLIC_WINDOW_HEIGHT = 2^12` — `2^8` until S-STREAM — the pinned height of the two public families, and `PUBLIC_INPUT_WINDOW = 2` / `PUBLIC_OUTPUT_WINDOW = 3`, each derived here as `origin / (4 · PUBLIC_WINDOW_HEIGHT)` and each 32 / 33 before the raise. The height is pinned by arithmetic and not by taste: a window's first address is `4·height·window`, so the height is what *places* the windows, and both must land inside the 64 KiB hole `[0, RAM_ORIGIN)` that no RAM window family initializes. Two windows of `2^12` are 16 KiB each, at `0x8000` and `0xC000`, and **end flush against `RAM_ORIGIN`** — which is what makes `2^12` the **ceiling** and not merely the current choice: `2^14` wants 128 KiB for the pair, and the only `2^14` window inside 64 KiB is window 0, which initializes address 0 and would let a null dereference balance. `[0, 0x8000)` is the half of the hole that survives, and it is the half that argument rests on. The price is the verifier's step 10c, two 4,096-point multilinear evaluations where S-IO's were 256-point (`docs/spec/public-values.md` §2). `DEFAULT_HEIGHTS` is that for both, and the window height for `ADVICE_WINDOWS`. |
| `delegation` | **S21.** The delegation ABI's numbers: `FRAME_DELTA = 0`, the in-cycle slot an invocation's frame accesses ride — a `(space, Δ)` pair no role takes, which is how `trace`'s frame builder tells them from the requesting row's; `ANCHOR_DELTA = 3`, the slot the request's mirror query writes at; and `MARKER_MAGIC` / `MARKER_BYTES`, the 12-byte `.rodata` record a linked shim emits so the preprocessor can see a family no pc claims (`docs/spec/delegation.md` §4, §5, §7). And `TYPES`, the one append-only registry of delegation types, `(family, ecall number, anchor space, frame words)` ascending by family id. **S-RECURSION appended its four field families to it, ten rows now, and added `BASE_TYPES = 6`**, the prefix the base format knows (`docs/spec/recursion.md` §1.2). The base `ADD_SUB` circuit commits a selector and three gates for every row it knows, so without a frozen prefix each appended row would move it and every base key's bytes; with one, the base circuit stays S26c's byte for byte and only the recursion form, which knows every row, grows. `a0_after(index, base)` is what a request of row `index` leaves in `a0`: 0 below `BASE_TYPES`, and past it the frame base advanced past its frame, `base + 4·words`, so a run of consecutive frames replays as back-to-back ecalls (§1.4). The emulator and the prover's fill compute it, and the recursion `ADD_SUB`'s `deleg_a0_rule` enforces it. |
| `keccak` | **S21, re-shaped at S26d.** keccak-f[1600] and keccak-256 as data: `LANES`, `LANE_BITS`, `STATE_BITS`, `STATE_BYTES`, `STATE_WORDS = 50`, `ROUNDS = 24`, `RATE_BYTES = 136`, `DIGEST_BYTES = 32`, the sponge's `PAD_FIRST`/`PAD_LAST`, and the two tables `ROTATIONS` and `ROUND_CONSTANTS`. S26d added the frame's own shape — `ROUND_WORD = 0`, `STATE_WORD = 1`, `FRAME_WORDS = 51`, `FRAME_BYTES = 204` — because one invocation is now one **round** and the round is frame word 0; `FRAME_WORDS` was 50 and is not the state's width any more, which is what `STATE_WORDS` is for. It also added `IOTA_BYTES = [0, 1, 3, 7]`, the byte positions a round constant can reach, with `IOTA_BYTES_ARE_THE_ONLY_ONES` asserting it at compile time: the circuit's iota is four obligations because of it, and four is what keeps its channel's fraction tree at 1,024 leaves (`docs/spec/delegation.md` §6.5). The circuit, the emulator and the guest SDK all read this module, which is the point: one permutation, three consumers, no second copy. `tests/keccak.rs` re-derives both tables and `IOTA_BYTES` from the LFSR's set bits. |
| `fr_op` | **S-RECURSION.** `FR_OP`'s frame `[op, d, a, b]` — `OP_WORD`, `D_WORD`, `A_WORD`, `B_WORD`, `FRAME_WORDS = 4`, `FRAME_BYTES = 16` — read and written back unchanged; the nine codes `MUL` 1 through `DIGIT` 9 and `OPS`, a live row carrying exactly one; `DIGIT_BITS = 8`, the MSM's window, and `DIGITS = 32`, a scalar's below `2^256`; `ACCESSES = 3`, the cells a row touches besides its frame; and the slots `DELTA_A` 0, `DELTA_B` 1, `DELTA_D` 2, distinct so any two operands may name one cell (`docs/spec/recursion.md` §3). |
| `p2_field` | **S-RECURSION.** `P2_FIELD`'s read-only frame `[n, s, x, y, d]` — `N_WORD` through `D_WORD`, `FRAME_WORDS = 5`, `FRAME_BYTES = 20` — and `STATE_CELLS = 3`; `ACCESSES = 8`, the state's three lanes, `x`, `y` and the next state's three; and the slots `DELTA_STATE` 0, `DELTA_X` 1, `DELTA_Y` 2, `DELTA_NEXT` 3. The next state goes wherever `D_WORD` names, so no handle to an old state is overwritten (§4). |
| `field_io` | **S-RECURSION.** `FIELD_IO`'s read-only frame `[op, cell, ptr]` — `OP_WORD`, `CELL_WORD`, `PTR_WORD`, `FRAME_WORDS = 3`, `FRAME_BYTES = 12` — and `DATA_WORDS = 8`, the RAM words at `ptr, ptr + 4, …`; `IMPORT` 1, `EXPORT` 2 and `OPS`; `ACCESSES = 9`; and the slots `CELL_DELTA` 0 and `DATA_DELTA` 1, which is not a frame word's 0, so a frame and its data may overlap (§5). |
| `fq_op` | **S-RECURSION.** `FQ_OP`'s read-only frame `[op, d, a, b]`, `FRAME_WORDS = 4`, `FRAME_BYTES = 16`, and the element layout: `ELEMENT_CELLS = 4` cells of 64-bit limbs, lazily reduced — congruent to the element mod `Q`, not necessarily below it. The op word packs the code below `2^CODE_BITS` (`CODE_BITS = 3`; `MUL` 1 through `FROM128` 5 and `OPS`), the indirection flags `IND_D` 8, `IND_A` 16 and `IND_B` 32, and the digit cell above `DIGIT_SHIFT = 6`; an indirect operand's element is its word plus `BUCKET_CELLS·digit`, a bucket being 8 cells, an affine point's `x` then `y`. `Q` is BN254's base field modulus in four 64-bit limbs, held by a `const` block to `mod_mul`'s BN254 modulus limb for limb; `SUB_MULTIPLE = 6`, because `SUB`'s `z = 6q − b` is nonnegative for every `b < 2^256`; `ACCESSES = 13`; and the slots `DELTA_G` 0, `DELTA_A` 1, `DELTA_B` 2, `DELTA_D` 3 (§6). |
| `extra_mask` | S11. Every family's `family_extra_mask` bit positions, one-hot per mnemonic, append-only, and the system codes `ecall`/`ebreak`/`fence` carry in `imm`. |
| `guest_memory` | The frozen guest memory map: `RAM_ORIGIN` and `RAM_LENGTH`; since S12, `STACK_RESERVE`, the 8 MiB at the top of RAM guest-sdk's allocator leaves to the stack; and, since S-IO, the three regions of `docs/spec/public-values.md` §2. `PUBLIC_INPUT_ORIGIN = 0x0000_8000` and `PUBLIC_OUTPUT_ORIGIN = 0x0000_C000` are the two public windows — the second was `0x0000_8400` until S-STREAM raised the height that places it — `PUBLIC_WINDOW_BYTES = 4 · family::PUBLIC_WINDOW_HEIGHT` (16,384, where it was 1,024) each, of which `PUBLIC_PAYLOAD_BYTES = PUBLIC_WINDOW_BYTES − 4` (16,380, where it was 1,020) is payload — word 0 is the payload's **byte length**, which is what makes a proof bind a byte string rather than its zero-padded word vector. Both sit in the hole below `RAM_ORIGIN` that `V[ram_live]` already masks, so they cost no existing row; since S-STREAM they take the **whole** of that hole above `0x8000`, ending flush against `RAM_ORIGIN`, and `[0, 0x8000)` is what stays a hole — which is both why a null dereference still cannot balance and why `2^12` is the last height this geometry admits. `ADVICE_ORIGIN = 0x8000_0000` opens the prover's advice region, `ADVICE_WORDS = 2^29` words to the top of the address space; it begins exactly where `RAM_ORIGIN + RAM_LENGTH` ends, so `[RAM_ORIGIN, ADVICE_ORIGIN)` keeps the meaning it had. All three regions are `address_space::RAM`. |
| `ecall` | The guest ecall ABI, and it is now short: `EXIT` (93), the two range boundaries, the precompile numbers — ten live since S-RECURSION's `PRECOMPILE_FR_OP` `0x0509`, `PRECOMPILE_P2_FIELD` `0x050A`, `PRECOMPILE_FIELD_IO` `0x050B` and `PRECOMPILE_FQ_OP` `0x050C`, beside three `RETIRED_*` numbers burned — and `ENOSYS` (38). **There are no file descriptors and no I/O call.** `READ` (63), `WRITE` (64), `FD_STDIN`, `FD_STDOUT`, `FD_STDERR`, `FD_HINT` and `EBADF` went with the POSIX layer: an Apogee guest is an Apogee-SDK program, its input is a memory window and its journal is another (`docs/spec/public-values.md`), and neither `read` nor `write` was ever a provable ecall. `ENOSYS` survives because it was never part of that layer — it is the delegation ABI's "this executor has no circuit" answer, which every shim checks for (`docs/spec/delegation.md` §2). `ZKVM_IO_FIRST..=ZKVM_IO_LAST` is now **reserved and empty**. |

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
(`docs/spec/shard-proof.md` §3, `docs/spec/jump-branch-slt.md` §6). S-RECURSION added four,
none of which a base-format proof's transcript carries: `STACK_CHALLENGE` (42, **challenge**),
a recursion-format shard's `σ` stack challenges, drawn after the GKR pass and before its one
batch opening — `σ = 0` in the base format, so none is drawn there
(`docs/spec/recursion.md` §1.3); and three in a recursion node's own transcript (§8.1, §8.3),
`FOLD_STATE` (43, scalars), one verified shard's final transcript state, its three lanes,
`FOLD_WEIGHT` (44, **challenge**), the fold weights — `w` then `w′` after each shard's state,
one after each child's journal — and `FOLD_CHILD` (45, scalars), one child's whole journal,
absorbed before the weight that folds its accumulator. Repeated draws under one tag are told
apart by position, as `LOOKUP_CHALLENGE`'s `g` and `β` are. `family` and
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

The `ecall` module holds the guest's call numbers — `EXIT` and, since S-RECURSION, ten live
precompile numbers — the three retired ones, the two non-Linux range boundaries and `ENOSYS`. It obeys the same rule as the tags, for a sharper reason: **once a program's
identity is published its ABI is frozen**, and redefining a number does not fail loudly —
it quietly makes an old program compute something else. `EXIT` keeps 93 because that is
what it has always had here and append-only keeps it there; nothing downstream reads any
meaning into the value. `ZKVM_IO_FIRST..=ZKVM_IO_LAST` is `0x0400..=0x04FF` and
`PRECOMPILE_FIRST..=PRECOMPILE_LAST` is `0x0500..=0x05FF`; both sit above the whole Linux
number space and are disjoint from each other, because a call in the first range would be
nondeterministic prover advice and a precompile is a deterministic function of memory, and
a reviewer has to tell them apart at a glance. The first range is **reserved and empty**,
and stays that way: advice does not need a syscall, it is a region the prover fills and the
guest authenticates (`docs/spec/public-values.md` §6). `docs/spec/ecall-abi.md` is
normative, and `tests/ecall_abi.rs` holds it to this module in both directions — it used to
parse a third table, the file descriptors, and there is none to parse.

**63 and 64 are retired and burned, and that is not a breach of append-only.** The rule
forbids *reassigning* a number, because an old program would then compute something else
under its published identity; it does not require carrying a call no guest may issue.
`read` and `write` were never provable ecalls — a transfer row that is permitted but not
constrained against its buffer and length can write any value to any RAM word — so every
guest that took that path was one no proof covered, and the two numbers now name nothing.
Nothing may ever take them. **An execution's public values are not a syscall's business**:
they are memory windows, and `guest_memory` is where they live.
