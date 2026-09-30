# S26d — `KECCAK_F` re-shaped: one Keccak round a row

**What this stage did.** Replaced the `KECCAK_F` delegation circuit. S21's row was a
whole keccak-f[1600] permutation — 1,600 boolean state columns, 24 seven-layer round
blocks, 354,762 inner columns over 177 layers. S26d's row is **one round**, a whole
permutation is **24 consecutive invocations** glued by the frame being ordinary RAM, and
the committed unit is a **byte**: there is no bit anywhere in the circuit but the 24 round
selectors and `live`.

The number the stage was for:

| | S21 | S26d | |
| --- | --- | --- | --- |
| height | `2^8` | `2^16` | |
| committed columns | 3,764 | **1,764** | |
| inner columns | 354,762 | **5,478** | 64.8× |
| layers | 177 | **27** | |
| artifact wire bytes | 100,254,040 | **1,899,700** | 52.8× |
| permutations a shard | 256 | **2,730** | 10.7× |
| **proof bytes a shard** | 11,880,012 | **373,276** | 31.8× |
| **proof bytes a permutation** | 46,406 | **137** | **339×** |
| forward pass a shard | 2.9 GB | ~15 GB | *up*, the height being 256× |

339× fewer proof bytes for the same work is the deliverable. `docs/spec/delegation.md`
§9.1 had measured the cost — five `2^8` keccak shards were **97%** of S25's pinned
mini-block's 61.3 MB proof — and could not act on it, because at 354,762 inner columns a
row `2^16` is 744 GB of forward pass. S26d re-shaped the row instead of the height, and the
height followed.

---

## 1. The design, and the one thing that makes it work

**The state is bytes and every Boolean operation is one lookup.** The new
`lookup_channel::XOR8` is a table channel whose table is a **closed form**: the 65,536
triples `(a, b, a ^ b)` read off the row index, three `VirtualKind`s wide. From it,

```text
a & b = (a + b − (a ^ b)) / 2        (¬a) & b = (b − a + (a ^ b)) / 2
```

are *linear forms* over the result and cost no obligation of their own, and a byte's
top-`s`-bit mask is one XOR against a **literal** — which makes a rotation a
literal-weighted combination of a byte and its masked copy. So `θ → ρ → π → χ → ι` is 1,020
obligations and 385 degree-≤2 gates, and **nothing produces an inner column**: the circuit
is flat, like `MOD_MUL`'s and `EC_ADD`'s, and the only inner columns in the artifact are the
two memory product trees, the two channels' fraction trees and the halving phase.

**The tuple is three wide and that is load-bearing.** Membership of `(x, y, z)` bounds each
of the three to `[0, 256)` *individually*, which is the whole of the bound argument: input
bytes are bounded because the `theta_a` obligation reads each at position 1, every stage's
output because the obligation that writes it reads it at position 2, and the derived forms
because they are integer combinations of bounded values whose maximum is 255. A packed key
`x + 256·y` would be one column cheaper a lookup and would bound neither operand alone.

**The cross-row glue is the frame, and nothing was added for it.** Round `r` writes the 50
state words at `4·cycle_r`; round `r + 1` reads the same 50 addresses and its `read_ts`
names that write. Both tuples are in the one global multiset. What makes 24 such rows a
keccak-f rather than 24 unrelated rounds is the **guest's own proven loop**, and
`round_rule` is what ties each row's arithmetic to the number that loop stored. This is
`EC_ADD`'s decomposition (`docs/spec/delegation.md` §16.2) applied a second time, and it
needed no column, no tag and no bus.

### The frame

**51 words, 204 bytes.** Word 0 is the round in `0..24`, read and **written back
unchanged** — the guest's loop advances it. Words 1.. are the state, SHA-3 byte order
unchanged from S21.

### 1,020 is three short of a cliff

A LogUp fraction tree has `(lookups + 1).next_power_of_two()` leaves, so 1,020 obligations
give 1,024 and **1,024 would give 2,048** — 4,096 more inner columns, ~8.6 GB more a shard,
and `KECCAK_F` rather than `EC_ADD` as the peak-setting family of a block. That is why `ι`
is four obligations and not eight: Keccak's round constants set only the bits `2^j − 1`, so
their little-endian bytes are zero everywhere but at positions 0, 1, 3 and 7.
`constants::keccak::IOTA_BYTES_ARE_THE_ONLY_ONES` asserts it at compile time and
`keccak::check_shape` asserts both the count and the cliff.

---

## 2. What was frozen, and what changed

### Frozen by this stage

```rust
// crates/constants/src/keccak — the frame's shape
pub const ROUND_WORD: usize = 0;      pub const STATE_WORD: usize = 1;
pub const STATE_WORDS: usize = 50;    pub const FRAME_WORDS: usize = 51;
pub const FRAME_BYTES: usize = 204;
pub const IOTA_BYTES: [usize; 4] = [0, 1, 3, 7];
pub const IOTA_BYTES_ARE_THE_ONLY_ONES: ();

// crates/constants/src/ecall
pub const PRECOMPILE_KECCAK_F: u32 = 0x0507;
pub const RETIRED_KECCAK_F_WHOLE_PERMUTATION: u32 = 0x0501;

// crates/constants/src/lookup_channel
pub const XOR8: u32 = 4;   pub const COUNT: u32 = 5;

// crates/constraints
pub enum VirtualKind { .., Xor8A, Xor8B, Xor8Out }        // wire tags 4, 5, 6
pub fn lookup::table_vars(channel: u32) -> u32;
pub fn lookup::xor8_table() -> Vec<PolyAddress>;

// crates/constraints/src/keccak — the column accessors
pub fn gap_chunk(j, c);  base_low();  base_low_hi();  base_room();  base_room_hi();
pub fn round_sel(r);  rc(t);  state_in(i, b);  parity(x, b, s);  theta_c(x, b);
pub fn c_mask(x, b);  theta_d(x, b);  theta_a(i, b);  rho_mask(i, b);  rho_out(i, b);
pub fn chi_and(i, b);  chi_out(i, b);  iota_out(t);
pub fn range16_multiplicity();  xor8_multiplicity();
pub const MEMORY_COLUMNS: usize = 208;  pub const WITNESS_COLUMNS: usize = 1556;
pub fn artifact(trace_vars: u32) -> CircuitArtifact;   // 16 <= n
pub fn channels() -> Vec<ChannelSpec>;                 // RANGE16, then XOR8
pub fn check_shape(a: &CircuitArtifact);

// crates/emulator
pub fn keccak_round(lanes: &mut [u64; 25], round: usize);
pub fn keccak_f(lanes: &mut [u64; 25]);                // 24 of them
pub fn lanes_of(words: &[u32; 50]) -> [u64; 25];       // the STATE words
pub fn words_of(lanes: &[u64; 25]) -> [u32; 50];
```

### Deleted

- `keccak::in_bit`, `gap_bit`, `base_low_bit`, `base_room_bit` — there is no bit.
- `keccak.rs`'s private `Assembly`, `round_sub`, `SUB`, `ROUND_LAYERS`, `tree_width`,
  `carry_width`, `keccak_width`, `tree`, `carry`, `kec`, `round_input` — the circuit is
  flat and goes through `memory::assemble` like every other family. **`KECCAK_F` was the
  one registered circuit `build::assemble` did not build; the exception is gone.**
- `prover::fill::delegation_frame`'s `witness_base` parameter. It existed for S21's keccak
  alone, whose 1,600 state bits came before the frame's own columns; every family now puts
  the frame's witness columns at `W[0]`, and `crates/prover/tests/fills.rs::
  every_frame_witness_block_starts_at_zero` is the invariant that replaced it.

### Amended, and why each is authorized

1. **`prompts/00-master.md`'s *Lookups (shard-local)* frozen invariant** — the owner's
   decision, asked before any code was written. The bullet named four channels and said a
   table channel's table is committed setup. `XOR8` is a fifth and is the first **table**
   channel whose table is a **closed form**. The amendment is in the bullet itself, in the
   italicised *Amended at S26d* style S-IO and S-NATIVE-IO used.
2. **`docs/spec/lookup.md`** — §14 is the new section; §1's, §3's and §3's
   channel-free-family paragraph are amended where they said "committed" or "four".
3. **`docs/spec/delegation.md`** — §6 rewritten (§6.0 the accounting, §6.1 the frame and
   columns, §6.2 the gates, §6.3 the round as obligations, §6.4 the glue, §6.5 the memory
   subtree and the cliff); §3's registry row and its retired-number paragraph; §9's height
   argument moved to the past tense; §9.1 and §9.2's tables; **§10.4** the amendment record.
4. **`docs/spec/ecall-abi.md`** — `0x0507` in §3's table, `0x0501` in §4's retired table.
5. **`docs/spec/constraint-manifest.md`** — §12 rewritten to the §22 checklist, and §0.4,
   §1.1, §1.2, §1.3, §13.1, observations 19 and 21, §22 and Appendix A updated.
6. **`docs/spec/debug-info.md`** — §6.6, the round histogram.

### Retired and burned

**Ecall `0x0501`.** The frame changed shape *and* semantics, and append-only forbids giving
a number a second meaning: an old binary issuing `0x0501` under the new executor would have
its first state word read as a round selector and get one round of a permuted state back,
with nothing failing loudly. This is the S26b precedent (`0x0503`) exactly. The family id
(9), the address-space tag (4) and the state's byte order did **not** move.

---

## 3. What moved outside the family

- **`crates/constraints/src/lib.rs`** — three `VirtualKind`s, their `Display`, and
  `minimum_trace_vars` now reading `lookup::table_vars` rather than `BITS` with an
  `IS_RANGE` filter. That last is not cosmetic: `XOR8`'s table is 65,536 rows without being
  a range channel, so the old filter would have given a family carrying it *alone* a floor
  of 0 and an incomplete table at every height below `2^16` — true of `KECCAK_F` only by the
  accident of its also carrying `RANGE16`.
- **`crates/constraints/src/lookup.rs`** — `Gating::Range` renamed **`Gating::NoOffset`**,
  because the discipline is "no offset, the all-zero tuple is a real table entry" and
  `XOR8` takes it without being a range channel. A variant called `Range` handling a
  non-range channel is the kind of name the master's frozen-invariant preamble forbids.
- **`crates/constraints/src/wire.rs`**, **`crates/gkr-verify/src/lib.rs`**,
  **`crates/verifier-core/src/types.rs`** — the three new kinds' wire tags and closed forms.
  `Xor8Out` is the first closed form that is not a weighted sum of the row's bits.
- **`constraints::add_sub`** — nothing in the source: `deleg_9_number`'s literal *is* the
  ecall number, read from `constants::ecall`, so only **`add_sub.bin` regenerated**. Same as
  S26b.
- **`tools/kat-gen/src/lookup.rs`** — S15's toy named one multiplicity per channel that
  *exists*; adding a fifth gave it a committed column for a channel it does not carry. It
  now names one per channel it **declares**, and `lookup_toy.bin` is byte-identical to its
  committed value again.
- **`tools/kat-gen/src/revm.rs`** — the keccak frame harvest keeps the **round-0**
  invocations and drops their round word, so `revm_block_keccak.bin` stays 200 bytes a
  permutation and is byte-identical. It asserts the invocation count is a whole number of
  permutations (144 = 6 × 24).

---

## 4. Guest-side

`guest_sdk::keccak256`'s signature is unchanged and frozen. Behind it:

- `Frame` is now `#[repr(C, align(4))] struct { round: u32, state: [u8; 200] }`, so `round`
  is frame word 0 by layout and `size_of::<Frame>() == FRAME_BYTES` is a `const` assertion.
- `permute` writes the round, calls, and repeats 24 times. The frame is transformed **in
  place**, so nothing is copied between calls and the chain a proof reads is the frame's own
  RAM history.
- **Only the first call may answer `-ENOSYS`**, which means an executor with no keccak
  circuit; the software fallback then runs from the untouched state. One answering it
  halfway through a permutation is a broken executor and `exit(EXIT_PRECOMPILE_ERROR)` is
  the answer, because skipping a round silently would be worse.

**What it costs the guest, measured.** At `--release`, `guest_sdk::keccak256` over
`guests/keccak-test`'s corpus is **1,681.5 cycles a call** — six calls, ten permutations, so
~1,009 cycles a permutation for the whole sponge — and the loop's share is roughly 145
cycles a permutation more than S21's single call. At `opt-level = 0` it is four times worse:
the committed debug ELF is **193,156 cycles against S21's 154,708**, because the shim is a
real call with a stack frame per round rather than five inlined instructions. The workload
that matters, `guests/revm-block`, is proven at `--release`.

**Every guest that hashes has a new identity.** The ecall number is in the image and the
height is in `VM_CONFIG`, which identity absorbs.

---

## 5. The executor

`emulator::keccak_round(lanes, round)` is what one invocation does and is the function the
circuit is checked against; `keccak_f` is 24 of them and remains the function every oracle
compares. `keccak_frame` **can refuse a frame** — a round word at or above 24 has no one-hot
selector, so answering it would produce a trace no honest prover could prove — which makes
`SHA256_COMP` the only one of the six with no refusal path.

`lanes_of` and `words_of` now take and return the 50 **state** words rather than the frame's,
which is what `STATE_WORDS` is for.

---

## 6. Verification

### Ran, green

```
cargo fmt --all -- --check                                          (+ the three other manifests)
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p prover --all-targets --features metrics -- -D warnings
cargo clippy -p prover --all-targets --features debug-info -- -D warnings
cargo clippy -p prover --all-targets --features metrics,debug-info -- -D warnings
(cd crates/guest-sdk && cargo clippy --target riscv32imac-unknown-none-elf -- -D warnings)
(cd guests && cargo clippy --bins -- -D warnings)
cargo run -p kat-gen                    # every default group, regenerated and diffed
cargo run -p kat-gen -- guests          # the two keccak ELFs; see below
```

and every suite this stage touches, scoped:

```
cargo test -p constraints --lib keccak          cargo test -p constraints --test wire
cargo test -p checker     --test keccak         cargo test -p checker     --test add_sub
cargo test -p emulator    --test keccak         cargo test -p gkr         --test lookup
cargo test -p verifier-core --test wire         cargo test -p program     --test tables
cargo test -p constants                         cargo test -p loader
```

**`cargo test --workspace` was NOT run locally** — the owner's instruction, and master
test-discipline rule 3's standing allowance: "it is legitimate to let CI spend it: push the
branch and read the answer there rather than holding a finished commit hostage to 45 minutes
of local wall clock." What was run locally is the scoped set above, which is the part that
rule keeps for the author. The first local workspace attempt found one thing — `add_sub.bin`'s
pinned digest, expected and fixed — and the three other pinned values this change moves were
found by predicting them rather than by a second run (§7 note 2).

The two runs worth naming:

- **`cargo test -p constraints --lib keccak`** — four unit tests, including
  `the_rotation_weights_are_rotate_left`, which evaluates `rotl_byte`'s literal weights over
  `Fr` exactly as a gate would, on every lane's own offset over four pseudo-random states
  each, against `u64::rotate_left`. That is the one place the circuit's arithmetic is checked
  at the level of the weights themselves, and it is where a wrong `2^{s−9}` or a wrong byte
  index would show.
- **`cargo test -p checker --test keccak`** — 21 tests, all green. The suite builds **one
  whole permutation** (24 rows, each reading what the row before it wrote, at one frame base)
  plus the all-zero and all-ones corners plus six padding rows, and reads the circuit twice:
  the gates through `checker::violated_relations`, and the 1,020 `XOR8` obligations through
  its own statement of what the table *is*. That second reading is the only account of the
  round's semantics in the fast gate — nine tenths of the circuit is in those obligations and
  no gate reads the columns they pin.

### Deferred, not run

`prompts/00-master.md` rule 7 and `CLAUDE.md`'s "deferred suites run once, at the end of a
progression". **None of the fourteen `# DEFERRED` suites was run.** The three this stage
would most change:

| suite | what it would say | last measured |
| --- | --- | --- |
| `prover --test keccak` | S21's acceptances 4 and 8 at the new height, and the shard's 373,276 proof bytes | 33.7 GB / 131 s at S21, 254 s at S-BATCH — **S21's shape** |
| `prover --test revm` | the revm block with a `2^16` keccak shard | 38.4 GB / 536 s at S24 |
| `host --test prove` | the mini-block gate, where the 59.4 MB → 0.37 MB fall is visible end to end | 136.28 GiB at S-BATCH |

**The peaks above are upper bounds for the wrong shape.** The keccak shard's own forward
pass went *up*, from 5,478 × 256 to 5,478 × 65,536 — about 15 GB — because the height is 256
times larger. It is below `EC_ADD`'s computed 20.5 GB, so `EC_ADD` remains the peak-setting
delegation family, but no pre-S26d keccak figure is usable for sizing and the table above
says so rather than implying otherwise.

What stands in for the deferred suites, per the same rule ("a change whose only coverage
would be a deferred suite owes a **fast** test pinning the same property"), all of it in
ordinary CI:

| what | where |
| --- | --- |
| the circuit, row-locally at its real `2^16`: 24 rows of one permutation, two corners, six padding rows, the gates and all 1,020 obligations, and fifteen negative controls | `crates/checker/tests/keccak.rs` (22 tests) |
| **the prover's own fill**, over a real trace: every live row against the gates, the `RANGE16` obligations and the `XOR8` ones, with the multiplicities counted by `trace::build_multiplicities` | `crates/checker/tests/keccak.rs::the_fill_satisfies_every_gate_and_every_obligation` |
| the rotation's literal weights against `u64::rotate_left`, 800 cases | `crates/constraints/src/keccak.rs` (4 unit tests) |
| 24 rounds are `tiny_keccak::keccakf`, and a round is exactly its round constant | `crates/emulator/tests/keccak.rs` (2 new tests) |
| the three new closed forms **are** the multilinear extensions of their tables, at 8, 15, 16 and 17 variables, and the table at 16 is the 65,536 triples each once | `crates/gkr/tests/lookup.rs::the_xor8_closed_forms_are_their_multilinear_extensions` |
| all seven `VirtualKind` wire tags, and the first index no kind has | `crates/constraints/tests/wire.rs` |
| a verifying key whose circuits carry the `XOR8` channel round-trips — the only fast reading of `verifier-core`'s own copy of the tag table | `crates/verifier-core/tests/wire.rs::a_key_carrying_the_xor8_channel_round_trips` |
| the fill writes every declared column exactly once | `crates/prover/tests/fills.rs::the_keccak_fill_covers_its_circuit_exactly` |

The statement-level numbers in `crates/prover/tests/keccak.rs` — 240 invocations, one shard,
373,276 proof bytes — are derived from the artifact, and the proof-byte literal was computed
from it rather than guessed.

### The adversarial review, and what it found

The finished change was put through a six-dimension adversarial review (bounds, the round's
mathematics, circuit-versus-fill agreement, the cross-row glue, the new channel, and the
guest/executor/docs), each finding then handed to an independent verifier told to refute it.

**No soundness, completeness or correctness defect in the circuit survived verification.**
What it did find, and what was fixed:

- **Two things that would have turned the default gate red**, neither yet run when the review
  started. `crates/prover/tests/fills.rs` passed the *unsubtracted* `WITNESS_COLUMNS` to
  `covers`, which excludes the channel multiplicities — the constant was right while this
  family carried no channel and is not now. And a test of mine,
  `a_round_depends_on_its_index`, asserted the 24 rounds of one state are **pairwise
  distinct**, which is false of Keccak: the LFSR repeats, `ROUND_CONSTANTS[5] ==
  ROUND_CONSTANTS[22]` and `[6] == [20]`, so 24 rounds take **22** values. It is now
  `a_round_is_its_round_constant`, which states the true and sharper thing — two rounds agree
  **iff** their constants do, exhaustively over all 576 pairs, and the difference is lane
  `(0,0)` alone.
- **Two pinned values I had not noticed**: `crates/program/tests/tables.rs` asserted
  `KECCAK_F`'s height is `2^8`, and `crates/loader/tests/common/mod.rs` pinned the two
  regenerated guest ELFs' digests. Both fixed before any suite ran.
- **Eight citations of `docs/spec/lookup.md` §10 that meant §14.** §10 is the decoder channel;
  §14 is the section this stage wrote. Every pre-existing §10 citation is correct and was left
  alone.
- **`docs/spec/delegation.md` §6.5 gave the output map in the wrong order** —
  `xor8` before `range16`, when `channels()` is ascending by channel id and the artifact's
  outputs 2–5 are `range16_num_root`, `range16_den_root`, `xor8_num_root`, `xor8_den_root`.
- **`docs/spec/constraint-manifest.md` §1.2's degree split was wrong** (`385 (257/128)`; the
  source gives 307 degree-1 and 78 degree-2, and §12.5 of the same page said so), and its
  `lookups` header had four slots for a five-value row.
- **§0.5's gate-shape census still described S21's circuit** in five cells, including the flat
  falsehood "keccak … none: a circuit with no lookup channel has no fraction tree". I had
  updated that section's preamble and not its rows. All five are recomputed, and the five
  shape counts sum to the artifact's 5,863 relations exactly.
- **Three coverage gaps**, each now closed by a test in the table above: the three new closed
  forms, the three new wire tags in both codecs, and the fill's *values*.
- `crates/program/CLAUDE.md`'s registry row still said ecall `0x501`, one permutation a row,
  `2^8`.

One thing the review checked and found sound, worth recording because it is the piece with no
precedent: `trace::build_multiplicities` counts a **virtual** table channel generically
(`Source::Virtual(kind)` → `virtual_at_row`), and `gate()`'s default arm is the no-offset
discipline `XOR8` takes — so the new channel needed no change there. Its cost is one map
operation per (row, obligation), 80.6M a shard, which is in line with `EC_ADD`'s measured
72.8M and not a new order of magnitude.

### Fixture regeneration

- `crates/constraints/tests/vectors/keccak.txt` — the new shape and digest.
- `crates/constraints/tests/vectors/add_sub.bin` — the ecall literal.
- `crates/loader/tests/vectors/{keccak-test,keccak-unused}.elf` — the shim changed, so the
  two guests that link it had to be rebuilt. **Only those two.** `cargo run -p kat-gen --
  guests` rebuilds all of them and a guest ELF is not byte-reproducible across machines, so
  every other ELF was reverted: the committed diff is exactly the two guests this stage
  touched. Their derived `loader` fixtures are unaffected — neither guest has an
  `objdump.txt` or `nm.txt`.
- `lookup_toy.bin` and `revm_block_keccak.bin` are **byte-identical** after the two
  generator fixes above, which is the outcome they should have: S15's toy and S24's harvested
  permutations did not change.

---

## 7. Deviations and judgement calls

1. **The round constant is selected by 24 one-hot columns, not by a lookup.**
   `prompts/S26d`'s wording offered either ("or otherwise select the round constant without
   a 24-way bit decomposition"). One-hot is `mod_mul::m_limb{k}_rule`'s and
   `ec_add::selector_rule`'s pattern exactly — a degree-1 gate pinning literals to a
   selector — it gives `round ∈ [0, 24)` structurally, and it is 24 columns of 1,556. A
   lookup would have needed either a fifth virtual table with a sparse 192-entry closed form
   or a committed setup table to bind, both more machinery than the thing they replace.
   **A one-hot indicator is not a bit decomposition of the round**; a 5-bit split would be,
   and there is none.
2. **`rho_out` (`B`) is committed, 200 columns, and could not be derived.** `χ` takes two
   rotated operands and a lookup tuple allows a linear form at position 0 only; every lane is
   `B0` for itself and `B2` for another, so every lane's bytes are needed as a bare column
   somewhere. The alternative — a second, two-wide packed-key channel — saves 200 columns and
   costs a channel plus the bound argument the three-wide tuple gives for free.
3. **`Gating::Range` was renamed `Gating::NoOffset`.** A rename inside one private enum, and
   the alternative was a variant named for a channel kind handling a channel of another kind.
4. **Three pre-existing documentation defects were repaired in passing**, all in files this
   stage edits: `crates/checker/CLAUDE.md`'s `tests/mod_mul.rs` row had a sentence split
   across two table rows; `crates/trace/CLAUDE.md` listed seven `AddressSpace` variants where
   the enum has nine; and `docs/spec/shard-proof.md`'s list of provable delegation calls
   stopped at S26's.
5. **`tools/kat-gen/src/lookup.rs` gained a `TOY_CHANNELS` constant.** S15's toy named one
   multiplicity per channel that *exists*, which was the same four until this stage added a
   fifth; it now names one per channel it *declares*. The alternative was letting
   `lookup_toy.bin` grow a committed column for a channel the toy does not carry.

---

## 8. For the next stage

- **`EC_ADD` is still the peak-setting delegation family**, at a computed 20.5 GB a shard
  against `KECCAK_F`'s ~15 GB. Its remaining lever is unchanged: five groups of two
  reductions instead of three of three (`docs/spec/delegation.md` §16.4).
- **`SHA256_COMP` is the family this stage's technique most obviously applies to.** It is
  16,688 inner columns a row at `2^8`, every bound a bit, and SHA-256's round is XOR,
  rotation and 32-bit addition — the first two of which `XOR8` now makes cheap. Nothing here
  assumed keccak.
- **The `XOR8` channel's 1,020 obligations are three short of doubling its fraction tree.**
  Anything added to this circuit pays 4,096 inner columns for the fourth.
- **`docs/spec/revm-block.md` §2's journal ceiling is untouched by this stage**, so
  `guests/revm-block` still cannot prove a full block and full-block work still belongs to
  `revm-block-stateless` (`docs/handoff/S-BATCH-miniblock-gate.md`).
