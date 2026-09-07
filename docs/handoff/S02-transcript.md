# S02 — Poseidon2 Permutation + Duplex Transcript

Branch `s02-transcript`. Status: complete, all 11 acceptance items met.

The normative document is **`docs/spec/transcript.md`**, written this stage; the section
numbers the stage prompt cites (§5 observe, §6 sample, §9 length-delimited scalars,
§10 byte encoding) are that file's. This note is the frozen API, the artifacts and the
deviations.

## Frozen public API, as built

```rust
// crates/transcript/src/lib.rs   (#![no_std], extern crate alloc)
pub fn poseidon2_permute(state: &mut [Fr; 3]);

pub type Tag = u64;                               // values only in constants::transcript_tags

pub struct Transcript { /* private: state + both buffers + event log */ }
impl Transcript {
    pub fn new() -> Transcript;                   // zero sponge, empty buffers
    pub fn observe(&mut self, x: Fr);             // raw duplex, spec §5
    pub fn sample(&mut self) -> Fr;               // raw duplex, spec §6
    pub fn append_scalar(&mut self, tag: Tag, x: Fr);
    pub fn append_scalars(&mut self, tag: Tag, xs: &[Fr]);   // spec §9
    pub fn append_bytes(&mut self, tag: Tag, bytes: &[u8]);  // spec §10
    pub fn challenge_scalar(&mut self, tag: Tag) -> Fr;      // spec §11
    pub fn snapshot(&self) -> TranscriptSnapshot;
    pub fn restore(s: &TranscriptSnapshot) -> Transcript;
    pub fn event_log(&self) -> &[TranscriptEvent];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptEvent {
    Absorb { tag: Tag, n_scalars: usize },
    Challenge { tag: Tag },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]   // + hand-written Serialize/Deserialize
pub struct TranscriptSnapshot { /* private fields */ }
```

```rust
// crates/constants/src/lib.rs   (additions; still zero logic, #![no_std])
// Upstream's hex literals, character for character.
pub const POSEIDON2_RC3_INITIAL:  [[&str; 3]; 4];   // RC3 rows 0..4,  all lanes
pub const POSEIDON2_RC3_INTERNAL: [&str; 56];       // RC3 rows 4..60, lane 0
pub const POSEIDON2_RC3_TERMINAL: [[&str; 3]; 4];   // RC3 rows 60..64, all lanes

pub mod transcript_tags { /* the table below */ }
```

```rust
// crates/field/src/lib.rs   (one addition; the rest is byte-identical to S01)
impl Fr {
    /// `0x` + exactly 64 lowercase hex digits, big-endian. `None` for any other
    /// spelling, or for a value `>= p`. The source-literal form for frozen
    /// constant tables — deliberately not `to_bytes`' little-endian wire order.
    pub fn from_hex(s: &str) -> Option<Fr>;
}
```

## The tag table (complete dump)

`Tag = u64`, sequential from 1, never renumbered, never reused. `0` is not a tag, so an
uninitialised value can never be a valid message. Later stages **append**.

| Name | Value | Message kind |
| --- | --- | --- |
| `PROTOCOL_SUITE` | 1 | scalars |
| `PUBLIC_INPUTS` | 2 | bytes |
| `COMMITMENT` | 3 | scalars |
| `SUMCHECK_ROUND` | 4 | scalars |
| `SUMCHECK_CHALLENGE` | 5 | challenge |
| `EVALUATION_CLAIM` | 6 | scalars |
| `PCS_OPENING` | 7 | scalars |

**One tag, one message kind — load-bearing.** The typed layer frames a message as
`tag, length, payload` and nothing more. Under that framing, a tag used for two kinds
admits real collisions. Between scalars and bytes: `append_bytes(T, b"")` and
`append_scalars(T, &[])` both absorb `T, 0`, and a one-byte message collides with a
one-scalar message whose scalar is below 256. Between scalars and challenges: a challenge
absorbs one element where a message absorbs a length, so the two framings can line up
element for element — `duplex.rs::a_tag_used_in_two_kinds_is_caught` exhibits two
different message sequences that yield the *same challenge*, and it runs on every build.

The alternative — a message-kind discriminant in the header, at one extra absorbed element
per message — was put to the repository owner, who chose the smaller framing. So the rule
is a **rule**, not a convenience: a later stage that reuses a tag across kinds introduces a
soundness bug. `duplex.rs::every_tag_is_used_in_exactly_one_kind` holds the committed
fixture to it, with the negative control above proving the checker can fail. Every tag
records its kind above, in `constants::transcript_tags`, and in
`docs/spec/transcript.md` §8.

## What this freezes for every later stage

1. **The permutation.** Width 3, rate 2, capacity 1, `x^5`, 4 initial full rounds / 56
   partial rounds / 4 terminal full rounds, partial-round S-box on lane 0, external
   matrix `[[2,1,1],[1,2,1],[1,1,2]]`, internal matrix `[[2,1,1],[1,2,1],[1,1,3]]`, and
   the external linear layer applied once *before* the first round.
2. **The duplex.** Overwrite absorption; an absorb of `n > 0` elements zero-fills the
   rest of the rate and adds `n` to the capacity; a duplex step with nothing pending is a
   pure squeeze and does neither; `observe` discards buffered output; challenges leave
   the rate from the end (`state[1]`, then `state[0]`).
3. **The typed framing.** `tag, length, payload`, with the length being the scalar count
   for scalars and the **byte** count for bytes. `append_scalar(t, x)` is exactly
   `append_scalars(t, &[x])`. `challenge_scalar` absorbs the tag and then samples.
4. **The byte encoding.** 31-byte little-endian chunks, trailing chunk zero-padded. The
   byte length, not the chunk count, is what makes it injective.
5. **The canonicalisation invariant.** Buffer lanes at or past their length are zero in
   the live transcript, not merely in a snapshot, and no squeezed material outlives an
   absorb. A snapshot is therefore a deterministic function of the operation sequence:
   replay the same script, get the same bytes — what master rule 9's archivable phase
   boundaries need. Deliberately *not* claimed: that equal challenge futures imply equal
   snapshots. With input pending the rate lanes are already dead, so a hand-built snapshot
   can differ there and behave identically; the serde validation checks the shape rules of
   spec §12, not reachability.
6. **`TranscriptEvent` and `event_log`.** Always on, metadata only, never fed to the
   sponge, and not part of a snapshot. `n_scalars` counts payload elements only: the
   scalar count, or the 31-byte chunk count for bytes.
7. **The snapshot wire form.** A fixed 226 bytes — `state[3]`, `input[2]`,
   `input_len: u8`, `output[2]`, `output_len: u8` — every field element canonical
   little-endian. Deserialisation rejects anything `snapshot` could not have produced.

## Artifacts

| Path | What | SHA-256 |
| --- | --- | --- |
| `crates/transcript/tests/vectors/poseidon2_rc3.txt` | The full upstream 64×3 `RC3` table | `40d9c19a629f6c7262a06730a78be8031975027c5f85b37c75681a05080e3d19` |
| `crates/transcript/tests/vectors/poseidon2_perm.txt` | 128 permutation vectors (the `[0,1,2]` KAT, 7 structured, 120 random) | `905e08088b1b9e1bfe985e1447f2f373d66b3e97ce1750714d39940de65e1fee` |
| `crates/transcript/tests/vectors/transcript_cases.txt` | 23 replayable transcript scripts, cases A–E among them | `273bc20993c636169d8fb014a56c73ea0fbc276ea4000a40d448cd87dd162ed8` |
| `tools/transcript-ref/` | The reference oracle that produces all three | — |
| `docs/spec/transcript.md` | The normative specification | — |

Digests are pinned in `tests/poseidon2.rs` and `tests/duplex.rs`. Refresh is manual and
deliberate:

```
cargo run --manifest-path tools/transcript-ref/Cargo.toml
shasum -a 256 crates/transcript/tests/vectors/*.txt
```

then update the pinned constants. Verified reproducible: rerunning the generator produced
byte-identical files, and CI runs exactly that and diffs.

## RC3 provenance

The `RC3` table of <https://github.com/HorizenLabs/poseidon2>, file
`plain_implementations/src/poseidon2/poseidon2_instance_bn256.rs`, at commit
`055bde3f4782731ba5f5ce5888a440a94327eaf3` — the table Plonky3's own BN254 Poseidon2
test uses. The permutation oracle is Plonky3 at commit
`7230fc572870436e6651762f35c6c3f3f48960d2`. Both revisions are pinned in
`tools/transcript-ref/Cargo.toml` and its committed `Cargo.lock`, and both are recorded in
every generated vector file's header.

`constants` stores only the entries the permutation reads: rows 0..4 and 60..64 with all
three lanes, rows 4..60 with lane 0. The literals are copied from upstream character for
character, so the vendored table diffs against its source by eye. `tests/poseidon2.rs`
checks all three vendored tables against the committed dump of the **full** table,
including that lanes 1 and 2 of the partial rounds are zero upstream — so the split cannot
have dropped anything, and it is also where the two textual conventions meet: `constants`
holds upstream's big-endian `0x` literals, the dump holds little-endian canonical bytes,
and they must name the same field element.

## Verification performed

69 workspace tests, green in debug and release (33 from S01, unchanged; 36 new).
*(71 after the post-stage `tools/test-support` refactor: the two duplicated
`sha256_matches_nist_vectors` tests became four shared ones.)*

- **Acceptance 1** — `permutation_kat`: input `[0,1,2]`, byte-exact from the committed
  file. The value was independently confirmed against *both* upstream implementations
  before anything was written here: Plonky3 and `zkhash` agree on
  `out[0] = 0x0bb61d24…` (little-endian
  `33304a4f0560f747f8a48ea94d333481320f65829a92b1bcee55cada241db60b`).
- **Acceptance 2** — `permutation_matches_every_reference_vector`: 128 vectors, all
  generated by the Plonky3 reference, all matching; the test asserts that at least 100 of
  them are random-input, discounting the eight structured ones. Plus
  `committed_vectors_cover_distinct_inputs`, which recomputes every output with *our*
  permutation and asserts no two share a lane and none is a fixed point — a generator
  whose input stream had collapsed would otherwise satisfy "all vectors match" while
  covering almost nothing.
- **Acceptance 3** — `every_committed_case_replays`: all 23 committed cases, including
  A–E, replayed byte-exact. Every expected value comes from `tools/transcript-ref`, which
  does not depend on `crates/transcript`, `field` or `constants` in any way. The oracle is
  the spec-pseudocode driver the stage asks for, and it additionally runs Plonky3's own
  `DuplexChallenger<Bn254, Poseidon2Bn254<3>, 3, 2>` alongside its transcription and
  asserts they agree on every raw operation — so spec §§5–7 are checked against the
  reference *type*, not only against a second reading of its source.
- **Acceptance 4** — `case_d_differs_from_case_e`.
- **Acceptance 5** — `samples_leave_the_rate_from_the_end`: the two committed outputs are
  checked to be `state[1]` then `state[0]` of the permutation applied to the duplex state
  the spec predicts, `[7, 0, 1]`.
- **Acceptance 6** — `observing_after_sampling_invalidates_the_output`: case C ≠ case B,
  same absorbed set.
- **Acceptance 7** — `repeated_squeezing_permutes_again`: four squeezes after one absorb;
  samples 3 and 4 are shown to come from a *second* permutation of the same state, and
  all four values are distinct.
- **Acceptance 8** — `typed_layer_separates_tags_and_messages` (tag X ≠ tag Y; one run of
  two ≠ two runs of one; the empty run is its own message) and
  `typed_layer_is_the_documented_framing` (the typed layer is reproduced exactly by raw
  `observe` calls, which pins the framing rather than assuming it).
- **Acceptance 9** — committed byte cases at 0, 1, 30, 31, 32, 62 and 100 bytes (the
  stage's list plus both sides of every chunk boundary), replayed;
  `byte_cases_cover_the_chunk_boundaries` pins the boundary list;
  `byte_length_prefix_separates_split_absorbs` (`"ab"` ≠ `"a"`,`"b"`);
  `trailing_zero_bytes_are_distinguished` (`[1,2,3]` ≠ `[1,2,3,0]` — the zero-padded
  trailing chunk would collide without the length).
- **Acceptance 10** — `restore_resumes_the_committed_script`: the committed 20-operation
  mixed script, snapshotted after operation 10, restored into a fresh `Transcript`; the
  remaining 10 operations agree with the original transcript *and* with the committed
  reference values, and the two snapshots then compare equal. Plus `restore_mid_message`
  (a snapshot with the rate half full), `restore_with_buffered_output` (a snapshot with an
  unread squeezed lane), and `snapshot_round_trips_through_bytes`.
- **Acceptance 11** — `a_flipped_bit_in_case_c_fails`, flipping one bit of a committed
  case-C `sample` value.
- **Must-be-exact 1** — covered by acceptance 10 above.

Negative controls beyond acceptance 11, since master rule 8 wants every checker provably
able to fail: `corrupted_rc3_is_rejected` (flipped constant, a nonzero "unused" lane, a
truncated line, a dropped constant), `corrupted_permutation_vectors_are_rejected` (flipped
output, flipped *input*, short line, unknown operator), `malformed_case_files_are_rejected`
(unknown operation, unknown tag name, truncated line, a declared scalar count that does
not match, a declared byte count that does not match, an unterminated case, an operation
outside any case), `malformed_snapshots_are_rejected` (length above the rate for either
buffer, a stale lane in either buffer, a truncated encoding) and
`snapshot_rejects_non_canonical_field_elements`.

Also checked: `sha256_matches_nist_vectors` (the pin is only as good as the hash; it now
lives once, in `tools/test-support`),
`tag_table_is_well_formed` (distinct, nonzero, all resolvable),
`event_log_records_typed_operations_only`, `event_log_does_not_affect_challenges`,
`restore_starts_a_fresh_event_log`, and `observe_drops_unread_output`. That last one
exists because the obvious justification for the line it covers is wrong: dropping
buffered output cannot change a challenge — `sample`'s own guard already duplexes whenever
input is pending — so what it actually buys is that the sponge state is a function of the
operation sequence alone, and that is what the test pins. `every_committed_case_replays`
additionally asserts the *whole* list of committed case names, so a case quietly dropped
from the generator cannot shrink coverage silently.

`cargo clippy --workspace --all-targets -- -D warnings` is clean, with one `#[allow]` in
library code — `clippy::new_without_default` on `impl Transcript`, because a `Default`
impl would be a second name for `new` with no caller, which anti-goal 10 rules out.
`cargo build -p field -p constants -p transcript --target riscv32imac-unknown-none-elf`
succeeds: the recursion guest links this crate.

## Additive extensions (everything beyond the stage's literal list)

1. **`Fr::from_hex`**, plus four tests for it in `crates/field/tests/edge_cases.rs`.
   Unavoidable in some form: the round constants have to reach `Fr` somehow, and after S01
   there is no way to write down an `Fr` table at all. `crates/field/src/lib.rs` is
   otherwise byte-identical to `main` — the diff is 40 added lines and nothing else.
2. **`docs/spec/transcript.md`.** The stage cites "spec §5/§6/§9/§10" and no spec
   existed; master rule 12 wants one. It is the normative document from here on.
3. **Structured permutation vectors** beyond the random ones: all-zero, all-one,
   all-`p-1`, and single-lane inputs. Free, and the zero state is exactly the case an
   implementation gets wrong.
4. **Byte cases at 30 and 62 bytes**, so both sides of every 31-byte chunk boundary are
   covered rather than only the stage's five lengths.
5. **`crates/transcript/CLAUDE.md`** and the `docs/GLOSSARY.md` entries, per master
   rule 12.
6. **CI additions**: the oracle's `fmt` and `clippy` checks (it is outside the workspace,
   so `--workspace` does not reach it, and it did drift below the repository's bar once
   before this was added), `transcript` in the guest-target build, and the transcript
   vectors in the regenerate-and-diff step.

## Deviations and notes for the reviewer

- **`tools/transcript-ref` is not a workspace member.** `zkhash` takes `serde` with
  default features, so inside the workspace cargo's feature unification would hand
  `serde/std` to `crates/field` during `cargo test --workspace` — the shipped featureless
  serde would be compiled but never executed, which is exactly the trap S01 identified and
  avoided. The tool is its own workspace root (empty `[workspace]` table, `exclude` in the
  root manifest) with its own committed `Cargo.lock`. Verified empirically with
  `cargo tree -e features -i serde`. It costs one `--manifest-path` in CI and in the
  commands block; `cargo fmt --all` does not reach it, so CI checks it separately.
- **`crates/field` was left alone, on purpose, after first not being.** The stage needs
  frozen `Fr` tables and S01 provides no way to build one. The first version of this branch
  made `mont_mul` and its helpers `const fn` and added a compile-time constructor; two
  claims justifying that did not survive measurement (see `docs/decisions.md`), and master
  rule 11 forbids optimising without a real-workload benchmark. It was reverted at the
  repository owner's direction in favour of a runtime `Fr::from_hex`. The cost is
  **1.76x** on the permutation — 4667 ns with the decode already done, 8201 ns as shipped —
  and the benefit is that S01's most correctness-critical routine was not touched and the
  vendored table is upstream's own text. If a real workload ever says the decode matters,
  the fix is a decoded table and it needs a benchmark in the same commit.
- **The oracle carries a second sponge on purpose.** The stage says the driver should
  "call ONLY the Plonky3 reference permutation"; the driver does transcribe the duplex from
  the spec text, as asked, but it also runs Plonky3's `DuplexChallenger` beside it and
  asserts agreement on every raw operation. Swapping the transcription for the reference
  type outright left all three vector files byte-identical, so this costs nothing and
  turns a reading of Plonky3's source into a check against Plonky3's code. The assertion is
  not vacuous: deleting the absorb-length tag from the transcription aborts the generator.
- **The oracle links `zkhash` as well as Plonky3.** The stage names Plonky3, and Plonky3
  is where the permutation comes from — but Plonky3 does not ship the BN254 `RC3`
  constants; its own BN254 test imports them from `zkhash`. Taking the constants from
  `zkhash` is what Plonky3 itself does, and it has the side benefit that a second
  independent Poseidon2 agreed the KAT before this repository saw it.
- **No `PROTOCOL_VERSION` bump.** It stays `0`: S02 fills in a placeholder rather than
  changing a released protocol.
- **`#[rustfmt::skip]` on the three constant tables.** Left to rustfmt they run to ~500
  lines of one limb per line. One constant per line is shorter and diffable by eye against
  upstream. `#[rustfmt::skip]` is a stable attribute, not an unstable rustfmt option, so
  anti-goal 5 is not engaged.
- **SHA-256 is duplicated** into `crates/transcript/tests/common/mod.rs` (~55 test-only
  lines). Master rule 11 wants fixtures pinned by hash; the master prompt prefers
  duplication to an abstraction; both copies are checked against the NIST vectors where
  they live. *(Overruled by the repository owner after the stage: both copies now live
  once in `tools/test-support`, a dev-dependency-only crate with no dependencies of its
  own. See the S02a entry in `docs/decisions.md`. The workspace test count goes from 69
  to 71 — two duplicated NIST tests removed, four shared ones added.)*
- **No conflicts between the master prompt and the stage prompt were found.** The only
  place the stage left a frozen protocol decision open — the typed framing — was raised
  with the repository owner and decided by them, as recorded above.

## Open for the next stage

- `transcript_tags` has 7 entries. Later stages **append**; they never renumber, and they
  never reuse a tag across message kinds.
- The statement-binding absorb order in the master prompt's frozen invariants (protocol
  suite tag → `PROTOCOL_VERSION` → SRS digest → …) is *not* implemented here. S02
  delivers the mechanism; the order is the commit phase's job, and `PROTOCOL_SUITE` is the
  tag it starts with.
- G1 point absorption (affine coordinates split into two ~128-bit limbs, 4 `Fr` per point)
  needs `crates/curve`, so it lands with S03. It will be `append_scalars` under
  `COMMITMENT`.
