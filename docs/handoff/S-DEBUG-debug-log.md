# S-DEBUG — The proving debug log

> `docs/spec/debug-info.md` is normative. This note records what was decided, what moved,
> and what was deliberately left out.

**S-DEBUG takes no number, for S-IO's and S-NATIVE-IO's reason**: it is not one of the
original twenty-seven stages and has no prompt file. It was asked for directly, ahead of a
batch of deferred prover runs on the `s26c-sha256-ec` branch, so that a heavy suite's failure
says *where*.

---

## 1. The owner's decisions

1. **A second cargo feature, `prover/debug-info`.** Asked for as "a debug-info feature"; the
   alternative offered was a purely runtime `APOGEE_DEBUG` switch with no feature, which would
   have left master anti-goal 1 and `crates/prover/tests/one_feature.rs` untouched. The owner
   chose the feature, which authorized the edits that come with it — **anti-goal 1 in
   `prompts/00-master.md`**, `one_feature.rs`, the root `CLAUDE.md`, `crates/prover/CLAUDE.md`,
   `docs/spec/metrics.md` §0 and CI. Those are the only edits to `prompts/` in this change.
2. **`crates/prover` plus a thin `gkr` seam**, rather than prover-only or a wider sweep. The
   seam is `gkr::explain_self_check`, and it is what turns a verifier's
   `LayerInconsistency { layer }` into a named relation with its operand values.

**The rule still stands at two.** `one_feature.rs`'s `EXPECTED` is the list, and a third
feature is the owner's decision and nobody else's.

## 2. What it is

`APOGEE_DEBUG=off | phase | detail | deep`, optionally `deep:EC_ADD,MOD_MUL`; unset in a
feature-on build is `phase`. It writes to the **raw `io::stderr()` handle**, not `eprintln!`,
because libtest's capture prints a test's output only when that test *fails* and the failures
this exists for — an OOM kill on a 34–38 GB block, a hang, a `SIGINT` — lose captured output
entirely. **A `begin` line with no matching `done` names the shard that died**, and that pair
is the whole design.

The level is an environment variable rather than a threaded parameter because the log has no
state to thread: every line is emitted where its subject is already in scope. `debug::config`
reads the environment per call and caches nothing — anti-goal 7 bans the `OnceLock` that
would — and no log site sits inside a trace-sized loop.

## 3. The two things worth knowing

**`prove_shard` never called `gkr::self_check`.** That was the largest hole: a fill or a
circuit the forward pass cannot satisfy surfaced only as a verifier-side
`LayerInconsistency { layer }`, one number, from a verifier that by design cannot say whose
shard it was. At `detail` the log runs `self_check` before the backward pass and hands the
error to `gkr::explain_self_check`, which recomputes exactly one row, finds the disagreeing
gate itself (`SelfCheckError` carries no gate index, and finding it there is what keeps the two
from disagreeing) and names every operand — a committed column by the artifact's own name, an
**inner** column by *the relation that wrote it*.

**A delegation canonicity scan must not judge where the gate is gated.** A frame value's
`< m` conclusion is gated to the rows that read it, so `FR_ARITH` and `POSEIDON2` get a
*tally* and `EC_ADD`'s verdict is restricted by `debug::ec_add_reads`, a mirror of the private
`constraints::ec_add::VALUES`. Without that restriction every group-0 row reports its six
intermediate words as non-canonical and the honest prover looks broken on every block.
`MOD_MUL` gets a real verdict, `a < m` and `b < m` being gates since S26b, and **its scan runs
before the witness loop** — whose panic would otherwise be the only output and names neither
the invocation, the value, nor the selected modulus.

## 4. One latent inconsistency found, not fixed

`verifier_core::reduce_shard` step 9 reads channel `j`'s root pair at `outputs[2 + 2j]`,
counting **up** past the two memory roots (`crates/verifier-core/src/reduce.rs:229`);
`constraints::lookup::channel_cones` reads it at `outputs[len − 2·channels + 2j]`, counting
**down** (`crates/constraints/src/lookup.rs:502`). They name the same pair exactly when
`outputs.len() == 2 + 2·channels`, and **nothing central asserts it**: `reduce.rs` only checks
the length against the artifact's and `check_discharge` only requires `>=`.

Every registered circuit satisfies it today and each family's own test is what pins it —
`constraints::ec_add`'s `outputs.len() == 4`, `sha256`'s `== 2` — so this is latent, not live.
A family whose top layer grew one more output would have the discharge validating one pair
while the verifier read another, surfacing as `Lookup { channel }` on an innocent channel. The
log prints the comparison per family every run (`OUTPUT-LAYOUT-BREAK`); **a central assertion
was not added**, that being a change to the verifier's own load rules rather than a log line.

## 5. Deliberately left out

`docs/spec/debug-info.md` §3 lists three candidates and why: a block-level self-verify
(`derive_global_phase`, `verify_global_memory`, `check_ts_windows` against the prover's own
state), a `check_memory_windows` pre-flight, and distinguishing "declared but never invoked"
from "invoked and nothing recorded" for a delegation family with **zero** shards. Each is
useful; each is more than logging.

Also not done: the commit phase is **bracketed, not ticked**. A per-shard tick needs the
shard's position, nothing else wants it, and the default build then carries either an unused
index or an explicit counter — clippy rejects whichever spelling the feature-on build does
not, which is the structure saying it is wrong. The `begin` line names every shard and its
column count instead.

## 6. What was run

Green: `cargo fmt --all --check`; `cargo clippy --workspace --all-targets`; `cargo clippy
-p prover --all-targets` at `--features metrics`, `--features debug-info` and
`--features metrics,debug-info`; `cargo test -p gkr` (12 binaries, `tests/explain.rs`'s 5 among
them); `cargo test -p prover --test one_feature`; `cargo test -p prover --features debug-info
--test debug_info` and `--lib` (16 unit tests).

Exercised with the log on, which is how the scans were confirmed to run rather than merely
compile:

- `cargo test -p prover --features debug-info --test fills` at `APOGEE_DEBUG=detail` —
  `KECCAK_F`, `POSEIDON2`, `FR_ARITH` and `SHA256_COMP`, including the new
  `compression agrees with the frame on 264 state words`;
- the **deferred** `the_mod_mul_and_ec_add_fills_cover_their_circuits_exactly` at `detail`,
  which is the only coverage of the `MOD_MUL` and `EC_ADD` scans. It printed
  `modulus=[secp256k1_p:1096 secp256k1_n:296 bn254_p:25 bn254_r:26] of 1443 live rows`,
  `canon operands a<m and b<m: 2886/2886`, `curve/group=[13 13 13 0 0 0]`,
  `secp256k1 thirds=[13, 13, 13]` and `canon values the group reads: 234/234` — all four
  moduli exercised by the real workload, and the two arithmetic identities (2886 = 2·1443,
  234 = 39·6) hold.
- `APOGEE_DEBUG=phase` over the same suite prints nothing, which is the level gating.

**Not run**: `a_logged_block_is_the_block_prove_block_makes`, the `#[ignore]`d byte-equality
over S16's statement (~8.6 GB a time, twice, the `deep` run adding a self-check pass per
shard). It belongs in the next deferred batch.
