# The proving debug log

> `crates/prover/src/debug.rs`, behind the `debug-info` cargo feature, plus
> `gkr::explain_self_check`, which is compiled unconditionally. Added at S-DEBUG on the
> owner's instruction. This document is the reading guide; the module docs are the
> implementation's own.

---

## 0. The exception, and its limits

The workspace has **one cargo feature**, `prover/debug-info`, and it is the only exception
to master **anti-goal 1**:

> **No cargo features. Zero, but for one the owner granted by name.** One build
> configuration for the whole workspace. `[features]` tables, `#[cfg(feature = "...")]`,
> `optional = true` dependencies, and `--no-default-features` are all banned. A
> configuration nobody builds is broken and undiscovered; a configuration everybody builds
> should not be conditional. If code is optional, delete it.

There was a second, `prover/metrics`, granted at S20 for the proving harness and **retired
at S-STREAM**: it instrumented the *archived* proving path, the streaming prover became the
only path a block is proved down, and a harness measuring a path nothing runs is exactly the
configuration the anti-goal forbids. It was deleted rather than ported.

The owner granted this one at S-DEBUG, for this log and nothing else, with the rule left
standing for every future progression. Three things hold that:

- **`crates/prover/tests/one_feature.rs`** reads every `Cargo.toml` in the repository and
  fails if any `[features]` **table** exists but this crate's, or if this crate's declares
  any key but `EXPECTED`'s two, in that order.
- **CI builds, clippies and tests both configurations, and the two together.** The
  anti-goal's stated hazard is "a configuration nobody builds is broken and undiscovered";
  a configuration CI builds is neither.
- **`tests/debug_info.rs` proves the feature changes no proof byte**, by proving one
  statement twice in the one build — once with the log silent and once at `deep` — and
  comparing the blocks on the wire.

The feature enables **no dependency**, optional or otherwise.

### Why a feature and not a runtime switch alone

Because the cost is real and unconditional. The log's interesting lines are the
**invariant scans**:
every live row of a delegation shard checked against its modulus, every selector tallied,
`gkr::self_check` run over a whole shard. That is work proportional to the shard, and a
runtime switch alone would leave it compiled into every proving run and reachable by a
branch. The feature deletes it instead.

### Why the level is then an environment variable

Because the log has no state to thread. Every line is emitted where its subject is already
in scope — `family` and `index` inside `gkr_part`, the frame words inside `mod_mul` — so
there is nothing for a `&mut Recorder` equivalent to carry, and adding one would put a
parameter on twenty signatures to pass a `u8`. `debug::level` reads `APOGEE_DEBUG` on each
call and caches nothing: master **anti-goal 7** bans the `OnceLock` that would, and at the
granularity these lines sit at — a phase, a shard, a layer — an environment lookup is not
measurable against a shard's forward pass.

It also means **the deferred suites' invocations do not change**. A cargo feature has to be
passed at build time; the level does not, so one `--features debug-info` build answers
every question at every verbosity without a rebuild.

---

## 1. The interface

```text
APOGEE_DEBUG=phase                  the skeleton: one line per stage of a block
APOGEE_DEBUG=detail                 and per shard, per family, per channel; runs self_check
APOGEE_DEBUG=deep                   and per GKR layer, per sampled invocation
APOGEE_DEBUG=off                    nothing
APOGEE_DEBUG=deep:EC_ADD,MOD_MUL    deep for those families, detail for every other
```

Unset, in a build that has the feature, is `phase`: a reader who compiled the feature in
asked for output. `off`, `none` and `0` silence it; the levels also answer to `1`, `2` and
`3`. An unparsable value **complains once on the same stream and falls back to `phase`**,
because a debugging tool that answers a typo with silence is worse than one that answers it
with noise. The family names are the ones the log itself prints — `EC_ADD`, `MOD_MUL`,
`ADD_SUB_LUI_AUIPC` — case-insensitively, or a bare `FamilyId`.

**A family filter lowers the other families; it never lowers the block's spine.** Every
`phase` line is printed whatever the filter says, so `deep:EC_ADD` still shows you where the
run is. `Config::level_for` is the rule and `a_named_family_is_one_level_deeper_than_the_rest`
is the test.

### Where it writes, and why that is not `eprintln!`

To the **raw `io::stderr()` handle**, one `write_all` per line, flushed.

`eprintln!` routes through `std::io::set_output_capture`, which is how libtest captures a
test's output and prints it **only when that test fails**. The failures this log exists for
are the ones where no test ever fails:

- an **OOM kill** on a 34–38 GB block — the process is gone, and captured output with it;
- a **hang**, where nothing has failed yet and nothing is printed;
- a **`SIGINT`** on a run that was going nowhere.

A direct handle consults no capture, so the last line printed is the last thing that
happened. It also makes the stream consistent: capture is a thread-local, so lines from
rayon's workers already bypassed it while the main thread's were held back, and a log whose
ordering depended on which thread wrote it would be unreadable exactly where it matters — in
the parallel shard region.

The cost is that the log appears even for a passing test. That is what `off` is for, and the
default build has no log at all.

---

## 2. The one line the design is built around

The shard region is a `par_iter`, so **every line below `phase` names its own shard**, and
a shard's begin and done bracket it:

```text
apogee shard    EC_ADD#0               [7/13] begin h=2^16 witness-cols=1803
...
apogee shard    EC_ADD#0               gkr done layers=41 rounds=656 ms=38214.7
```

**A `begin` with no matching `done` names the shard that died.** That is the whole answer to
"where did this run go" for a kill, an OOM or a hang, and it needs no other machinery:

A shard has **two** such pairs, one per region — `begin`/`gkr done` and
`open begin`/`open done` — so on a 13-shard block each column below reads 13 when the block
finished:

```console
$ grep -c 'begin h=' run.log        # 13   GKR region entered
$ grep -c 'gkr done' run.log        # 12   <- one shard never finished its forward pass
$ grep -c 'open begin' run.log      # 12
$ grep -c 'open done' run.log       # 12

$ grep 'begin h=' run.log | tail -1   # the last shard to enter the GKR region
apogee shard    EC_ADD#0               [7/13] begin h=2^16 witness-cols=1803
```

The `[k/13]` counter on the `begin` line says how far into the block the kill happened, and
inside a region the set of unmatched `begin`s is the set of shards that were in flight — which
is what a 38 GB peak is made of.

Lines interleave across shards and that is fine; they never lose their subject.

---

## 3. What is logged, and the rule for adding a line

**A line must carry information a reader cannot already get.** The panic messages, the
`ProverError` variants, `tools/bench`'s `BenchReport` and `crates/checker`'s validators are
all already there; a line that restates one of them is cost, not information. And a log site may **never
sit inside a trace-sized loop**: a per-row fact is reported as a scan's summary — a count, an
extreme, the first offender — and never a row at a time.

| level | what | lines on a 13-shard block |
| --- | --- | --- |
| `phase` | setup, the statement, an aborted guest, the commit phase's begin and end, each shard's GKR begin/done **and opening begin/done**, the two parallel regions' begin/done, the block's begin/done, the streaming passes | tens |
| `detail` | each family's circuit inventory, each shard's `M` column count, the shard's `ts`/`g`/`β`, its output roots, the opening's commitment split, `self_check`, the delegation frame scans | low hundreds |
| `deep` | every GKR layer's shape and cumulative bytes, and the top layer's all-zero columns | hundreds |

**Every region and every shard has a `begin`/`done` pair, and that is not decoration.** The
GKR region is one peak and the **opening region is another** — it clones every committed
column at full height, 1,420 of them for `EC_ADD`, before `batch_open`'s MSM — so an OOM
there has to name something too. The commit phase is a third: its MSM bulk is one sequential
`map`, ~300 MB a shard, and a `begin` line is the only thing that prints if a run dies inside
it.

The commit phase is **bracketed, not ticked**: its `begin` line names every shard and its
column count in one line, and there is no per-shard line inside the loop. A tick would need
the shard's position, the position is wanted by nothing else, and the default build then
carries either an unused index or an explicit counter — clippy rejects whichever spelling the
feature-on build does not, which is the structure telling you it is wrong. The `begin`/`done`
pair is what localizes a death to the phase, and the per-shard column counts are on the
`begin` line before the work starts.

### What is deliberately *not* logged

- **the circuit, readably** — `cargo run -p checker -- dump <artifact>` already prints every
  layer, gate and relation, offline and better. `detail` prints the one-line inventory
  instead, because a `layer=9` in a failure means nothing until you know there are 41.
- **stage timings as a report** — that is `tools/bench`'s `prove` verb, whose
  `BenchReport` carries the `StreamingReport`'s clocks — each pass's wall clock and the
  executor's time inside it — beside the setup, verify and unattributed time, and is a
  better instrument for it. The log's `ms=` fields are there to
  say which shard is slow while it is still running, not to be added up. **A per-shard
  `ms` inside a parallel region is not a cost**: the GKR prover is itself rayon-parallel,
  so a worker parked in a nested `par_iter` work-steals another shard's task while that
  shard's `debug::Clock` keeps running. S-BATCH measured `INIT_TEARDOWN#0` at 6,958.8 ms
  in one pass and 154,167.8 ms in an otherwise identical one — a 139× spread on unchanged
  work (`docs/handoff/S-BATCH-miniblock-gate.md` §2.1). Per-family costs are read off a
  serial pass or not at all.
- **anything the multiset already catches globally**, such as a dropped delegation
  invocation, *except* where a local check names it better — which is what `EC_ADD`'s
  equal-thirds line and `ADD_SUB_LUI_AUIPC`'s request counts are.

### Three candidates considered and left out

Each would be useful and each is more than logging. They are recorded here so the next stage
does not have to rediscover them, and none should be added without deciding it is wanted.

- **A block-level self-verify.** After `public_inputs`, run `verifier_core::derive_global_phase`
  and compare its digest and memory challenges against the prover's own; then
  `verify_global_memory`; then `check_ts_windows` over the reconciliation records. It costs one
  Poseidon2 replay, 66 `eval_gate` folds and twelve comparisons against a 523 s block, and it
  would convert three `&'static str` refusals that name no shard into named ones *while the
  trace is still in hand*. It is left out because it makes the prover verify, which is a
  behavioural change and not a log line.
- **A `check_memory_windows` pre-flight**, before the commit phase. Seven `Statement` refusals
  and two payload ceilings are pure functions of data already in scope and are currently first
  discovered by `verify_block` after the whole block is proved. Same reason.
- **Distinguishing "declared but never invoked" from "invoked and nothing recorded"** for a
  delegation family with zero shards. The statement's `counts=` shows `MOD_MUL:0` and
  `frame_scan` covers the planned-but-empty shard, but a family with no shard at all runs no
  fill and so emits no line. Closing it means a per-delegation-family line at statement time
  carrying the cycle profile's invocation count beside the shard count.

---

## 4. The two pins, printed every run

```text
apogee setup    key ok families=12 entry_pc=0x10000 identity=<64 hex> srs_digest=<64 hex>
```

In full, not truncated, and in **`to_bytes` order** — the same bytes the `verifier` CLI
takes as its `<identity-hex>` argument, so the value pastes straight into it.

Five pins went stale in S26c and every one was found by a test failing somewhere else. A run
that prints both, every time, is how the sixth gets found by reading one line.

**Bare hex in this log is always a field element's canonical little-endian bytes.** The one
exception is `debug::limbs`, which prints an integer a reader compares against the
literature — a modulus, a coordinate — and marks it `0x` and big-endian for that reason.

---

## 5. The GKR self-check, and why it is the largest thing here

`prove_shard` does not call `gkr::self_check`. A fill or a circuit the forward pass cannot
satisfy therefore reaches a reader as a **verifier-side** `LayerInconsistency { layer }` —
one number, from a verifier that by design cannot say whose shard it was, which row, or what
the gate meant (the root `CLAUDE.md`'s "One `LayerInconsistency { layer }` for every failing
round or final check" is that decision, and it is right for a *proof*).

At `detail` the log runs `self_check` before the backward pass and, on failure, hands the
error to **`gkr::explain_self_check`**:

```text
apogee gkr      EC_ADD#0   self_check FAILED layer=12 row=41 relation=y2_below_modulus
apogee gkr      EC_ADD#0     gate list 12 row 41: enforcing gate 3, relation 87 y2_below_modulus
apogee gkr      EC_ADD#0     computed 1, and an enforcing gate owes 0
apogee gkr      EC_ADD#0     W[9] = 1   live
apogee gkr      EC_ADD#0     W[1832] = 0   y2_borrow_7
```

`explain_self_check` recomputes **exactly one row**, finds the first gate that disagrees
itself — `SelfCheckError` does not carry a gate index, and finding it here is what keeps the
two from ever disagreeing — and names every operand:

- a **committed** column by the name the artifact gives it (`artifact.memory`, `witness`,
  `setup`);
- an **inner** column by *the relation that wrote it*, which is what makes a failure at layer
  12 of a delegation circuit legible at all;
- a **cached** entry by its own name, a **virtual** table by its kind.

It is compiled unconditionally, because `gkr` may not have a feature of its own (that would
be a second `[features]` table, which anti-goal 1 still forbids). `crates/gkr/tests/explain.rs`
is what keeps it honest in the default build.

---

## 6. The delegation families

The user-facing reason this stage exists. Six families are invoked rather than decoded, their
rows are invocations, and what goes wrong in them is not what goes wrong in an execution
family. Every one of the six gets the shared frame scan; two get more.

### 6.1 Every delegation family: the frame

```text
apogee deleg    EC_ADD#0   invocations=1893/65536 frame_words=104 cycles=[812..990411] base=[0x2f000..0x2f000]
apogee deleg    EC_ADD#0   ts-gap=[3..14] over 38 bits
```

- **the invocation count against the height.** Zero is the *declared but never invoked*
  case — the family is in the `VmConfig` because the linked binary declared it, its shard is
  proved because the statement counts it, and every row is padding. Legal, and the first
  thing to check when a delegation is suspected of doing nothing. The line says so in words.
- **the cycle range**, the shard's cut of the execution, which its `ts` window must contain.
- **the base range**, which the frame's two decompositions bound.
- **the timestamp gap against the 38-bit clock.** The bit-decomposition frame writes exactly
  `memory::TS_BITS` bits and drops anything above, so a gap of `2^38` is committed as a gap
  of 0 and the memory argument stops balancing for a reason no gate names. The line prints
  ` -- OVER the 38-bit ceiling` when it happens.

`FR_ARITH` and `POSEIDON2` add a **canonicity tally** against `Fr`'s modulus — `below-p=[a:256
b:137 out:256] of 256 live rows`. A tally and not a verdict, deliberately: a value's `< p`
conclusion is gated to the rows that read it, so a row whose operation does not read a value
may legitimately carry one at or above `p`, and calling that a failure would report the honest
prover as broken. `out: 0/256` on a family whose every row writes `out` is still a bug you can
see at a glance.

### 6.2 `MOD_MUL`: the modulus selector, and a pre-flight

```text
apogee deleg    MOD_MUL#0  modulus=[secp256k1_p:1893 secp256k1_n:0 bn254_p:2 bn254_r:0] of 1895 live rows
apogee deleg    MOD_MUL#0  canon operands a<m and b<m: 3790/3790 below the modulus
```

The fill already panics on a selector that names no modulus and on an operand not below the
selected one — and its message names neither the invocation, nor the value, nor which of the
four moduli was selected. **The scan runs before that loop**, so it is read at all, and it
reports every offender rather than the first:

```text
apogee deleg    MOD_MUL#0  canon operands a<m and b<m: 3789/3790 below the modulus -- NOT
                           CANONICAL on 1 rows, first invocation 41: value=a=0xffff...fc2f
                           modulus=0xffff...fc2f
```

That is S26b's real cost made visible: `a < m` and `b < m` are *gates* now, so a caller
holding a lazily reduced representation must reduce **below the modulus** and not merely below
`2^256`. The histogram is the other half — a workload whose every invocation should be
`secp256k1_p` and which shows two in `bn254_p` has found its bug in one line.

### 6.3 `EC_ADD`: three thirds, and a canonicity verdict that does not lie

```text
apogee deleg    EC_ADD#0   curve/group=[secp256k1_g1:631 secp256k1_g2:631 secp256k1_g3:631 bn254_g1:0 ...]
apogee deleg    EC_ADD#0   secp256k1 thirds=[631, 631, 631]
apogee deleg    EC_ADD#0   canon values the group reads: 11358/11358 below the modulus
```

**The equal-thirds check is free and nothing else in the repository does it.** A row of this
family is one third of a complete point addition, so a guest that performed `n` additions on a
curve invoked each of that curve's three groups exactly `n` times. Three counts that differ
mean an addition whose thirds did not all reach the executor, and the line says
` -- UNBALANCED, a point addition is missing a third`. The global multiset catches a dropped
invocation eventually, as a root product that does not reconcile over a whole block, naming no
family and no row.

**The canonicity verdict is restricted to the values the row's group actually reads.** A
value's `< m` chain is computed on every row but its *conclusion* is gated to the groups that
read it, so on a group-0 row the six intermediate words hold whatever the guest's scratch held
and need not be below `m` at all. A scan that ignored that would call every honest block
broken. `debug::ec_add_reads` is that rule — a deliberate mirror of the private
`constraints::ec_add::VALUES`, and `a_group_reads_its_own_six` pins its shape.

This is also the line that names **S26c's own bug**: a gated conclusion written
`b_7 = enable` instead of `enable · (1 − b_7) = 0` made every row of `EC_ADD` unprovable while
the executor, the guests and every shape test passed. What a reader would have seen is a
canonicity verdict and `self_check` naming `<value>_below_modulus` on row 0.

### 6.4 The request side, and the anchor pairing

An invocation's partner is a **request row in `ADD_SUB_LUI_AUIPC`**, so the request side is
counted where that family is filled:

```text
apogee deleg    ADD_SUB_LUI_AUIPC#0    requests=[KECCAK_F:1204 POSEIDON2:0 FR_ARITH:0 MOD_MUL:1443 SHA256_COMP:33 EC_ADD:1893] exit-rows=1
```

Two sums a reader can do by eye, and nothing else in the repository offers either:

- **Σ requests per type, over this family's shards, equals that delegation family's
  invocation count** on its own `invocations=` line. Today a dropped invocation is
  `MemoryArgument("the statement's roots do not reconcile")` over a thirteen-shard product,
  naming no family and no row.
- **Σ exit rows over the whole execution is exactly 1** — the one row that writes `HALT_PC`.
  A trace missing its exit row cannot balance, and a trace with two is a different failure
  with the same symptom.

### 6.5 `SHA256_COMP`: the comparison is no longer the log's

Until S26e this section was a line the log printed — `compression agrees with the frame on
264 state words`, or `DISAGREES` — because S26c's fill re-ran the whole compression, committed
only its bits, and so never compared its answer with what the frame said the guest wrote. Since
S26e the fill makes that comparison **always**, in the default build: `prover::fill`'s
`sha256_row` recomputes each invocation's four rounds and four schedule words and refuses the
shard when a written working variable or window word differs, with an error that carries
`DISAGREES` and names the invocation and the word. A failing suite prints it through its
`expect`, so §8's grep still finds it; there is nothing left for a scan to add.

### 6.6 `KECCAK_F`: the round histogram, and the one failure the glue cannot see

```text
apogee deleg    KECCAK_F#0   round=[0:114 1:114 2:114 ... 22:113 23:113] of 2730 live rows
```

and, when the counts are not near-uniform:

```text
apogee deleg    KECCAK_F#0   round counts spread 0..114 -- a permutation is 24 consecutive
                             rounds, so a spread above 1 is a guest that is NOT LOOPING 24 TIMES
```

S26d made one invocation one **round**, so a permutation is 24 consecutive
invocations glued by the frame (`docs/spec/delegation.md` §6.4). The circuit proves
each row honestly whatever the sequence, and the memory multiset proves each row
read what the row before it wrote — **neither says there were 24 of them**. That is
the guest's own proven loop's job, and this histogram is where a reader can see it:
24 near-equal counts are a guest looping correctly, and any other shape is not.

The verdict line fires at a spread above 1 and not above 0, because a shard cut
mid-permutation legitimately leaves the low rounds one ahead of the high ones. It
is the analogue of §6.2's modulus histogram and §6.3's curve/group one, and like
them it is a **tally with one derived verdict** rather than a pass/fail: a
`round=[0:1 1:0 2:0 ...]` on a shard with one live row is a guest that called the
shim once, which is a real bug and an unambiguous line.

24 increments a row on a `2^18` family.

---

## 6a. One invariant the log checks that no test does

```text
apogee setup    EC_ADD OUTPUT-LAYOUT-BREAK outputs=5 want=4 (2 memory roots + 2 per channel):
                reduce_shard step 9 and constraints::lookup::channel_cones index from opposite
                ends and no longer agree
```

`verifier_core::reduce_shard` step 9 reads channel `j`'s root pair at `outputs[2 + 2j]`,
counting **up** past the two memory roots (`crates/verifier-core/src/reduce.rs:229`);
`constraints::lookup::channel_cones` reads it at `outputs[len − 2·channels + 2j]`, counting
**down** (`crates/constraints/src/lookup.rs:502`). They name the same pair exactly when
`outputs.len() == 2 + 2·channels`.

**Nothing central asserts that.** `reduce.rs` only checks the length against the artifact's and
`check_discharge` only requires `>=`. Every registered circuit satisfies it today and each
family's own test is what pins it — `constraints::ec_add`'s `outputs.len() == 4`,
`sha256`'s `== 6` since S26e — so this is a latent inconsistency rather than a live bug. A family whose
top layer grew one more output would have the discharge validating one pair while the verifier
read another, and it would surface as `Lookup { channel }` on a channel that is innocent. The
log prints one integer comparison per family, every run.

---

## 7. What it costs

Nothing in the default build: the module does not exist, and `dlog!` and `debug_only!` expand
to nothing, so their arguments are never evaluated.

With the feature on and `APOGEE_DEBUG` unset or `off`, one `std::env::var` lookup per log site
— at phase, shard and layer granularity, which is hundreds of lookups against a block that
runs for minutes.

At `detail`, `gkr::self_check` is another pass over every gate at every row of every shard,
comparable to the forward pass itself; budget roughly **1.5× to 2× a block's wall clock**, and
no additional memory beyond the one row of scratch. The delegation scans are
`O(live rows × frame words)` over the **live** rows alone — 1,893 rows of a `2^16` shard, not
65,536.

At `deep`, one line per layer and **no per-cell sweep**: an all-zero test over every column of
every layer is ~90M `Fr::get` calls on one shard, which would make `deep` change what it is
measuring — the one thing a debugging aid may not do. The per-layer line carries the layer's
bytes and the running total instead, and the all-zero test is applied to the **top layer
alone**, where it is a handful of columns and where an all-zero column is a root of 0.

---

## 8. Using it on a failing deferred suite

```console
$ APOGEE_DEBUG=detail cargo test --release -p prover --features debug-info \
      --test revm -- --include-ignored --test-threads=1 2>&1 | tee /tmp/revm.log

$ grep 'begin h=' /tmp/revm.log | tail -1  # the last shard to enter the GKR region
$ grep -c 'begin h=' /tmp/revm.log; grep -c 'gkr done' /tmp/revm.log   # unmatched = died
$ grep -E 'FAIL|NOT CANONICAL|UNBALANCED|OVER the|NAMES NO|DISAGREES|ABORTED|LAYOUT-BREAK' \
      /tmp/revm.log                           # every verdict any scan reached
$ grep '^apogee setup    key' /tmp/revm.log   # identity and the SRS digest, for the pins
$ grep '^apogee commit   done' /tmp/revm.log  # the five values every shard forks from
```

Then narrow: `APOGEE_DEBUG=deep:EC_ADD` re-runs with that one family at full depth and
everything else at `detail`.

### Which pass died

Since S-STREAM there is one proving path and it runs the guest twice
(`docs/spec/streaming.md` §2), and since S-PIPELINE each pass is a pipeline of
`max_in_flight` workers (`docs/spec/streaming.md` §5), so every shard of every pass has a
`take` line when a worker claims it and a `committed` or `proved` line when that worker
is done with it:

```console
$ grep '^apogee stream' /tmp/run.log
apogee stream   begin max_in_flight=8 families=13
apogee stream   pass 1 take ADD_SUB_LUI_AUIPC#0    fill#0 in_flight=1/8 waiting=0
apogee stream   pass 1 committed ADD_SUB_LUI_AUIPC#0    M=<n> fill_ms=<ms> ms=<ms>
...
apogee stream   pass 1 done shards=51 ms=<ms> execute_ms=<ms> peak_in_flight=8/8
apogee stream   pass 2 take ADD_SUB_LUI_AUIPC#0    fill#0 in_flight=1/8 waiting=0
apogee stream   pass 2 proved ADD_SUB_LUI_AUIPC#0    fill_ms=<ms> ms=<ms>
...
apogee stream   pass 2 done shards=51 ms=<ms> execute_ms=<ms> peak_in_flight=8/8
```

`begin` with no `pass 1 done` is a death in pass 1 — in the executor, or in a shard's
commitments — and a `pass 1 take` with no `pass 1 committed` names the shards that were in
flight, at most `max_in_flight` of them. `pass 1 done` with no `pass 2 done` is a death in
pass 2, and the `take`/`proved` pairs, with §2's `begin`/`gkr done` counting inside them,
name the shard. `fill#` is the shard's place in fill order, which is the order a failure
is chosen by (the earliest wins). A `take` line's `in_flight=` is the shards claimed and
its `waiting=` the shards filled and not yet claimed — rows, at most one per family — so
`in_flight` held below the bound in mid-pass is a pass whose executor is the bottleneck,
the first thing to check when a pass is slower than its shards. `fill_ms` is a shard's
fill, which is one thread; the rest of its `ms` is its MSMs or its proof, on the pool.

`apogee ABORTED` is the other line worth a `grep`: a nonzero `x10`. A guest that panicked
exits 101 having published whatever it had committed, so its block proves and verifies
and answers a different question.

### Two runs that should have agreed

A `max_in_flight` difference, a rebuilt key, a thread count — none of these may move a
byte of the block, and when one does, the first question is whether the two runs agree at
`apogee commit   done`. Everything downstream is a function of the digest and the four
memory challenges on that line: if they agree, the divergence is inside a shard and §2's
per-shard lines bracket it; if they do not, it is in the statement or the key, and
`apogee setup    key` (§4) is where identity and the SRS digest are printed in full.

**There is no second construction to diff against.** Until S-STREAM a streamed block could
be held against `prove_block`'s, and that comparison is gone with the archived path
(`docs/spec/streaming.md` §6.3) — a test may not run it, and neither may a debugging
session. What is left is this log, two runs of the one path, and `verify_block`.
