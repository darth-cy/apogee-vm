# S-BATCH — The mini-block gate, measured

> **S-BATCH takes no number**, for S-IO's and S-NATIVE-IO's reason: it is not one of the
> original twenty-seven stages and has no prompt file. It is the **deferred batch S26c
> deliberately skipped** (`S26c-sha256-ec.md` §7.1) and the run S-DEBUG was built for
> (`S-DEBUG-debug-log.md` §6, "It belongs in the next deferred batch").
>
> It changed no circuit, no wire form and no constant. It fixed eight assertions, ran one
> suite, and produced the first measurements of this repository's proving cost on x86-64.

**Tree measured:** `c8d8028` on `s26c-sha256-ec` (PR #32, left a draft).
`aff4b0c` is code-identical — it touches only `ci.yml` and `CLAUDE.md` — and was committed
two minutes *after* the gate began, so every number here is `c8d8028`'s.
**Machine:** `apogee-dev`, AWS `r8i.8xlarge`, 32 vCPU / **16 physical cores + SMT2** /
3.9 GHz / 256 GiB, Ubuntu 24.04, `rustc 1.96.1 (31fca3adb)`, x86-64.
**Every previous figure in this repository was taken on an 18-core / 48 GiB Apple M5 Pro.
This is the first x86-64 measurement of anything.**

Read every figure below as **[M] measured**, **[D] derived** or **[U] unverified**. The
distinction is load-bearing and the note keeps it everywhere.

---

## 1. What ran, and the result

`cargo test --release -p host --features prover/debug-info --test prove -- --include-ignored
--test-threads=1` at `RAYON_NUM_THREADS=12`, `APOGEE_DEBUG=phase`.

| test | result |
| --- | --- |
| `a4_a_claimed_journal_that_is_not_the_proved_one_is_refused` | **ok** |
| `a4_the_mini_block_proves_and_verifies` | **ok** — the gate |
| `a5_a_corrupted_advice_cell_is_refused` | **not run** — killed on the owner's instruction, §9 |

The `Exit status: 101` in `10-miniblock-gate-t6.time` is that kill, not a failure.

**The gate's seven assertions all held** [M]. The load-bearing one is the third:

```rust
assert_eq!(proven.journal, read(fixture::journal_file(STEM)),
           "the proved journal is not the pinned one");
```

The journal is the committed public output, bound by `verify_shard_local` step 10c against
the verifier's own multilinear extension of `public.output`
(`docs/spec/public-values.md` §5.1). It matched the pinned 90 bytes
(`sha256 2b526b96…`) exactly. **So S26b's `MOD_MUL` and S26c's `EC_ADD` compute
bit-identically to the software paths they replace, on a real workload, end to end.**
That is the result S26c §7.1 listed as unobtained.

```
statement    31 shards, 15,899,359 cycles, block 26,057,509 first 2 of 246 txs
identity     ae9d07ca035750cda04b424f04856778e51b23b46639f5be2e20e8e507499c03
srs_digest   6a5581ccd7fe2b2ca6646b02f5400ea529369c17afecbee688ad6c5e6a55c318
families     16 declared; plan [(0,5)(1,3)(2,3)(3,1)(4,4)(5,2)(6,1)(7,0)(8,0)(9,5)
                               (12,0)(13,0)(14,0)(15,1)(16,0)(17,1)]
proof        61,382,738 bytes      journal 90 B      exit 0
```

`families=16` with ids 10 and 11 absent is the log's own proof that `revm-block` declares
`KECCAK_F`, `MOD_MUL`, `SHA256_COMP` and `EC_ADD` and not `POSEIDON2` or `FR_ARITH` [M].
A direct scan of the linked release image for `APOGDEL1` records found the four at
`.rodata` offsets `0x1b587c`, `0x1b5888`, `0x1b5894`, `0x1b58a0` [M, but by a direct read,
not from a committed log — `05-revm-declares.log`'s extraction failed].

### 1.1 Proof length agrees across thread counts; byte identity is **not** shown

`bytes=61382738` at 6 threads, at 12 threads, and in the tamper harness's serial re-proof;
per-family per-shard proof lengths sum to 61,248,716 in all four passes; the commit digest
is `3e089ef6…` in every honest pass [M]. That is **length** identity plus an identical
commitment phase. No digest of any shard proof or of the `BlockProof` appears in any log,
so byte identity is *consistent with* the evidence and not *demonstrated* by it [U].
`crates/prover/tests/streaming.rs` is what proves byte equality, and it did not run.

---

## 2. The cost anatomy — and a warning about reading it

### 2.1 A per-shard `ms` in a parallel region is not a cost

The shard region is a rayon `par_iter` (`crates/prover/src/phases.rs:319`), and the GKR
prover is **itself** rayon-parallel — `crates/gkr/src/lib.rs:324` over forward-pass blocks
and `:833` over the layer sumcheck's round nodes. A worker parked in a nested `par_iter`
work-steals another shard's task **while its own `debug::Clock` keeps running**
(`crates/prover/src/debug.rs:264`). So a shard's logged `ms` in a parallel region is its
*elapsed wall inside a contended region*, not its work.

How badly: `INIT_TEARDOWN#0` — one shard, identical work — logged
**1,244.4 / 1,256.9 / 8,800.9 / 47,935.6 ms** across the run's four passes, and
**6,958.8 ms in pass A against 154,167.8 ms in pass B**, two otherwise identical parallel
passes [M]. A 139× spread on unchanged work. **Anyone reading per-family costs off a
parallel region will be wrong by up to two orders of magnitude.**

The honest basis is the **serial** pass: `checker::TamperHarness` proves into a `Vec` in a
plain loop (`crates/checker/src/tamper.rs:467`) and never enters the shard `par_iter`, so
each shard there is measured alone — **a shard's isolated 12-thread wall**, still
intra-shard parallel, not a single-thread cost.

### 2.2 Per-family cost, serial basis (one block, 815.8 s of shard work) [M]

| | share of shard work | per shard |
| --- | --- | --- |
| **7 execution families** (19 shards) | **612.5 s — 75.1%** | 21.2–41 s |
| **3 delegation families** (7 shards) | **197.4 s — 24.2%** | see below |
| ` ` `KECCAK_F` ×5 | 116.5 s — 14.3% | 23.3 s at 2^8 |
| ` ` `EC_ADD` ×1 | 65.8 s — 8.1% | **61,716 ms — the most expensive single shard** |
| ` ` `MOD_MUL` ×1 | 15.1 s — 1.8% | 15.1 s at 2^16 |
| 5 window families (5 shards) | 5.9 s — 0.7% | ≤1.3 s |

**The execution families dominate by 3.1×, and neither delegation family dominates.**
`ADD_SUB_LUI_AUIPC` alone (138.8 s, 17.0%) beats `EC_ADD` + `MOD_MUL` together by 1.72×.
`EC_ADD` is the costliest *shard* — 1.99× the execution median — and simultaneously **97.4%
empty**: 1,728 invocations in 65,536 rows [U on the count, §5].

### 2.3 A cost law, and the one family that breaks it [D]

GKR ms ÷ (witness columns × height) is **0.55–0.97 µs per witness cell for nine of the ten
families with witness columns**, across a 42.8× width range and both 2^16 and 2^20 — with a
systematic ~1.5× height term inside the band (2^20 median 0.61, the two 2^16 families 0.92
and 0.97). So proving cost is, to first order, **per witness cell**.

`KECCAK_F` is the tenth and is **25.48 µs/cell — 41× the median**, because at 2^8 its 177
layers and 1,380 rounds pay per-round fixed cost over only 256 rows.

Opening cost at 2^20 is **linear in committed width**: OLS over 22 points gives
`ms = 923.3 + 48.70 × committed` [D]. Against ~651 ms per witness column on the GKR side,
widening a circuit is ~13× cheaper on the opening side than on the proving side.

### 2.4 `KECCAK_F`'s height is the largest single lever in the repository

5 `KECCAK_F` shards are **59,400,060 of 61,382,738 proof bytes = 96.77%** [M]. Its height
is therefore one lever on *both* proving cost (41× the per-cell median) and proof size.
`docs/spec/delegation.md` §9.2 sets `2^8` because `2^16` is 744 GB of forward pass. `2^10`
would be 11.6 GB, inside the 10.0–15.8 GB an execution shard already costs at 2^20 — but
**`2^10` is NOT on the height menu.** `constants::family::HEIGHT_MENU` is
`[1<<8, 1<<16, 1<<18, 1<<20, 1<<22]` (`crates/constants/src/lib.rs:1215`), five entries, and
it is *enforced on bytes a verifier is handed*: `VmConfig::from_bytes` refuses any height
not in it (`crates/verifier-core/src/statement.rs:84`) and `decode_program` returns
`HeightNotOnMenu` (`crates/program/src/lib.rs:717`). §9.2's "the menu below `2^16` had `2^8`,
`2^10`, `2^12` and `2^14` to choose from" is what S21 *could* have picked, not what the menu
holds today. **An earlier draft of this note read it the other way; this is the correction.**

So the lever is **one constants amendment away**, not free: `HEIGHT_MENU` goes `[u32; 5]` to
`[u32; 6]`, and `crates/program/tests/common/mod.rs:144-145` reads `HEIGHT_MENU[1]` and
asserts it is `1 << 16` **by name**, which inserting `2^10` breaks. The circuit itself needs
no change — `KECCAK_F`'s minimum height is 0 (`crates/constraints/src/lib.rs:169-180`).

Raising `KECCAK_F` to `2^10` would cut its shard count 4× at full-block scale. **Proof size
is not height-independent** — the controlled case is `ZERO_WINDOWS` and `PUBLIC_OUTPUT`,
whose circuits agree byte for byte (`constraint-manifest.md`), differing only in height:
9 layers / 36 rounds / 6,604 B at 2^8 against 21 / 210 / 30,508 B at 2^20, i.e. ~137 B per
round, growing logarithmically [M]. So the win is shard count, net of ~2.6 kB a shard.
**This is the cheapest large win available and nobody has taken it.**

### 2.5 Parallel behaviour [M]

Per-shard elapsed summed over a block ÷ the block's wall gives **8.16 and 8.10 of 12
workers** for the two complete blocks. Inside the GKR *region* alone, summed task time ÷
the longest task gives **11.19× and 11.32× of 12 — 93–94% packing**. Measured speedup
6 → 12 threads is **918,683.9 → 515,386.8 ms on the same test = 1.79×, 89.6% efficiency**.

Whole-run utilisation was **6.06 cores of 12 (605% CPU)** — dragged down by the serial
tamper passes, which is the measured cost of `TamperHarness`'s serial loop.

---

## 3. Memory — the peak, and why the marginal is a bracket

| | |
| --- | --- |
| peak at `RAYON_NUM_THREADS=12` | **142,897,232 kB = 136.28 GiB** [M, `10-miniblock-gate-t6.time`] |
| peak at `RAYON_NUM_THREADS=6` | 96,923,324 kB = 92.43 GiB [**U** — an operator reading of `/proc/PID/status` `VmHWM` mid-run on a partial run; no `.time` file exists for it, and it is the single unreproducible input to everything below] |

**136.28 GiB is 3.9× what this repository records for this gate** (S25: 34.9 GiB / 37
shards) and 3.3× the largest peak recorded anywhere (41.2 GB, `S26-cycle.md`). The cause is
`MOD_MUL` and `EC_ADD` joining the statement after those notes were written. **No memory
figure in any handoff note predating this one should be used for sizing.**

**The marginal per concurrent shard is a bracket, not a number.** Fitting the two points
against the *thread count* assumes concurrency equals threads, and the logs refute that:
walking every `[n/31] begin` against its `gkr done` gives a maximum of **17 shards
simultaneously live at 12 threads and 10 at 6** — rayon steals into a new shard task while a
thread is parked in a nested `par_iter`. Time-weighted concurrency is 10.23 and 5.91.

| basis | marginal / shard | base |
| --- | --- | --- |
| peak concurrency (10 → 17) | **6.26 GiB** | 29.8 GiB |
| time-weighted (5.91 → 10.23) | **10.16 GiB** | 32.4 GiB |
| thread count (6 → 12) — *the false reading* | 7.31 GiB | 48.6 GiB |

`docs/spec/metrics.md` §4.3's modelled 4.94 GiB per 2^20 shard sits below all three and is a
documented floor; `metrics.md:256` forbids quoting the model where the measured figure
matters, so it corroborates nothing here.

**Consequence: max safe in-flight on a 247 GiB box is ~22 shards, not 31.** At the
conservative 10.16 GiB, 20 in flight is 217 GiB and 252 GiB with three `EC_ADD` resident —
over the box. The run's own `RAYON_NUM_THREADS=12` (136 GiB) had ample margin; 16 would have
been ~165 GiB and also safe. The session's in-run estimate of 13.9 GiB/shard was too
pessimistic and its rejection of 16 threads was over-conservative.

---

## 4. Full-block proving — the blocker is not the machine

**Every sizing number below is secondary. The binary this run measured cannot prove a full
block, and no full-block witness can be recorded today.**

### 4.1 `guests/revm-block` cannot publish a full block's journal [M]

`docs/spec/revm-block.md` §2 is **frozen** and carries a record **per transaction** — 45
bytes each on this workload — so a 246-transaction block's commitment is ~11 KB against the
public output window's **1,020 bytes** (`docs/spec/public-values.md` §3).
`guest_sdk::commit` **exits `EXIT_IO_ERROR` = 70 rather than truncating**
(`crates/guest-sdk/src/lib.rs:199,209,273`), because a caller reads the journal back and
must not see one it did not write.

This is already measured, four times over. `S26-cycle.md` §4.1 profiled four real blocks and
**every one exits 70**; only the mini-block exits 0:

| block | txs | gas | cycles | cycles/gas | exit |
| --- | --- | --- | --- | --- | --- |
| mini-block | 2 | 392,997 | 23,733,540 | 60.4 | **0** |
| 26,059,929 | 67 | 17,342,086 | 175,185,282 | 10.1 | **70** |
| 26,059,800 | 132 | 60,000,000 | 747,689,251 | 12.5 | **70** |
| 26,059,700 | 450 | 60,000,000 | 1,010,920,000 | 16.8 | **70** |
| 26,059,900 | 376 | 60,000,000 | 2,075,897,177 | 34.6 | **70** |

`host::prove` does **not** check exit status (`crates/host/src/lib.rs:102-105`), so a full
block on this binary would *prove* — and gate assertions 2 (`exit_code == 0`) and 3 (journal
== pinned) would both fail on an execution that published a partial journal.

**The full block is `revm-block-stateless`'s job** — a second `[[bin]]`
(`guests/revm-block/Cargo.toml:39-41`), a **second program identity**, a second verifying
key, and a **fixed 148-byte** journal that digests the per-transaction stream instead of
carrying it (`revm-block.md` §5). `S25-block.md:12` says it in words: *"stateless full block
last."*

It is **not** entirely unmeasured, and §11 leans on the one datum there is:
`S25-block.md:451-452` records the guest recomputing the post-state root in **665,154
cycles** against **17 real accounts and 37 real slots** — the mini-block's own shape, 210
trie nodes, so **~3,170 guest cycles per trie node** [M]. It has never been *proved*, never
run on a real block, and no committed artifact carries a stateless `KECCAK_F` count.

### 4.2 And the cycles/gas base everyone has been scaling is the wrong one

The table above is the correction. **The mini-block's 60.4 (S26) / 40.5 (S26c) cycles per
gas is a 2–6× outlier**, because two transactions amortise MPT verification and witness
loading over almost no gas. Real blocks measure **10.1–34.6** cycles/gas.

`S25-block.md` projects the pinned full block at ~1.72e9 cycles and **~1,900 shards** by
scaling the mini-block's 61.6 cycles/gas. On the measured real-block range, 27,971,256 gas
is **~280M–970M cycles** — so **~1,900 shards is likely a 2–3× overestimate** [D], and the
500–600 GB archived-commit figure that follows from it with it. Note also that cycles at
fixed gas span 2.8× across the three 60 M-gas blocks, so gas alone is a poor predictor and
**tx count matters independently**.

Also structural, and got wrong by a flat scale: `INIT_TEARDOWN`, `PUBLIC_INPUT` and
`PUBLIC_OUTPUT` prove **exactly one shard in every statement, forever**. Scaling 31 shards
by a gas ratio scales five families that do not scale.

### 4.3 Recording a full-block witness is blocked upstream of the prover [M]

Stateless mode must recompute the post-state MPT root, and **a collapsing deletion needs a
sibling node `eth_getProof` cannot return** — measured at 87 of 300 randomised trials, 29%
(`S25-block.md:205-215`), and common in practice because writing zero to a storage slot is a
deletion. `tools/kat-gen/src/block.rs:192-196` says of the committed node set that it *"is
deliberately NOT a complete stateless witness."* `debug_executionWitness` closes it and Geth
does not serve it (`S25-block.md:583-588`). There is exactly one committed pin, and it is
`mode: Mini`.

### 4.4 If both of those clear, here is the sizing

Shard-work basis: 815.8 s per mini-block serially [M]; the central full-block projection is
**~1,717 shards** by component (execution 1,352 + `KECCAK_F` 356 + `EC_ADD` 2 + `MOD_MUL` 2
+ windows 5) on the mini-block's own cycles/gas [D] — and §4.2 says read that as an upper
bound. Proof size projects to **~3.66 GB at 97.6% `KECCAK_F`** [D], which alone justifies
§2.4.

- **Memory is not the binding constraint** once the streaming prover is used. Peak is
  `base + in-flight × marginal`, so `--in-flight` buys any box: at the conservative
  10.16 GiB/shard, 256 GiB holds ~22 in flight and 768 GiB ~72.
- **vCPU quota is the binding constraint, and it is administrative.** `L-1216C47A` is **40**
  with 4 in use by out-of-jurisdiction instances, so 36 vCPU of headroom caps us at 32 and
  **`r8i.12xlarge` and larger cannot launch at all.** An increase to 96 is authorized but
  **unfiled**: `apogee-provisioner` holds `ServiceQuotasReadOnlyAccess`, which lacks
  `servicequotas:RequestServiceQuotaIncrease` — an action both
  `config/iam-policy-apogee-operator.json` and `…-supplement.json` already declare and
  neither attaches. Approval takes days. **File it before anything else.**
- **Per-core throughput on this box is ~1.3× slower than the M5 Pro reference** at equal
  thread count [D], so core count buys less than a naive scaling suggests. Compilation is
  free: 23.7 s for 164 crates and 171 test binaries at 1762% CPU [M].
- One prover change is a clean win on the archived path and **not** on the streaming one:
  `commit_chunks` is deliberately one shard at a time
  (`crates/prover/src/streaming.rs:267-271`, *"holding two shards' columns here would buy
  nothing but a second shard's worth of peak"*). Parallelising it costs
  `min(threads, batch) × 0.9–1.04 GB` — 26–32 GB at 32 threads — which is exactly what
  streaming exists to avoid.

---

## 5. What the run proves about the precompiles, and what it does not

**Proved** [M]: `MOD_MUL` and `EC_ADD` are bit-exact on this workload, through the journal
(§1). `EC_ADD` proved one real 2^16 shard — the first ever — at 392 committed and 1,028
witness columns. The vendored routing is live and the arkworks fallbacks are dead:
`05-revm-declares.log` reports `g1_point_add` and `g1_point_mul` in
`guests/vendor/revm-precompile/src/bn254/arkworks.rs` as **never used**, which is the
`Crypto` default-body patch working as S26c §3.5 intended.

**Not proved**, and each should be stated rather than assumed:

1. **`SHA256_COMP` proved ZERO shards** (`plan … (16,0)`) [M]. It is declared, in the
   verifying key, and never exercised end to end by this fixture, whose two transactions
   call no `0x02`. What covers it is `prover::fills` (deferred, not run) and
   `checker::tests::sha256`'s row-local evaluation. **`SHA256_COMP` has never been proved in
   a block.**
2. **Which of `MOD_MUL`'s four moduli this block exercises is unknown** [U]. The selector
   scan is a `detail`-level feature and this run was at `phase`. The workload is `ecrecover`
   through the patched `k256`, which reaches secp256k1's `p` and `n`; BN254's `q` and `r`
   are reached only through `ark-ff`, which this block's transactions do not call. One
   `APOGEE_DEBUG=deep:MOD_MUL` run over this fixture settles it.
3. **The invocation counts 1,728 and 1,123 are not from this run** [U]. `phase` emits no
   frame scan. They are S26c's, and `S26-cycle.md:348` records `MOD_MUL` at **6,705** for
   the same fixture one stage earlier — a 6× move, explicable (S26c routed `ProjectivePoint`
   through `EC_ADD`) but unevidenced here. What the run bounds is: each family filled exactly
   one 2^16 shard, so each made 1 to 65,536 invocations.

---

## 6. S26c §7.1, row by row

| suite | after this session |
| --- | --- |
| `host::prove` | **SETTLED** — the gate passes; both new circuits in the config |
| `prover::revm` | **STILL OPEN** — not run. Its `revm_params()` bug was fixed here (§7) but the suite never executed |
| `checker::tamper` | **STILL OPEN, permanently** — struck from every run list, §9 |
| `emulator::guests` | **STILL OPEN** — the `ec-ops`/`sha256-ops` invocation counts |
| `prover::fills` | **STILL OPEN** — and it is the only thing covering `SHA256_COMP`'s fill |
| the other eight, `checker::logup`, `verifier::cli`, `prover::{acceptance,metrics}` | **STILL OPEN** — cancelled |
| S-DEBUG's `a_logged_block_is_the_block_prove_block_makes` | **STILL OPEN** |

**`EC_ADD`'s 20.5 GB per shard is still not confirmed** [U]. What was measured is a whole
*block's* peak; no log line carries a per-shard memory figure, and no run isolated one
`EC_ADD` shard. Treating 136.28 GiB as confirmation of 20.5 GB would be exactly the
whole-block-for-one-shard conflation §3 warns about. S26c §7's caution stands.

---

## 7. The eight assertions fixed, and how one validated itself

`constants::delegation::TYPES` went from four entries to six at S26c; add/sub commits one
request selector per type, so its witness count went 33 → 35 and identity's setup
commitments moved two slots later. Four assertions across three never-run suites still
pinned the four-type shape.

| file | was | now |
| --- | --- | --- |
| `prover/tests/acceptance.rs:174` | `57_004` | `57_196` |
| `prover/tests/acceptance.rs:178` | `27 + 33 + 7` | `27 + 35 + 7` |
| `prover/tests/control.rs:163,164` | `27+33+7`, `&add[60..]` | `27+35+7`, `&add[62..]` |
| `prover/tests/alu.rs:196,197` | `27+33+7`, `&claim[60..]` | `27+35+7`, `&claim[62..]` |
| `checker/tests/tamper.rs:1139` | `last_family == MOD_MUL` | `== EC_ADD` (id 17 > 15) |
| `prover/tests/revm.rs:275-283` | 4-family tail | 6-family tail |
| `prover/tests/revm.rs:71-74` | three families named | **derived** from `program::delegation_ecall` |

**`57_196` was derived and then confirmed by the prover independently**: the gate log emits
`ADD_SUB_LUI_AUIPC#0 … open done bytes=57196` [M]. The `+96` a delegation type costs — one
64-byte witness commitment and one 32-byte base claim — is exactly what the comment above
that assertion already stated.

The last row is a latent bug, not a stale pin. `revm_params()` named three of the six
delegation families and left `MOD_MUL`, `SHA256_COMP` and `EC_ADD` at **2^20**, where
`EC_ADD`'s 8,708 row-wise columns are a **292 GB** forward pass and `SHA256_COMP`'s 16,688
are **560 GB**. Latent only while that block invokes neither. (Related headroom, for a stage
that grows this guest: a `2^20` decoded table reaches pc `2·2^20 − 4`, but `.text` starts at
`RAM_ORIGIN = 0x10000`, so the code-available span is **2,031,612 B = 1.9375 MiB** and S24's
release image uses **82.7%** of it, leaving ~342 kB — not 18% of the full pc reach.) Both sibling suites already
derived the height; this one now does too — S26c §5's "derive over document".

---

## 8. Corrections owed to the repository's own pages

| where | says | should say |
| --- | --- | --- |
| `CLAUDE.md`, `ci.yml`, every handoff note | peaks of 8.6–41.2 GB, largest 41.2 | the mini-block gate is **136.28 GiB** at 12 threads; no pre-S26c peak is usable for sizing |
| `S25-block.md` mini-block rows | 34.9 GiB, 37 shards, 849,920 ms | 136.28 GiB, **31** shards, 512,716 ms at 12 threads — a different statement |
| `S25-block.md` full-block projection | ~1.72e9 cycles, ~1,900 shards | derived from the mini-block's outlier cycles/gas; §4.2 puts it 2–3× high |
| `CLAUDE.md:210` (before this stage) | tamper 17.9 GB / 4231 s | `S26-cycle.md` measured 20.2 GB / 5,330 s |
| `apogee-aws` instance/inventory docs | justify the box with QEMU differential tests | QEMU is gone; the driving requirement is 136 GiB of peak |

---

## 9. Deviations and decisions, listed

1. **`checker::tamper` is not run, anywhere** — owner's instruction, struck from
   `CLAUDE.md`'s command block and both of `ci.yml`'s blocks. The file and
   `checker::TamperHarness` stay, and the harness is **not optional**:
   `host/tests/prove.rs`'s `a5` is built on it. Coverage given up, stated as such: control
   C8's three forgeries, S17–S19's per-family twins, the delegation anchors' four, and
   S26c's changed `mm_shards == 1`. `host::prove`'s advice twin is what still exercises the
   harness — and it did not run either.
2. **`a5_a_corrupted_advice_cell_is_refused` was killed**, on the owner's instruction, after
   it proved to be ~2.5 h rather than the ~26 min first estimated — because
   `TamperHarness` is serial (`crates/checker/src/tamper.rs:467`) and gains nothing from
   more workers.
3. **The twelve other deferred suites were cancelled** on the owner's instruction, to focus
   the session on the gate.
4. **The thread cap was released from 6 to 12**, not to 32: §3's measurement puts 31
   concurrent shards at ~336 GiB against 247. In hindsight 16 was also safe (§3).
5. **The vCPU quota increase to 96 was authorized but could not be filed** — §4.4.

---

## 10. What a next session owes

**Must, in order:**

1. **File the vCPU quota increase.** Administrative, days of latency, blocks every box above
   32 vCPU.
2. **Decide the full-block binary.** §4.1 — `revm-block-stateless` exists and has never been
   proved. Nothing about full-block proving can be planned against `revm-block`'s numbers.
3. **Solve the witness source, or accept synthetic full blocks.** §4.3 — this is upstream of
   the prover and of the hardware.
4. **Run `prover::fills`.** It is the only coverage of `SHA256_COMP`'s and `EC_ADD`'s fills,
   it has never executed on this branch, and it is 19.1 GiB / seconds of work.

**Should:**

5. **Raise `KECCAK_F` to 2^10.** §2.4 — the cheapest large win in the repository: 4× fewer
   shards of the family that is 96.77% of proof bytes and 41× the per-cell cost median.
6. **Isolate `EC_ADD`'s per-shard peak** — one 1-thread run settles S26c §7's open figure.
7. **One `APOGEE_DEBUG=deep:MOD_MUL` run over the mini-block**, to learn which of the four
   moduli a real workload reaches (§5.2).
8. **Re-run the cancelled suites**, now that the eight assertions are fixed — and note
   `prover::revm`'s `revm_params()` fix is untested.
9. **Give the debug log a region duration.** `block gkr region done` carries no `ms`
   (`phases.rs:311-336`), which is why §2.5's region figures are bounds rather than
   measurements. One field would fix it.
10. **Consider a shard-level `debug::Clock` that excludes stolen work**, or document §2.1 in
    `docs/spec/debug-info.md` — the log currently invites a two-order-of-magnitude
    misreading, and this stage nearly published one.

---

## 11. What one real full block would cost — an estimate, not a measurement

**Every figure here is [D] on top of the [M] anchors above. Nothing in this section has been
run.** It answers: *pin down `revm-block-stateless`, feed it recently-fetched mainnet blocks
— what does one proof need?* The band is wide on purpose, and §11.4 names the one cheap
experiment that collapses most of it.

### 11.1 The anchors, and the correction they force

| anchor | value | source |
| --- | --- | --- |
| base cycles, four real blocks, S26c-adjusted | **121M / 522M / 690M / 1,468M** | `S26-cycle.md` §4.1 [M] with the per-family baseline→mod-mul→S26c ratios [D] |
| MPT cost | **~3,170 guest cycles per trie node** | `S25-block.md:451-452` — 665,154 cycles over 210 nodes [M] |
| keccak per node | **2.786 permutations**, histogram {1:76, 2:6, 3:15, 4:113} | exact walk of `mini-block-nodes.bin` [M] |
| base `KECCAK_F`, block 26,059,700 | **24,879** invocations | `S26-block-26059700-mod-mul.json` [M] |
| of the mini-block's 1,080 `KECCAK_F` | **89.4% is `keccak256(code)`** in `WitnessDb::basic`, 10.6% EVM `SHA3`, **0% MPT** | Σ⌈(L+1)/136⌉ over the 12 recorded code blobs [M] |

**The correction this forces: the stateless binary adds little to *cycles* and a great deal to
`KECCAK_F`.** Every `keccak256` in the image is the S21 delegation, so MPT hashing becomes
`KECCAK_F` **rows**, not guest cycles — the guest pays only ecall plumbing, which the measured
3,170 cycles/node already includes. A model that prices MPT keccak at ~1,000 cycles per
permutation *on top of* that anchor double-counts. Cycles go up **~1.1–1.3×**; `KECCAK_F`
invocations go up **~7–13×**.

### 11.2 A typical 60 Mgas block

Node count is the dominant assumption: 16,000–37,000 trie nodes [A], from a trie-fill model
calibrated on the fixture's measured 210 nodes at 17 accounts.

| | typical (60 Mgas) | heavy |
| --- | --- | --- |
| guest cycles | 570M – 890M | ~1.5G – 1.6G |
| execution shards, 2^20 | 620 – 770 | ~1,620 |
| **`KECCAK_F` shards, 2^8** | **700 – 1,300** | 1,500 – 2,000 |
| `MOD_MUL` 2^16 / `EC_ADD` 2^16 | 1–5 / 1–3 | up to 10 / up to 4 |
| window + advice + fixed shards | ~40 – 60 | ~60 – 90 |
| **total shards** | **≈ 1,400 – 2,200** | ≈ 3,200 – 3,700 |
| serial shard work | **10 – 15 core-hours** | 20 – 28 |
| **proof size** | **8.4 – 15.5 GB** (97–99% `KECCAK_F`) | 18 – 24 GB |
| ↳ with `KECCAK_F` at 2^10 | **2.1 – 3.9 GB** | 4.5 – 6 GB |
| verification | 8 – 29 min | 20 – 60 min |
| stateless witness (advice) | 11 – 23 MB | 25 – 40 MB |

`MOD_MUL` and `EC_ADD` stay small, and one reason is worth stating: **senders arrive
pre-recovered**. `guests/revm-block/src/lib.rs:387-388` — *"`caller` is the sender, because
this VM has no `ecrecover` delegation"* — so a 450-tx block needs no in-circuit signature
recovery, and `EC_ADD` scales with contract-invoked `0x01`, not with tx count. That also
bounds what a full-block proof *means*: it proves state transition, **not** that the
transactions were validly signed. The 148-byte journal carries no signature commitment.

### 11.3 Where the wall clock goes — and a correction to an earlier draft of this section

**An earlier draft of this note claimed the commit phase is "strictly serial" and that going
12 → 192 workers buys only ~40% of wall clock. That was wrong**, and the error is worth
recording because it is easy to make from a grep alone.

What is actually serial, and what is not:

```
pass 1  (streaming.rs:158-172)   execution and commitment INTERLEAVE in one loop:
                                 a family's shard is flushed and committed the moment
                                 its buffer fills. No pipelining between the two.
  run.step()                     SERIAL — the emulator is single-threaded
  commit_chunks  for chunk       serial ACROSS shards
    memory_columns_of            SERIAL — crates/trace/src/memory.rs has no rayon at all
    commit_all  columns.par_iter()   PARALLEL over 21-392 columns...
      commit -> Mercury/KZG MSM      ...and each MSM parallelises again:
                                     msm.rs:241, chunks = current_num_threads()/windows
pass 2  (streaming.rs:358-386)   queue, then batches of max_in_flight proved with par_iter
```

So the **commit work is parallel**, inside the shard rather than across it, and
`streaming.rs:265-268` is right that an outer `par_iter` over shards *"would buy nothing but
a second shard's worth of peak"*: one add/sub shard is 27 columns of 2^20-point MSM, which
saturates 32 cores by itself. The serial residue is only **memory-column construction** —
O(height) writes, ~28M Fr per add/sub shard — plus the two single-threaded executions.

**The honest position: the construction/MSM split inside the commit phase has never been
measured**, so the commit term is a range, not a number. The one measurement is
`S25-mini-block.json`'s `phases.commit_ms = 131,661.7` over 37 shards = **3.56 s a shard at
rayon 6 on the M5 Pro** [M], which already contains whatever parallelism exists at 6 threads.
At 1,700 shards that is 1.7 h **if nothing in it scales**, which is an upper bound and was
mistakenly reported as the serial term.

| workers | pass-2 proving | commit (range) | 2× execution | **wall** | **$/proof** |
| --- | --- | --- | --- | --- | --- |
| 12 | 0.9 – 1.4 h | 0.4 – 1.7 h | 0.1 h | **1.4 – 3.2 h** | $3 – 7 |
| 32 | 0.35 – 0.5 h | 0.2 – 1.1 h | 0.1 h | **0.7 – 1.7 h** | $2 – 4 |
| 96 | 0.12 – 0.17 h | 0.1 – 0.7 h | 0.1 h | **0.3 – 1.0 h** | $2 – 7 |
| 192 | 0.06 – 0.09 h | 0.05 – 0.5 h | 0.1 h | **0.2 – 0.7 h** | $3 – 10 |

**More cores do help.** How much depends entirely on the unmeasured split: at the optimistic
end the commit phase is MSM-dominated and scales with the pool; at the pessimistic end it is
construction-dominated and does not. Either way the earlier claim that hardware is nearly
worthless here does not hold.

Two consequences survive the correction, and one dies:
- **Survives:** parallelising `crates/trace/src/memory.rs`'s column construction is still a
  real win, because that part genuinely does not scale. It is just smaller than claimed.
- **Survives:** an outer `par_iter` over shards in `commit_chunks` is still the *wrong* fix —
  `streaming.rs:265-268`'s reasoning is sound.
- **Dies:** "commit-bound, so the `r8i.8xlarge` is cost-optimal and a bigger box is wasted."
  A bigger box plausibly halves wall clock from 32 to 96 workers.

Memory is not the constraint once streaming is used: peak is `base + in-flight × marginal`
= ~30 GiB + 16 × 6.26–10.16 GiB ≈ **130–193 GiB**, inside 247 GiB. Budget `EC_ADD` at a
**planning ~31 GiB** a shard, not the computed 20.5 GB — `metrics.md:253` records this class
of model running at 62% of measured. The **archived** path needs 60–180 GB resident for a
typical block and 660–819 GB for a heavy one, so **streaming is mandatory, not preferred**.

### 11.4 The band is 3–4× and one run collapses it

The spread above is almost entirely the **`KECCAK_F` shard count under
`revm-block-stateless`**, which sets proof size, verification time and a third of the cost.
Every measured `KECCAK_F` number in this repository comes from `Mode::Mini`
(`tools/profiler/src/main.rs:254` hardcodes it), **which performs no MPT work at all**.

> **One `cargo run --release -p profiler -- record <block>` against the stateless binary
> closes it.** Minutes of work, no proving, no AWS. Nothing else in this section is worth
> refining first.

Second weakest: **the construction/MSM split inside the commit phase** (§11.3) — it decides
whether a bigger box halves the wall clock or barely moves it, and
`global_commit_phase_metered` already exists to time it. Third: `EC_ADD`'s per-shard peak,
which decides the box (§6). Fourth: the 92.43 GiB `/proc` reading, sole anchor of both memory
fits (§3).

And two blockers remain upstream of all of it, from §4: `revm-block` is the wrong binary, and
no real full-block witness can be recorded while `eth_getProof` cannot return a collapsing
deletion's sibling.
