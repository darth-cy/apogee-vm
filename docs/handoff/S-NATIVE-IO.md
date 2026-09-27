# S-NATIVE-IO — the native I/O model, and the deletion of POSIX and QEMU

**This stage takes no number, and that is deliberate** — the same reading as `S-IO`, and
for the same reason. It is not one of the original twenty-seven. S-IO built the mechanism
that binds an execution's inputs and outputs (`docs/spec/public-values.md`) but left the
POSIX surface standing beside it, on the grounds that a second executor needed something
to watch. This stage removes the surface and the second executor together.

One sentence carries the whole change:

> **An Apogee guest is an Apogee-SDK program, not a generic Linux/POSIX RISC-V
> executable.** It has no file descriptors, no streams and no I/O syscall. Its public
> input, its advice and its journal are three fixed regions of memory reached with
> ordinary loads and stores, and the only ecalls it issues are `EXIT` and a delegation
> number.

---

## 1. Why, and what it cost

S-IO already knew `read` (63) and `write` (64) were not provable, and said so: "a guest
that takes this path is not a guest that can be proven." It kept them anyway, because
`crates/emulator/tests/qemu_outputs.rs` held this emulator's exit status and fd 1 bytes
against `qemu-riscv32`, and that oracle needed a stream to read.

That is the trade this stage refuses. Keeping the oracle meant keeping a second,
unprovable input and output path in the VM *for the oracle's sake*, forever — a guest
was provable or QEMU-runnable and never both, which made half the `guests/` tree
unprovable by construction and cost `guests/revm-block` a whole second binary. The
master prompt's frozen-invariant preamble names that failure mode exactly: "a name that
no longer says what the thing is, or a structure bent so the old invariant stays
technically true — paying complexity forever to avoid saying that an earlier decision
was superseded."

**The price, stated plainly.** Master implementation rule 10's emulator clause is
withdrawn: there is no second executor and no cross-implementation check on what a guest
computes. What holds a trace to this VM's own semantics is
`crates/emulator/tests/trace.rs`, `crates/trace`'s log self-check, `crates/checker`'s
multiset and memory suites and each family's row suite — all of which run in
`cargo test --workspace` with nothing to install, and none of which is an independent
implementation. Two further losses are recorded in §7 rather than papered over.

The owner's instruction was explicit and is recorded here: *"THIS IS A NUCLEAR
MODIFICATION WHERE WE SIMPLY REMOVE QEMU'S INFLUENCE ON THE REPO ALL TOGETHER. ERASE ITS
EXISTENCE. IN THE FUTURE, ONLY OUR OWN NATIVE I/O SCHEME IS CANONICAL."*

---

## 2. The frozen API

```rust
// crates/guest-sdk — the whole guest-facing surface.
guest_sdk::entry!(main);
pub fn public_input() -> &'static [u8];      // verifier-bound, <= 1020 bytes
pub fn read_input(buf: &mut [u8]) -> usize;  // the same, copied
pub fn commit(bytes: &[u8]);                 // the verifier-bound journal
pub fn journal() -> &'static [u8];
pub fn advice() -> &'static [u8];            // prover-supplied; NOTHING binds it
pub fn exit(code: i32) -> !;
pub fn keccak256(input: &[u8]) -> [u8; 32];
pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool;
pub mod recursion { /* poseidon2, fr_arith, mod_mul frames — unchanged */ }

// crates/emulator
pub struct GuestIo { pub input: Vec<u8>, pub advice: Vec<u8> }
pub struct Execution { pub regs: [u32; 32], pub exit_code: i32,
                       pub cycle_count: u64, pub io: IoStreams }
```

**Deleted, with no replacement and no shim:** `read_stdin`, `write_stdout`, `hint`,
`log`, `read_fd`, `write_fd`, `ecall3`, the `Diagnostics` `fmt::Write` sink;
`GuestIo::{stdin, hint}`; `Execution::{stdout, stderr}`; `Machine::transfer` and every
transfer cycle; `ecall::{READ, WRITE, FD_STDIN, FD_STDOUT, FD_STDERR, FD_HINT, EBADF}`.

**`ENOSYS` (38) survives** because it was never part of that layer: it is the delegation
ABI's "this executor has no circuit" answer (`docs/spec/delegation.md` §2), which every
shim checks so a caller can take its software path.

**63 and 64 are retired and burned.** Append-only forbids giving a number a second
meaning; it does not forbid deleting a call nothing may issue. Neither number may ever
be reassigned.

---

## 3. A panicking guest is now provable

`#[panic_handler]` is a bare `exit(EXIT_PANIC)` and writes nothing. It used to format
the `PanicInfo` out on fd 2 through `write`, which was not a provable ecall, so **every
panicking execution was one no proof could cover** — `docs/spec/public-values.md` §9
said so. That restriction is gone, and §9 is reversed.

The cost is that a panic says nothing about why. Routing the message into the journal
was considered and refused: it would break `exit` publishing nothing, and a guest's last
act before dying would rewrite what it had already committed.

---

## 4. The circuit changed: ADD_SUB_LUI_AUIPC's frame is five queries

This is the part that reaches the arithmetization, and it is a consequence rather than a
goal. `arg1` and `arg2` were an ecall row's `a1` and `a2`, which only `read` and `write`
ever passed; add/sub's `ram` query was the **transfer row's** alone, no instruction
routed to that family touching memory. All three became unreachable the moment those
calls did.

The query table is seven entries, not nine:

```text
old  [pc, rs1, rs2, arg1, arg2, load, ram, rd, deleg]   ids 0..8, rd = 7, deleg = 8
new  [pc, rs1, rs2, load, ram, rd, deleg]               ids 0..6, rd = 5, deleg = 6
```

`frame_queries(ADD_SUB_LUI_AUIPC)` is `[PC, RS1, RS2, RD, DELEG]`. No other family's
query list moved. Measured consequences:

| | before | after |
| --- | --- | --- |
| `w`, the frame width | 8 | **5** |
| `M` columns (`1 + 5w`, `+1` for `deleg_space`) | 42 | **27** |
| `W` columns, the frame's own (`w + 3`) | 11 | **8** |
| timestamp obligations (`2w`) | 16 | **10** |
| product-tree leaves a side | 8, no pad | **8** — five queries and **three** literal-1 pads |
| frame enforcing gates | 16 | **11** |
| layer-1 width | 100 | **68** = 16 + 32 + 16 + 4 |
| first multiplicity column | `W[33]` | **`W[30]`** |

Gates deleted by name: `arg1_mask_rule`, `arg2_mask_rule`, `ram_mask_rule` — each was
`mask == 0`, so **the family already forbade these three queries outright** and the
columns proved nothing. With them go `arg1_mask_boolean`, `arg2_mask_boolean`,
`ram_mask_boolean`, `arg1_writes_back`, `arg2_writes_back`, and the `arg1_gap_hi`,
`arg2_gap_hi` and `ram_gap_hi` witness columns. `prover::fill::add_sub`'s "is an ecall's
transfer cycle" refusal is deleted with the concept.

**Three tamper cases became unrepresentable and were removed rather than weakened**
(`crates/checker/tests/add_sub.rs`, `crates/checker/tests/tamper.rs`): an exit row
reading `a1` or `a2`, and a live or padding row of this family storing a word. There is
no column for the forgery to live in, which is a stronger refusal than a gate.

`crates/trace/tests/memory.rs` holds `frame_queries` equal to the union of the family's
instructions' queries over all 59 of them; it passes on the five-query frame, which is
the check that says the narrowing is exact and not merely smaller.

**`Role::Arg1` and `Role::Arg2` are deleted**, so `trace::ROLES` is six long and
`Row::present` has two spare bits again. `crates/trace/src/archive.rs`'s refusal of a
present mask naming a role that does not exist was **unreachable** from S21 until now —
the mask was full — and is restored, with a negative control beside the delegation one.

---

## 5. What was deleted from the tree

| Path | Why |
| --- | --- |
| `crates/emulator/tests/qemu_outputs.rs` | the output oracle; its comparison surface was fd 1 |
| `crates/loader/tests/qemu.rs` | ran the guests under `qemu-riscv32` |
| `crates/emulator/tests/consistency.rs` | the three-way host/QEMU/emulator suite |
| `guests/consistency/` | its guest, ~14k lines; the corpus wrote 7,627–19,705 bytes to fd 1 and a journal holds 1,020 |
| `guests/revm-block/src/stdio.rs` | the `revm-block-stdio` binary, which existed only for executors with no advice region |
| `.github/workflows/ci.yml` | the `qemu-user` install and all four QEMU steps |
| `guests/.cargo/config.toml` | `runner = "qemu-riscv32"` |

Deleting `guests/consistency` cost one thing beyond the suite: it was the guest
`crates/program/tests/partition.rs` used to prove `TableTooShort` fires.
`guests/mod-mul-ops` reaches pc `0x21d3a` and serves the same purpose; the control is
re-pointed at it and at `ADD_SUB_LUI_AUIPC`, and `mod-mul-ops` was already the second
committed guest needing a `2^18` table, so the tall-table path keeps its coverage.

---

## 6. Every guest is an Apogee-SDK program

All 21 guests were ported and every committed ELF regenerated. Input that was fd 0 is
`public_input()` where it is genuinely the statement's input, and `advice()` where it is
bulk the guest authenticates; output that was fd 1 is `commit()`; fd 2 is gone with no
replacement; fd 3 is `advice()`. Exit statuses are unchanged — `addsub` 42, `control`
16, `alu` 96, `mem` 50, `shards` 2, `keccak-test` 6, `recursion-ops` 9, `mod-mul-ops` 12,
`keccak-unused` 7, `recursion-unused` 11 — and every guest's declaration record set is
unchanged, so `DECLARING_GUESTS` and static detachment are untouched.

Three ports are worth reading before writing a guest:

- **`guests/vault`** — its withdrawal records are 19,688 bytes at the format's limits and
  a public window holds 1,020, so they are **advice**. That is sound because a Merkle path
  authenticates itself against a running root whose start is the public input; the module
  doc now states plainly what the prover still chooses (which valid leaves the batch
  touches) and that the statement is therefore existential.
- **`guests/orderbook`** — the permutation was fd 3 and is now advice, and "no
  permutation" is expressible as a four-byte region with a zero length word.
- **`guests/opcodes`** — `cover_ecall`'s `read`/`write`/`-EBADF` block is deleted. The
  `ecall` *instruction* is still covered by the two unassigned-number calls that were
  already there; a delegation number was deliberately **not** used, because that would
  put a delegation family in the image and move `DECLARING_GUESTS`.

**`advice()` on a run given no advice region is a fatal `OutOfBounds`**, which is the
SDK's stated contract, so `echo`, `orderbook` and `vault` now require an advice region —
possibly of zero length — to run at all.

---

## 7. Two coverage losses, recorded

1. **The allocator's heap-ceiling rule is asserted and exercised nowhere.** Its two
   probes lived in `guests/consistency`. `guests/heap` churns the allocator but never
   fills it, so nothing now reaches the `exit(71)` ceiling — neither the
   `__stack_top - STACK_RESERVE` half nor the live-`sp` half. The rule is unchanged in
   `crates/guest-sdk/src/lib.rs`; only its test is gone.
2. **`guests/echo`'s in-guest Poseidon2 comparison is vacuous, and was already.** It
   compares `guest_sdk::poseidon2_permute` against `transcript::poseidon2_permute`, and
   since S23 the latter delegates on `riscv32` too — so both sides are the same ecall.
   This predates the stage; what the stage changed is that `crates/emulator/CLAUDE.md`
   no longer claims the property. It lives in `recursion-ops`, which re-derives the state
   from the crate.

---

## 8. Documents amended

`prompts/00-master.md` — **with the owner's explicit authorization**, this stage being
the one that made three of its statements false. Implementation rule 10's emulator
clause is withdrawn; rule 2 no longer lists QEMU as a reference oracle; the *Guest
target* frozen invariant loses "= Linux RISC-V syscall convention … so qemu-riscv32 runs
guests unmodified"; the *Public values and advice* invariant records that the fd API is
deleted rather than wrapped, and that a panicking guest is provable. Each amendment
carries what it replaced, as the frozen-invariants preamble requires.

Normative specs rewritten: `docs/spec/ecall-abi.md` (the table, and §7's memory-map
rationale), `docs/spec/public-values.md` (§1 and §9), `docs/spec/execution-trace.md` (the
seven-role query table; the transfer-cycle rules deleted),
`docs/spec/constraint-manifest.md` §3, and `docs/guest-program-manual.md`. Every
per-crate `CLAUDE.md` and the root `CLAUDE.md`.

---

## 9. Fixtures

Regenerated with `cargo run -p kat-gen -- guests` on one machine, then
`cargo run -p kat-gen`: all 20 committed guest ELFs and the pinned digests of the
nineteen that carry one,
the loader/isa/program vectors, every family circuit artifact (`add_sub.bin` moved, as
did `memory_frame_alu.bin`), the global transcript tape, and S24's revm vectors. The
add/sub frame's fixture digest and `crates/checker/tests/add_sub.rs`'s `FIXTURE_SHA256`
moved with the circuit.

**Every S16-and-later verifying key's bytes changed**, because the add/sub circuit is in
the registry the key is built from. Identity is unaffected — it binds the program, not
its circuit — and the SRS digest is unaffected, the packed generic table not having
moved.

`crates/loader/tests/vectors/consistency.elf` went with its guest. Four **derived**
fixtures needed their pins refreshed and did not get them in the first pass, because
`committed_fixtures_match_their_pins` asserts in a loop and reports only the first
mismatch: `fib.objdump.txt`, `rvc-dense.objdump.txt`, `amm.objdump.txt` and
`rvc-dense.nm.txt`, plus `fib_io.txt`'s standalone digest in `differential.rs`.

**One gap here predates this stage and is left open**: `mod-mul-ops.elf` is a committed
fixture with no entry in `PINS`, though `PINS`' own doc comment says it holds *every*
committed fixture. S26 added the guest and the pin never followed. Nothing enumerates
the vectors directory, so neither the missing pin nor the orphan `consistency.elf` was
caught by a test — the same absent both-directions check in both cases.

---

## 10. What this stage owes

### The gates that are green

`cargo fmt --all -- --check` over all four workspaces; `cargo clippy --workspace
--all-targets -- -D warnings`; `cargo clippy -p prover --all-targets --features metrics`;
guest-sdk's clippy on `riscv32imac-unknown-none-elf`; `cd guests && cargo clippy --bins`;
transcript-ref's clippy; the no_std guest-target build of the eight crates; and
`cargo run -p kat-gen` followed by a clean regenerate-and-diff over the twelve vector
directories.

Marker counts after the change: **1,101 `#[test]` functions, 67 of them `#[ignore]`d,
1,034 run by a plain `cargo test --workspace`**. The line above the command block in the
root `CLAUDE.md` said 1,065 and 54 and was already stale before this stage; it now reads
the counts above.

### What is owed

**1. The thirteen `# DEFERRED` suites have not been run.** This is the debt that matters,
and it is larger here than at an ordinary stage: the add/sub family's frame went from
eight queries to five, so **every S16-and-later verifying key's bytes moved**, and every
deferred suite proves against one. They are owed a batch run under the root `CLAUDE.md`'s
rule — once, at the end of the progression, no further commits expected — and several
will need numbers re-measured rather than merely re-confirmed:

| Suite | What this stage is expected to have moved |
| --- | --- |
| `checker --test tamper` (release) | Seven statements, each re-proved per twin. Three add/sub tamper cases became *unrepresentable* when the `arg1`/`arg2`/`ram` columns left the frame, and one — the exit row storing a word — was deleted outright. The pinned 4231 s will fall. |
| `prover --test acceptance`, `verifier --test cli` | S16's statement on the narrower frame. Peak and wall clock both expected down. |
| `prover --test control`, `alu`, `mem` | Unchanged circuits, but their keys' bytes moved. |
| `prover --test block`, `streaming`, `keccak`, `recursion`, `revm` | Shard counts are pinned in these suites' assertions and in the command block's comments. S-IO added two shards to every statement; this stage removes none, but the pinned figures were taken before it. |
| `prover --test public_io` | S-IO's statement, and the one that exercises the three regions directly. |
| `host --test prove` | S25's mini-block gate, and the advice tamper twin. |
| `prover --features metrics --test metrics` | Prints both reports; its two figures are quoted in `docs/spec/metrics.md`. |

**2. The full `cargo test --workspace` run is left to CI**, under the master's Test
discipline rules 3 and 6-8 as amended at the close of this stage. Three local attempts
each died at a different stale literal, and each cost three quarters of an hour to buy
one bit; the fourth was replaced by a **static audit** of the suites that had never
executed, which is what the amended rules now require.

That audit is worth recording, because it is the method this stage recommends for a
change of this shape. Of 165 test binaries, 48 had never executed against the change —
every truncated run died before reaching them. Rather than run them, each was read
against the change and every candidate finding independently checked by a second reader
told to refute it. It confirmed **19** stale assertions, nine of them in suites that run
in CI and seven in `#[ignore]`d suites no workspace run would ever reach. Running the
scoped suites the audit pointed at then found **three more** it had missed, each a
downstream consequence of a width it *had* found — which is the honest summary of what a
static audit is for: it narrows where to look, it does not replace looking.

The sharpest finding is worth naming, because it would have survived review. `Role` has
no explicit discriminants, so deleting `Arg1` and `Arg2` silently renumbered `Rd` from 6
to 4 — and `crates/trace/src/archive.rs`'s tamper case went on poking slot 6, which is
now a spare no role names and nothing reads. `import` returned `Ok`, and the case's
`unwrap_err()` would have panicked. A deletion that reads as a pure deletion was a
renumbering.

**CI is green on `16238fc`**, the commit that closes this stage: 192 suites, **1,042
passed, 0 failed**, over fmt, clippy (including the one feature's configuration), the
`riscv32imac` guest-target build, the guest workspace's own clippy, `cargo test
--workspace` and the regenerate-and-diff gate. That is the tally this section owed. The
two commits before it are red in CI for exactly the assertions repaired here, and the
first of them died at `program --test tables` and stopped — CI is fail-fast too, so
finding the other eighteen that way would have taken eighteen more pushes.

Green locally as well, each run scoped to what changed:
`cargo fmt --all -- --check` over all four workspaces, `cargo clippy --workspace
--all-targets -- -D warnings`, `cargo test -p trace --lib`, `-p verifier-core` (26
tests), `-p program --test tables` (14), `-p program --test delegation`,
`-p loader --test differential`, and `cargo check -p prover --all-targets`.

**3. Two coverage losses stand** and are argued in §7 rather than repaid — there is no
second executor to disagree with this one, and no test replaces what the QEMU output
oracle observed. §7 is the honest version of what that costs and why it was the owner's
call to accept it.

**4. `mod-mul-ops.elf` has no pin** (§9). Pre-existing, one tuple, left for the owner.
