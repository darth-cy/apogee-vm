# apogee-vm

A RISC-V zkVM proving RV32IMAC guest programs, arithmetized as GKR circuit families
over the BN254 scalar field Fr, proven with gate-based sumcheck, committed with the
Mercury multilinear PCS, transcripted with Poseidon2. No FRI anywhere. The full
specification, the frozen protocol invariants, the effort budget and the anti-goals
live in `prompts/00-master.md` — **read it before writing code**, along with the stage
prompt you are working on.

## Where things are
```
.github/         CI: fmt, clippy, tests, guest build, fixture regenerate-and-diff
prompts/         00-master.md (design authority) + one prompt per build stage
docs/
  GLOSSARY.md    the vocabulary (column = multilinear = poly; layer; shard; family)
  guest-program-manual.md  writing a guest and exporting its ProgramImage artifact
  spec/          the frozen protocol specs; read before touching what they cover
  handoff/       one note per completed stage: frozen API, artifacts, deviations
crates/
  constants/     frozen constants and tags; zero logic; no_std
  field/         Fr arithmetic (Montgomery); no_std
  curve/         Fq tower through Fq12 + G1/G2 + the optimal ate pairing + Pippenger MSM; std
  transcript/    Poseidon2 permutation + duplex transcript; no_std
  poly/          MultilinearPoly + small-type backing + eq machinery; no_std
  sumcheck/      Gate + zerocheck prover/verifier; no_std
  srs/           snarkjs .ptau ingestion, the SRS archive, univariate KZG; std
  pcs/           Mercury commit/open/verify, RLC batching, deferred pairings
                 and the accumulator, plus the typed G1 absorption; std
  loader/        ELF parsing, RVC expansion, ProgramImage; std
  isa/           the RV32IMAC instruction model and the 32-bit decoder; no deps
  program/       decoded per-family tables, VmConfig derivation, program identity; std
  trace/         the memory event log and its self-check, the family buffers, the cycle
                 profile and shard plan, and the TraceArchive snapshot; std
  emulator/      the RV32IMAC reference emulator, its tracing path, and the QEMU
                 differential harness; std
  guest-sdk/     crt0, entry!, linker script, bump allocator, ecall shims; no_std,
                 guest-only, and NOT a workspace member
guests/          fib/, echo/, rvc-dense/, amm/, orderbook/, vault/, atomics/, opcodes/, heap/, consistency/
                 -- their own workspace; see guests/Cargo.toml and docs/guest-program-manual.md
assets/          gitignored: the PSE powers-of-tau ceremony files; see the S07 handoff
tools/
  kat-gen/       regenerates the committed Fr, multilinear, curve, MSM, SRS and G1-absorption
                 vectors from arkworks, the Mercury proof fixture from `pcs` itself, the ISA
                 corpus via llvm-objdump, and the identity pin from `program` itself
  bench/         one routine per measurement, individually selectable
  artifact-dump/ a guest ELF out as the frozen ProgramImage artifact, plus a
                 readable report of it; `tables` prints the decoded tables and identity
  transcript-ref/ the transcript oracle: Plonky3 + zkhash, NOT a workspace member
  test-support/  seeded RNG, SHA-256, hex; shared by every suite and generator
```
Later stages add the crates listed in the master prompt's workspace layout. Crate names
are frozen; internals are not.

## Build stage protocol
Read `prompts/00-master.md`, then the stage prompt, then every prior note in
`docs/handoff/`. Branch off `main`, commit on the branch, open a PR, and finish by
writing `docs/handoff/<stage>.md` and updating this file. Raise conflicts and
open questions with the user rather than picking a default silently.

## Commands
Everything above the line is what CI runs (`.github/workflows/ci.yml`); a green local
run of these is a green CI run.
```
cargo fmt --all -- --check
cargo fmt --manifest-path tools/transcript-ref/Cargo.toml --all -- --check
cargo fmt --manifest-path crates/guest-sdk/Cargo.toml --all -- --check
cargo fmt --manifest-path guests/Cargo.toml --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --manifest-path tools/transcript-ref/Cargo.toml --all-targets -- -D warnings
(cd crates/guest-sdk && cargo clippy --target riscv32imac-unknown-none-elf -- -D warnings)
(cd guests && cargo clippy --bins -- -D warnings)
cargo test --workspace                      # 495 tests as of S12; 20 more are #[ignore]d
cargo build -p field -p constants -p transcript -p poly -p sumcheck --target riscv32imac-unknown-none-elf
cargo run -p kat-gen
cargo run --manifest-path tools/transcript-ref/Cargo.toml
cd guests/fib && cargo build --target riscv32imac-unknown-none-elf
APOGEE_GUEST_PROFILE=release cargo test -p loader --test qemu -- --include-ignored
cargo test -p emulator --test differential -- --include-ignored
cargo test -p emulator --test consistency -- --include-ignored   # and again at APOGEE_GUEST_PROFILE=release
git diff --exit-code -- crates/field/tests/vectors/ crates/transcript/tests/vectors/ crates/poly/tests/vectors/ crates/curve/tests/vectors/ crates/srs/tests/vectors/ crates/pcs/tests/vectors/ crates/loader/tests/vectors/ crates/isa/tests/vectors/ crates/program/tests/vectors/
-------------------------------------------------------------------------------
cargo run -p kat-gen                        # refresh every fixture (manual, deliberate)
cargo run -p kat-gen -- <group>             # just one: field | poly | curve | tower | pairing | msm | srs | pcs | loader | isa | program
cargo run -p kat-gen -- guests              # rebuild the guest ELFs; opt-in, one machine
cargo run --manifest-path tools/transcript-ref/Cargo.toml   # ditto, transcript vectors
cargo run --release -p bench                # every routine; internal numbers only
cargo run --release -p bench -- --list      # the routines, and what each measures
cargo run --release -p bench -- <routine>   # just that one; setup is per-routine

cargo run -p artifact-dump -- <guest.elf> [--out <dir>]   # export a ProgramImage
cargo run --release -p artifact-dump -- tables <guest.elf> [--ptau <file>]   # decoded tables, identity
cargo test --release -p program --test identity -- --ignored   # identity; needs the ceremony file
```

`artifact-dump` writes `<name>.img` — the frozen `postcard` wire form, with no
header of its own, which is the artifact later stages read — and `<name>.img.txt`,
a report of that artifact with the full instruction listing.
`docs/guest-program-manual.md` walks the whole path from an empty crate to those
two files, and `tools/artifact-dump/tests/manual.rs` *runs* that walkthrough on
every crate in `guests/Cargo.toml`'s member list, reading the list from the
manifest so a guest that exists is a guest whose walkthrough is checked.

`tools/transcript-ref` is deliberately outside the cargo workspace, so it takes
`--manifest-path` rather than `-p`. Its Plonky3 and `zkhash` dependencies would otherwise
feature-unify `serde/std` into `crates/field` during `cargo test --workspace`.
`crates/guest-sdk` and `guests/` are outside it for a different reason: they compile only
for `riscv32imac-unknown-none-elf` and link a `#[panic_handler]`. Guests are built from
their own directory, where `guests/.cargo/config.toml` supplies the target, the runner and
the pinned linker flags.
The toolchain, its components and the guest target come from `rust-toolchain.toml`. CI
does not name a version anywhere, so it cannot drift from that pin. `llvm-tools` is one of
those components: `kat-gen -- loader` disassembles the committed guest ELFs with it, so
the disassembler is pinned to the same LLVM as the compiler.

`qemu-riscv32` runs the guests; it was the only executor before S12, and since S12 it is the
oracle `crates/emulator/tests/differential.rs` holds the emulator's trace to. It is user-mode
emulation: it translates Linux syscalls into host ones, so it builds for Linux hosts only
and no macOS build of it exists. That is a claim about *native* builds — a Linux VM is an
ordinary arrangement and the suite runs fine inside one. The tests stay `#[ignore]`d so a
machine with no emulator cannot report silent coverage, and CI asks for them by name:

```
cargo test -p loader --test qemu -- --include-ignored   # a Linux host with qemu-user
cargo test -p loader --test layout -- --ignored         # after editing link.ld

APOGEE_GUEST_PROFILE=release \
  cargo test -p loader --test qemu -- --include-ignored   # the same eight, optimised
```

**Guests build at `--release` too, and both profiles are pinned.** In a zkVM
instruction count is proving cost, and `opt-level = 3` removes 24% to 58% of the image
across the guests. Cargo's default release profile would also turn `overflow-checks`
off, which is not a performance setting here: `u32::MAX + 1` then commits `00000000` on
fd 1 where the dev build panics and exits 101, and fd 1 is the *committed public output*.
So `guests/Cargo.toml` pins both profiles to the same semantics — they differ only in
`opt-level` — and CI runs `tests/qemu.rs` twice, once per profile, to hold that.

On macOS that costs about four minutes of setup, once:

```
brew install colima docker && colima start --cpu 4 --memory 8 --disk 60
docker run --rm -v "$PWD":/w -w /w -e CARGO_TARGET_DIR=/tmp/t rust:latest \
  bash -c 'apt-get update -qq && apt-get install -y -qq qemu-user &&
           cargo test -p loader --test qemu -- --include-ignored'
```

`CARGO_TARGET_DIR` is not optional there: cargo does not namespace `target/` by host
triple, so sharing it with the macOS build makes each run rebuild over the other. The
guests built inside the container differ in bytes from the committed fixtures — rustc
embeds absolute paths in panic-location strings — which is why `qemu.rs` builds every
guest from source rather than reading a fixture.

What that suite would have caught about the *image* is also covered by `crates/loader/
tests/layout.rs`, which reads the program headers and runs everywhere.

## The rules that bite most often
- **Concrete types.** `Fr` is a struct. There is no `F: Field`, and there never will be.
- **No cargo features. Zero.** One build configuration for the whole workspace.
- **One encoding.** Field elements on the wire are canonical (non-Montgomery) 32-byte
  little-endian. Montgomery form exists only in memory. Source literals are the one
  exception and are their own single form: `Fr::from_hex`, `0x` plus 64 lowercase digits,
  big-endian, because a constant in source is a number and should diff against upstream.
- **Fq is not Fr.** `Fr` is the scalar field everything is arithmetized over; `Fq` is the
  base field curve coordinates live in. The moduli agree in their top 128 bits. `curve::Fq`
  is a deliberate literal duplicate of `field::Fr`'s Montgomery kernel, not an abstraction
  over it, and `curve::g2` is a literal mirror of `curve::g1`.
- **The pairing is the exact power.** `final_exponentiation` returns `f^((q^12-1)/r)` and
  never a fixed multiple of it, so the Fuentes-Castañeda hard part is out — which also
  means arkworks' own `Bn254::pairing` is *not* a drop-in oracle, and the fixtures raise
  its Miller output to the literal exponent instead.
- **Points on the wire are uncompressed affine.** 64 bytes `x ‖ y` for G1, 128 bytes
  `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1` for G2, each coordinate canonical 32-byte LE, all-zero for
  infinity. No compressed form, no decompression, ever. A point's *transcript* form is a
  different thing: four ~128-bit Fr limbs. Those limbs are frozen in S08: `x` low,
  `x` high, `y` low, `y` high, split at 128 bits, with infinity absorbing four copies of
  `constants::G1_INFINITY_SENTINEL` = `2^128` — a value no real limb can take.
  `pcs::append_g1_list` is **one** message of `4k` limbs, never `k` messages.
- **One index convention.** Variable `j` is bit `j`: the evaluation at `y` sits at
  `index = sum_j y_j 2^j`, and `bind` fixes variable 0, the low bit. Frozen in
  `crates/poly` and load-bearing for every later circuit stage. Sumcheck round `i`
  binds variable `i`, so a claim's point reads in that same order.
- **`u1` is the FIRST half of a Mercury opening point.** `n = 2^{2t}`, `b = 2^t`, and the
  evaluation at index `i + j·b` is the coefficient of `X^{i+j·b}` with `i` the low `t`
  bits. `u1 = u_0..u_{t-1}` pairs with `i`; `u2` pairs with `j`. This is the #1
  integration bug and the verifier rejects a swapped pair. `docs/spec/mercury.md` §2.
- **A Mercury commitment IS a plain KZG commitment** of the evaluation table read as
  coefficients — exact equality, no second scheme. Trace heights are *even* powers of two
  so that `b = sqrt(n)` exists, which is where the height menu comes from.
- **A batch is one instance, not `k` of them.** `pcs::batch_open` opens `k` same-size
  columns at ONE point by squeezing `rho` *after* every commitment and every claimed value
  is absorbed, then opening `cm* = Σ ρ^i cm_i` once. Column `i` carries `ρ^i`, so index 0
  carries 1 and reordering the list is a different statement. The proof is one 704-byte
  `MercuryProof` however large `k` is. `docs/spec/mercury.md` §11. A `k=1` batch is **not**
  the same transcript as a bare single opening and the two are not interchangeable.
- **`AccumulatorEntry` and `PairingSide` are frozen forever.** A deferred Mercury
  verification emits exactly 12 entries — `cm`, the 8 proof points in field order, `[1]_1`,
  then the two `G2X` terms — each six canonical Fr words and 192 bytes. Groups are
  per deferred check, carried as a count word on the wire and as the `checks: &[usize]`
  argument in memory. Entry lists are **concatenated, never combined**; `discharge` weights
  each check by a power of a challenge drawn from the accumulator's own digest, and that
  weight is load-bearing — without it two checks can cancel each other's errors.
  `docs/spec/accumulator.md`. `ShardProof` and `BlockProof` carry no entries.
- **`discharge` validates every accumulator point.** Nobody upstream does: absorption binds
  claimed limbs, and the in-VM replay does no curve math. One rule, `docs/spec/accumulator.md`
  §4, cited rather than restated.
- **Fixed proof shapes.** A sumcheck round message is 4 coefficients, always — the
  degree ceiling makes the round polynomial a cubic, and nothing in a proof has a
  data-dependent length.
- **One tag, one message kind.** The transcript frames typed messages as
  `tag, length, payload`, so a tag in `constants::transcript_tags` must name exactly one
  of scalars, bytes or a challenge. Reusing one across kinds is a soundness bug.
- **The ceremony is PSE's, not Hermez's.** `ppot_0080_<power>.ptau` from PSE's perpetual
  powers of tau, contribution 80, and nothing else. Hermez's `powersOfTau28_hez_final_*`
  is a *different ceremony with a different `tau`*: the two are not interchangeable, and
  swapping one in silently gives a correct-looking SRS whose committed fixtures do not
  match. `docs/spec/srs.md` §2.0.
- **`.ptau` points are little-endian *Montgomery*.** The one file format here that is
  not canonical: a ceremony file stores `coord * R mod q`, because that is
  ffjavascript's in-memory layout written straight out. `crates/srs` multiplies by
  `R^-1` and hands canonical bytes to S05's `from_bytes`, so there is still exactly one
  validating decoder.
- **SRS integrity is presumed; there is no SRS digest.** S07's Poseidon2 digest over the
  SRS was dropped on instruction, so the master's statement-binding item `SRS digest`
  has no implementation and nothing binds a proof to a particular SRS. Read
  `docs/spec/srs.md` §4 before building statement binding.
- **A guest ELF must satisfy two loaders, not one.** The zkVM makes the whole RAM window
  addressable by construction, so `crates/loader` only ever reads `p_vaddr` and `p_memsz`.
  A *host* loader — `qemu-riscv32`, the only executor before S12 — maps just the `PT_LOAD`s
  the headers declare, page by page, at the declared permissions. So `link.ld` reserves
  `__heap_start .. __stack_top` as one writable `NOBITS` segment reaching the top of RAM,
  and page-aligns every section: an undeclared stack is unmapped memory whose first push
  faults, and two segments sharing a page take the second mapping's permissions for all of
  it. S10 shipped both bugs and QEMU is what found them. `docs/spec/ecall-abi.md` §7.1;
  `crates/loader/tests/layout.rs` pins it without needing an emulator.
- **Addresses are never compacted.** RVC expansion changes representation, not layout: a
  `c.addi` at `0x1002` stays at `0x1002` and occupies two bytes. `ProgramImage.slots` is
  therefore pc/2-indexed, and `Slot::Instruction`'s `compressed` flag *is* the
  instruction's length — the only thing that says whether the next pc is `pc + 2` or
  `pc + 4`. Compacting would shift every later address and change S11's program identity
  for a program that did not change.
- **The all-zero halfword is not code, and not a refusal.** RVC's *defined*-illegal
  encoding gets a `Slot::NonInstruction` and the sweep resumes two bytes later; reaching
  it is a run-time trap, which is the executor's business, and a loader cannot know
  whether any pc does. This is not a corner case. rustc's RISC-V target sets
  `TrapUnreachable`, so at the guests' `opt-level = 0` every LLVM `unreachable` block
  becomes a real `unimp`, and with the C extension that assembles to exactly this
  halfword — an exhaustive three-arm `match`, any `core::sync::atomic` operation, a
  `for i in 0..n` with a signed counter, `slice::sort_unstable_by` and `field::Fr::inverse`
  each emit one. Refusing it meant refusing ordinary compiler output, and did:
  `guests/{amm,orderbook,vault}` carry 1, 16 and 2 of them. The desync oracle is
  `crates/loader/tests/differential.rs` against `llvm-objdump`, not any single encoding
  being fatal. `docs/guest-program-manual.md` §6a is the guest author's version.
- **ecall numbers are append-only, forever.** Once a program's identity is published its
  ABI is frozen, and redefining a number does not fail loudly — it quietly makes an old
  program compute something else. One source: `constants::ecall`. The standard calls keep
  their Linux numbers (read 63, write 64, exit 93) so `qemu-riscv32` runs a guest
  unmodified; zkVM host calls take `0x0400..=0x04FF` and precompiles `0x0500..=0x05FF`,
  disjoint because a host call is nondeterministic prover advice and a precompile is a
  deterministic function of memory. fd 0 and fd 1 are committed, fd 2 is ignored, fd 3 is
  advice. `docs/spec/ecall-abi.md` is the table and a test holds it to the constants.
- **`io_digest` is frozen.** `transcript::io_digest(input, output)` is two `append_bytes`
  messages under `PUBLIC_INPUT_STREAM` and `PUBLIC_OUTPUT_STREAM` and one raw `sample`, in
  a sponge of its own. Later stages recompute it; nobody redefines it.
- **A guest ELF is not byte-reproducible across machines**, and CI does not pretend
  otherwise. rustc embeds absolute paths in the panic-location strings of every crate
  outside the guest workspace and of `core`, and stable Rust cannot remap them. Two clean
  builds on one machine do agree — that is acceptance 2 and a test proves it — so the
  committed `.elf` fixtures are refreshed with `cargo run -p kat-gen -- guests` on one
  machine, and only what is derivable *from* them is regenerated and diffed in CI.
- **Decoded tables are absolute, one row per halfword, `MINUS_ONE`-padded.** Row `i` is pc
  `2i`; a family's table is exactly its `VmConfig` height and strictly taller than its last
  live row; every row that is not one of that family's live instructions is `Fr::MINUS_ONE` in
  **every** field, never 0 (pc 0 is valid, so an all-zero row would be claimable).
  `next_pc` is the fall-through, never a branch target. `crates/program/CLAUDE.md`.
- **`family_extra_mask` is one-hot per mnemonic**, bits frozen in `constants::extra_mask`,
  append-only; `ecall`/`ebreak`/`fence` share the add/sub/lui/auipc family's bit-0
  *system* kind and are told apart by `imm` (0/1/2). No family keeps `funct3`. `FamilyId`s
  are `constants::family`, append-only, and ascending `FamilyId` is the canonical order.
- **Program identity binds the instruction tables, not the data image or the entry pc.**
  `.rodata`, `.data` and `ProgramImage.entry` reach no decoded table, so at S11 a program
  differing only in a constant or its entry point has the same identity; init/teardown is in every `VmConfig` and absorbs an **empty** commitment
  list until its stage fills that slot. Identity needs the 2^22 ceremony SRS, so its tests
  are `#[ignore]`d and run locally only. A verifier takes identity from a channel the
  prover does not control, never from the proof.
- **`decode` is RV32IMA's 59 instructions exactly, and `fence` is its one wide form.** Every
  `MISC-MEM funct3 = 000` word is a fence, as the ISA says; llvm-objdump prints `<unknown>`
  for the reserved ones. `crates/isa/tests/sweep.rs` counts the whole 2^30 space per opcode.
- **Own the crypto.** Runtime dependencies are limited to serialization, rayon, CLI and
  error handling. arkworks, Plonky3 and `zkhash` are reference oracles for tests and
  fixtures only, and never reachable from the prover, the verifier or a guest.
- **No `unsafe`, no nightly, no async, no threads.** Parallelism is rayon over data.
- **The execution trace's convention is `docs/spec/execution-trace.md`, and it is frozen.**
  Timestamp `4·cycle + Δ` over four in-cycle slots, **cycles numbered from 1** (timestamp
  0 is every address's initial write, which a cycle-0 pc query could not strictly follow),
  a 38-bit clock that is a fatal error to exhaust, the frame of each instruction class, the
  x0 rule, and the ecall frame — `a7` at slot 1, its arguments at slot 2, `a0` at slot 3,
  and a `read`/`write`'s one **transfer cycle** per word moved *before* its own row. S14's
  multiset fill and S16's ecall constraints cite it; they do not reinvent it.
- **Address-space tags are nonzero**: `constants::address_space` `REG = 1`, `RAM = 2`,
  `PC = 3`, so no real memory tuple is all zeros. A RAM event's address is the byte address
  of its 4-aligned word.
- **Family buffers are raw live rows**, column-major in small integer types, every query's
  address, value and timestamps per row. No padding and no `MultilinearPoly` — those belong
  to the constraint system, which is not built yet.
- **`sc.w` always succeeds in the emulator.** That is the one divergence the QEMU
  differential whitelists; the harness's other rule — `x2` differs at entry, Linux's stack
  pointer, until the guest writes it — is about the environment, not an instruction.
- **Misaligned halfword/word accesses, RAM-window violations (ecall buffers included),
  `ebreak` and a pc that is not an instruction are fatal guest errors**, in `run` and
  `trace_run` alike, and a fatal error returns no trace. `read`/`write` on a descriptor
  the ABI does not give that call return `-EBADF`; the recorded fd 0 stream is the bytes
  the guest consumed.
- **The trace archive's deterministic payload is a byte prefix of the file**; the timing
  section follows it, so determinism excludes timing by construction, not by comparison.
- **The heap never meets the stack.** guest-sdk's allocator refuses a block, with
  `exit(71)`, when it would end above `__stack_top - STACK_RESERVE` (8 MiB) or above the
  live `sp`. Until S12 the ceiling was `__stack_top` itself, and an exhausted heap handed
  out blocks on top of live stack frames. The allocator never frees, so the total a run
  allocates is the limit, not its peak.
- **Consistency is tested three ways.** `guests/consistency` is a `no_std` library the
  host calls directly, plus a thin guest `main`. `crates/emulator/tests/consistency.rs`
  runs one corpus on the host, under QEMU (`#[ignore]`d; CI runs it) and on the emulator,
  and holds fd 1, the exit status and a panic's message and line equal across all three.
  Rust itself lets some values differ per target: `usize` width in `core::hash` and
  `size_of`, 32-bit `usize` overflow, a `u64` narrowed with `as usize`, and NaN bits.
  Those are declared in `hazards::PLATFORM_DEPENDENT` and excused for the host alone —
  the pointer-width ones must then actually differ, and the NaN one is excused only on a
  host whose own convention differs.
- **Boring beats clever.** Added surface area is a defect. Every verifier entry point is
  `(&VerifyingKey, &Proof, &PublicInputs)` and nothing else.

## Status
| Stage | State | Handoff |
| --- | --- | --- |
| S01 — Fr field + constants skeleton | done | `docs/handoff/S01-field.md` |
| S02 — Poseidon2 permutation + duplex transcript | done | `docs/handoff/S02-transcript.md` |
| S03 — MultilinearPoly + small-type backing | done | `docs/handoff/S03-poly.md` |
| S04 — Gate-based sumcheck (zerocheck) | done | `docs/handoff/S04-sumcheck.md` |
| S05 — Fq tower + G1/G2 arithmetic | done | `docs/handoff/S05-fq-tower-curve.md` |
| S06 — Fq6/Fq12, Miller loop, final exponentiation | done | `docs/handoff/S06-pairing.md` |
| S07 — Pippenger MSM + ptau ingestion + KZG | done | `docs/handoff/S07-msm-srs-kzg.md` |
| S08 — Mercury I: single-polynomial commit/open/verify | done | `docs/handoff/S08-mercury-single.md` |
| S09 — Mercury II: RLC batching, deferral, accumulator | done | `docs/handoff/S09-mercury-batching.md` |
| S10 — Guest toolchain + SDK + loader | done | `docs/handoff/S10-toolchain.md` |
| S11 — Decoder + program identity | done | `docs/handoff/S11-decoder.md` |
| S12 — Emulator + trace generation | done | `docs/handoff/S12-emulator.md` |
