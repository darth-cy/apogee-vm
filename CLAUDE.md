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
  spec/          the frozen protocol specs; read before touching what they cover; and
                 metrics.md, the proving harness: the stage tree, the byte classes and
                 what the memory model does and does not count; and
                 constraint-manifest.md, every registered circuit's columns and gates by
                 position, name and formula. One page per circuit family:
                 jump-branch-slt.md, shift-bitwise.md, mul-div.md, memory-ops.md;
                 block-proof.md, the block layer: BlockProof, verify_block, ts windows; and
                 delegation.md, THE delegation ABI: the ecall convention, the frame, the
                 anchor, static detachment, the three delegation circuits, and the
                 guest-target backend; and
                 revm-block.md, S24's two wire formats: the output commitment, frozen,
                 and BlockWitness, deliberately NOT frozen
  handoff/       one note per completed stage: frozen API, artifacts, deviations
crates/
  constants/     frozen constants and tags; zero logic; no_std
  field/         Fr arithmetic (Montgomery); no_std
  curve/         Fq tower through Fq12 + G1/G2 + the optimal ate pairing + Pippenger MSM; std
  transcript/    Poseidon2 permutation + duplex transcript, and the curve-free G1 absorption; no_std
  poly/          MultilinearPoly + small-type backing + eq machinery; no_std
  sumcheck/      Gate + zerocheck prover/verifier; no_std
  srs/           snarkjs .ptau ingestion, the SRS archive, univariate KZG; std
  pcs/           Mercury commit/open/verify, RLC batching, deferred pairings
                 and the accumulator, plus the typed G1 absorption; std
  loader/        ELF parsing, RVC expansion, ProgramImage; std
  isa/           the RV32IMAC instruction model and the 32-bit decoder; no deps
  program/       decoded per-family tables, VmConfig derivation, program identity and the image
                 column; re-exports the statement descriptor and window rules from
                 verifier-core; std
  trace/         the memory event log and its self-check, the family buffers, the cycle
                 profile and shard plan, the TraceArchive snapshot, and the memory
                 argument's column builders; std
  emulator/      the RV32IMAC reference emulator and its tracing path, plus the
                 output-level QEMU oracle; std
  constraints/   circuits as data: PolyAddress, GateDef, LayerSpec, CircuitArtifact, the
                 laws, the cache-free compilation and the wire form; `memory`: the per-family frames,
                 the two window artifacts and check_memory; and `lookup`: the LogUp
                 channels, their gated tuples, the fraction tree and the discharge rules;
                 `add_sub`: S16's family circuit; `jump_branch_slt`: S17's; `shift_bitwise`
                 and `mul_div`: S18's two; `mem_word`, `mem_subword` and `atomics`: S19's
                 three; `delegation`: the frame, the anchor and the layered builder S23's
                 two circuits share; `keccak`: S21's delegation circuit; `poseidon2` and
                 `fr_arith`: S23's; `gadgets`: the is-zero and
                 comparison gadgets;
                 `family_circuit`: the registry, now every family; no_std
  gkr-verify/    the GKR verifier half: the gate kernel, the layer sumcheck verifier and
                 verify, and every type verify touches; the memory argument's window
                 constant, boundary factors and reconciliation; no_std, linked by the
                 recursion guest
  gkr/           the GKR prover half: forward pass, self-check, layer sumcheck prover,
                 prove; std + rayon; re-exports gkr-verify whole
  verifier-core/ the statement and its wire forms, the global and shard transcripts, the
                 verifying key and its load rules, reduce_shard and its two halves —
                 every check of a shard but its Mercury opening — and the block: BlockProof,
                 BlockReconciliation and the ts-window rule; no_std, linked by the recursion guest
  verifier/      verify_shard and verify_block, the two verification paths, and the
                 `verifier` CLI; std
  prover/        the verifying key's construction, family registration and fills, the
                 global commit phase, prove_shard, prove_block, the phase snapshots and
                 resume, and `metrics`, the proving harness behind the workspace's one
                 cargo feature; std
  checker/       the standalone law validators and lookup rules, the padding, padding-identity
                 and witness-row checks, the native lookup evaluator, the memory_roots hook,
                 the artifact cross-check, the circuit dump, the transcript-tape validator,
                 the `checker` CLI, and TamperHarness, the tamper-twin prover; std
  host/          the host SDK: `prove` and `verify`, thin wrappers over S20's entry points
                 with their arguments unchanged, `execute`, which is the one caller that
                 measures the execution phase's wall clock, a hand-written JSON reader and a
                 curl-backed JSON-RPC client with a content-addressed cache, and
                 WitnessRecorder, which pre-executes a block with native revm against that
                 client. **RPC is confined to a manual refresh; nothing else may reach the
                 network.** std
  guest-sdk/     crt0, entry!, linker script, bump allocator, ecall shims, and the two
                 public stream buffers whose bytes `io_digest` covers; no_std,
                 guest-only, and NOT a workspace member
guests/          fib/, echo/, rvc-dense/, amm/, orderbook/, vault/, atomics/, opcodes/, heap/, consistency/,
                 addsub/, control/, alu/, mem/, shards/, keccak-test/, keccak-unused/,
                 recursion-ops/, recursion-unused/, revm-block/
                 -- their own workspace; see guests/Cargo.toml and docs/guest-program-manual.md
assets/          gitignored: the PSE powers-of-tau ceremony files; see the S07 handoff
tools/
  kat-gen/       regenerates the committed Fr, multilinear, curve, MSM, SRS and G1-absorption
                 vectors from arkworks, the Mercury proof fixture from `pcs` itself, the ISA
                 corpus via llvm-objdump, the identity pin from `program` itself, S13's
                 toy circuit artifacts, defined there and compiled by `constraints`,
                 S14's memory artifacts, written from `constraints::memory`'s constructors,
                 S15's lookup toy, every registered execution family's circuit, written from
                 `constraints`, the three delegation circuits **by digest** (the artifacts
                 are megabytes),
                 the generic table's commitments over the ceremony, S20's global
                 transcript tape, and S24's synthetic block -- the witness, what native
                 revm makes of it, and the keccak-f frames the guest delegates
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
writing `docs/handoff/<stage>.md` and updating this file. A stage that adds or changes a
circuit family also writes that family's entry in `docs/spec/constraint-manifest.md`
(its maintenance section is the checklist). Raise conflicts and open questions with the
user rather than
picking a default silently.

## Commands
Everything above the line must be green before a stage's PR. All of it runs in CI
(`.github/workflows/ci.yml`) except the lines marked `# DEFERRED`, which are commented out
there under master rule 7 because the circuit is the real size: run those locally and
record the result in the stage's handoff note. For the rest, a green local run is a green
CI run.

**The `# DEFERRED` suites run once, at the end of a progression, not per commit**
(owner's instruction, S20). Each is tens of minutes and 8–33 GB of peak memory, so
re-running them after every change spends hours re-confirming what the previous run
established. While a progression is in flight, the gate is `cargo fmt`, `cargo clippy`,
the `riscv32imac` build and `cargo test --workspace`; a change whose only coverage would
be a deferred suite owes a **fast** test pinning the same property — a synthetic key and
statement in a unit test rather than a real proof — so the workspace run still guards it.
Then run the deferred suites in one batch when no further commits are expected, and
record their timings and peaks in the handoff note. **The peaks and timings below are
S24's measurement and S25a did not re-take them**: the I/O binding moved every guest's
cycle count — `guests/revm-block` at `--release` went 221,239 → 388,598 cycles and ten
shards → twelve — so the numbers will move when S25's batch runs on the dev box, and they
are kept here until then because a stale measurement of the right suite is more useful
than none.
```
cargo fmt --all -- --check
cargo fmt --manifest-path tools/transcript-ref/Cargo.toml --all -- --check
cargo fmt --manifest-path crates/guest-sdk/Cargo.toml --all -- --check
cargo fmt --manifest-path guests/Cargo.toml --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --manifest-path tools/transcript-ref/Cargo.toml --all-targets -- -D warnings
(cd crates/guest-sdk && cargo clippy --target riscv32imac-unknown-none-elf -- -D warnings)
(cd guests && cargo clippy --bins -- -D warnings)
cargo clippy -p prover --all-targets --features metrics -- -D warnings   # the ONE feature's configuration
cargo test --workspace                      # 1,046 tests as of S25a; 83 more are #[ignore]d
cargo test -p prover --features metrics --test metrics  # the metrics harness; 10 more, 2 #[ignore]d
cargo test -p program --test delegation -- --ignored --test-threads=1  # static detachment at BOTH guest profiles; builds six guest images, 2.9 s
APOGEE_GUEST_PROFILE=release cargo test -p emulator --test revm -- --ignored --test-threads=1 --skip a3_  # S24's guest against native revm; builds the revm guest, 47 s
APOGEE_GUEST_PROFILE=release cargo test -p emulator --test revm -- --ignored a3_  # ditto under qemu-riscv32, so a Linux host
cargo test -p checker --test logup -- --include-ignored --test-threads=1  # DEFERRED; 2^20 rows, 17.5 GB peak, 203 s, 30 min on a runner
cargo test -p prover --test acceptance -- --include-ignored --test-threads=1  # DEFERRED; S16's statement, 10.7 GB peak, 374 s
cargo test -p verifier --test cli -- --include-ignored --test-threads=1       # DEFERRED; ditto, 10.7 GB, 44 s
cargo test --release -p checker --test tamper -- --include-ignored --test-threads=1  # DEFERRED; one re-proof a twin, SIX statements since S23, 17.9 GB peak, 4231 s -- the slowest by wall clock; --release since S21
cargo test -p prover --test control -- --include-ignored --test-threads=1     # DEFERRED; S17's statement, 19.6 GB peak, 59 s
cargo test --release -p prover --test alu -- --include-ignored --test-threads=1  # DEFERRED; S18's statement, 31.7 GB peak, 53 s
cargo test --release -p prover --test mem -- --include-ignored --test-threads=1  # DEFERRED; S19's statement, 33.5 GB peak, 61 s
cargo test --release -p prover --test block -- --include-ignored --test-threads=1  # DEFERRED; S20's block, 34.9 GB peak, 840 s
cargo test --release -p prover --test keccak -- --include-ignored --test-threads=1  # DEFERRED; S21's nine-shard block, 33.7 GB peak, 131 s
cargo test --release -p prover --test recursion -- --include-ignored --test-threads=1  # DEFERRED; S23's ten-shard block, 35.2 GB peak, 120 s -- the heaviest by memory
RAYON_NUM_THREADS=6 cargo test --release -p prover --test revm -- --include-ignored --test-threads=1  # DEFERRED; S24's ten-shard revm block, and it builds the guest; 38.4 GB peak, 536 s -- NINE 2^20 shards, so the thread bound is not optional on a 48 GB machine
cargo test -p prover --features metrics --test metrics -- --include-ignored --nocapture  # DEFERRED; S16's statement twice, 21.0 GB peak, 60 s, and prints both reports
cargo build -p field -p constants -p transcript -p poly -p sumcheck -p constraints -p gkr-verify -p verifier-core --target riscv32imac-unknown-none-elf
cargo run -p kat-gen
cargo run --manifest-path tools/transcript-ref/Cargo.toml
cd guests/fib && cargo build --target riscv32imac-unknown-none-elf
APOGEE_GUEST_PROFILE=release cargo test -p loader --test qemu -- --include-ignored
cargo test -p emulator --test qemu_outputs -- --include-ignored
cargo test -p emulator --test consistency -- --include-ignored   # and again at APOGEE_GUEST_PROFILE=release
git diff --exit-code -- crates/field/tests/vectors/ crates/transcript/tests/vectors/ crates/poly/tests/vectors/ crates/curve/tests/vectors/ crates/srs/tests/vectors/ crates/pcs/tests/vectors/ crates/loader/tests/vectors/ crates/isa/tests/vectors/ crates/program/tests/vectors/ crates/constraints/tests/vectors/ crates/checker/tests/vectors/ crates/emulator/tests/vectors/
-------------------------------------------------------------------------------
cargo run -p kat-gen                        # refresh every fixture (manual, deliberate)
cargo run -p kat-gen -- <group>             # just one: field | poly | curve | tower | pairing | msm | srs | pcs | loader | isa | program | gkr | memory | lookup | family | delegation | tape | revm
cargo run -p checker -- laws <artifact>     # Laws 1-4 and the lookup rules, the standalone validators
cargo run -p checker -- padding <artifact>  # the padding contract
cargo run -p checker -- dump <artifact>     # a circuit, readably: layers, gates, relations, catalogue
cargo run -p checker -- tape <verifying-key> <public-inputs>
                                            # the global commit phase's absorb sequence, diffed
                                            # against the frozen pre-fork order
cargo run --release -p verifier -- <verifying-key> <identity-hex> <public-inputs> <proof>...
                                            # verify a statement: the types' to_bytes, as crates/verifier/tests/cli.rs writes them
cargo run --release -p verifier -- block <verifying-key> <identity-hex> <public-inputs> <block>
                                            # verify a BlockProof file end to end
cargo run -p kat-gen -- guests              # rebuild the guest ELFs; opt-in, one machine
cargo run --manifest-path tools/transcript-ref/Cargo.toml   # ditto, transcript vectors
cargo run --release -p bench                # every routine; internal numbers only
cargo run --release -p bench -- --list      # the routines, and what each measures
cargo run --release -p bench -- <routine>   # just that one; setup is per-routine

cargo run -p artifact-dump -- <guest.elf> [--out <dir>]   # export a ProgramImage
cargo run --release -p artifact-dump -- tables <guest.elf> [--ptau <file>]   # decoded tables, identity
cargo test --release -p program --test identity -- --ignored   # identity; needs the ceremony file
cargo test --release -p program --test lookup_tables -- --ignored   # the generic table's commitments; ditto
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
oracle `crates/emulator/tests/qemu_outputs.rs` holds the emulator's **answers** to — its exit
status and its fd 1, and nothing below that. It is user-mode
emulation: it translates Linux syscalls into host ones, so it builds for Linux hosts only
and no macOS build of it exists. That is a claim about *native* builds — a Linux VM is an
ordinary arrangement and the suite runs fine inside one. The tests stay `#[ignore]`d so a
machine with no emulator cannot report silent coverage, and CI asks for them by name:

```
cargo test -p loader --test qemu -- --include-ignored   # a Linux host with qemu-user
cargo test -p loader --test layout -- --ignored         # after editing link.ld

APOGEE_GUEST_PROFILE=release \
  cargo test -p loader --test qemu -- --include-ignored   # the same fifteen, optimised
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
- **No cargo features. Zero — with exactly one exception, and it is closed.** One build
  configuration for the whole workspace. The exception is `prover/metrics`, granted by the
  owner at S20 for the proving harness and **for nothing else**: the rule stands unchanged
  for every future progression, and `crates/prover/tests/one_feature.rs` enforces that by
  reading every `Cargo.toml` in the repository and failing on any `[features]` table but
  that one, or any key in it but `metrics`. The feature is off by default, enables no
  dependency, and changes no proof byte; CI builds, clippies and tests the feature-on
  configuration too, so the anti-goal's stated hazard — "a configuration nobody builds is
  broken and undiscovered" — does not apply to it. `docs/spec/metrics.md` §0. A
  `features = [...]` *key* inside a dependency entry is a different thing and always was
  allowed: it selects an upstream crate's features, as the workspace manifest does for
  `ark-ec` and `ark-ff`.
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
  `pcs::append_g1_list` is **one** message of `4k` limbs, never `k` messages. Since S16
  the split is `transcript::g1_limbs` over the 64 bytes, so the no_std verifier core
  absorbs a point without decoding it; validating a point is its decoder's job.
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
- **SRS integrity is presumed; the SRS digest covers the verifier points and the generic
  table, nothing else.** S07's Poseidon2 digest over the whole SRS was dropped on
  instruction. The SRS digest is a Poseidon2 sponge over the 320-byte `SrsVerifier` (S16)
  and, since S17, the packed generic table's three commitments as one twelve-limb
  `GENERIC_TABLE` message. It is in the verifying key and G2 absorbs it in every statement:
  it binds a proof to the points its pairings read and the table its generic lookups read,
  and nothing more. The key's loader recomputes it from the key's own points, and identity
  binds neither the SRS nor the table, so a key whose verifier points were swapped for ones
  with a known `tau`, or whose table commitments were swapped for another table's, still
  loads under its own recomputed digest. A verifier must get the ceremony's SRS digest from
  a trusted channel, as it gets identity, or else get the ceremony's `SrsVerifier` and the
  table's three commitments, which anyone holding the ceremony can compute, and recompute
  the digest from them. `docs/spec/srs.md` §4, `docs/spec/shard-proof.md` §3 and §7.2.
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
  a sponge of its own. Later stages recompute it; nobody redefines it. **Since S25 the
  guest computes it too**: `transcript::exit_with_io_digest` hashes the two streams the run
  moved and leaves the eight LE `u32` words in `x24..x31`, and `verify_global_memory`
  recomputes them from the statement's own streams and compares — unconditionally, once per
  block, no new message and no new wire form. A run that moved nothing publishes
  `constants::IO_DIGEST_EMPTY`, so the check is never skipped. The length is absorbed
  before the bytes, so the digest is **not streamable**: a guest pays for it at exit, over
  the whole of both streams, and on `guests/revm-block` at `--release` that is +76% of the
  cycles (221,239 → 388,598) and two extra delegation shards. At the committed fixtures'
  `debug` profile the epilogue costs far more than the small guests themselves — `fib` runs
  9,963 instructions of its own and 306,441 more to publish, nearly all of it marshalling
  delegation frames through `copy_from_slice` at `opt-level = 0` — which is why every
  guest's cycle count moved at S25a. Under an executor with no circuit it costs far more
  again — `qemu-riscv32` answers `-ENOSYS` and runs the software permutation, 80 hex decodes
  and 240 Montgomery multiplies apiece, so `fib`'s four-byte digest is 25.7 **million**
  instructions there — which is why nothing compares the two executors' instruction streams.
  `docs/spec/memory.md` §10.
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
- **Program identity binds the instruction tables, the image window and the entry pc.**
  Since S14 the recipe absorbs `PROGRAM_ENTRY [entry_pc]` after `VM_CONFIG`, and
  `INIT_TEARDOWN`'s commitment list is the image column, row `y` = `initial_word(4y)` over
  RAM window 0, so a changed `.text`, `.rodata` or `.data` byte or entry pc moves it;
  `ZERO_WINDOWS` absorbs an empty list. It binds nothing an execution chooses — no shard
  count, no window list — and not a `NOBITS` segment's size. `decode_program` refuses file
  bytes past window 0 (`ImageOutsideWindow`), so no image byte escapes the column.
  `identity_from_commitments` is the SRS-free digest a verifying-key loader recomputes.
  Identity needs the 2^22 ceremony SRS, so its full tests are `#[ignore]`d and run locally
  only. A verifier takes identity from a channel the prover does not control, never from
  the proof. `docs/spec/memory.md` §6.2.
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
  x0 rule, and the ecall frame — `a7` at slot 1, its arguments at slot 2, `a0` at slot 3.
  S14's multiset fill and S16's ecall constraints cite it; they do not reinvent it.
  **Every instruction is one cycle, with no exception since S25.** A `read` or a `write`
  that moved bytes used to be preceded by one **transfer cycle** per word — a live row at
  the same pc with `next_pc = pc` — and S14's open question 10 asked how such a row's RAM
  write could be confined to its ecall's buffer. It cannot be: a transfer row is a
  *different* row from its ecall, and this arithmetization has no cross-row constraint. So
  S25 took the answer S14 recommended and removed the row: a provable `read` moves exactly
  one 4-aligned word and carries that word's RAM query **on the ecall's own row**, beside
  the `a1` and `a2` it is held against, and a `write` stages no memory event at all.
- **Address-space tags are nonzero**: `constants::address_space` `REG = 1`, `RAM = 2`,
  `PC = 3`, so no real memory tuple is all zeros. A RAM event's address is the byte address
  of its 4-aligned word. Since S21 there is **one space per delegation family** — 4, 5 and
  6 — holding that family's anchor tuples and nothing else, which is what makes a request's
  mirror read answerable by an invocation of *that type* and by nothing in RAM or a
  register. One `deleg` frame query serves all three, so its tag is not a literal but the
  frame's own `deleg_space` M column: a memory leaf may read no `W` column, and a type
  selector is one (`docs/spec/delegation.md` §5.1 and §10.1).
- **Family buffers are raw live rows**, column-major in small integer types, every query's
  address, value and timestamps per row. No padding and no `MultilinearPoly` in them: the
  memory argument's padded columns are filled from the log by `trace`'s memory builders,
  keyed by `constraints::memory`'s layout.
- **QEMU is an oracle for what a guest computes, never for how this emulator computes it**
  (owner's decision, S25). The comparison is the **exit status and fd 1**, and nothing
  else: no instruction count, no pc, no intermediate register, no trace. S12 built
  `crates/emulator/tests/differential.rs` as a per-instruction register-file comparison
  with an entry-state rule for `x2` and a one-entry `sc.w` whitelist; that file is now
  `tests/qemu_outputs.rs`, `emulator::qemu` is **deleted**, and the invariant is
  **withdrawn from every spec that stated it**. It was never the property the project
  needs, and since S23 it is not even true: a **delegation** ecall runs natively here and
  takes the `-ENOSYS` software fallback under QEMU, so the two instruction streams differ
  *by design* and agree on the answer. S25 made that universal — publishing `io_digest` at
  exit means Poseidon2, so every guest that moves committed bytes delegates — and the
  register comparison would have been a suite asserting this VM must execute the way a
  foreign emulator does. Keeping it was also not free: QEMU's software permutation turns
  `fib`'s four-byte digest into 25.7 million instructions, and `-one-insn-per-tb -d cpu`
  logs that at about 630 bytes each, a 15.5 GB file per guest.
- **A trace's correctness is held against this VM's own semantics, not against QEMU's
  execution.** `crates/emulator/tests/trace.rs` (the frame table, the four-slot clock,
  routing, the halting sentinel, every ecall's answer against the ABI), `crates/trace`'s
  log self-check, `crates/checker/tests/multiset.rs` and `memory.rs` (the memory argument
  over real guests' logs, every forgery refused by the gate that refuses it), and each
  family's row suite over its fill. Those run in `cargo test --workspace`, on every push,
  with no emulator to install.
- **`sc.w` always succeeds in the emulator**, and the circuits share that semantics, so
  emulator and constraint agree (`docs/spec/memory-ops.md` §6.6). It is a conformance
  deviation and never a soundness one. It is no longer a whitelist entry anywhere, there
  being no register comparison to exempt it from; what would catch it if it ever mattered
  is a guest whose committed output depended on it, which is the comparison above.
- **Misaligned halfword/word accesses, RAM-window violations (ecall buffers included),
  `ebreak` and a pc that is not an instruction are fatal guest errors**, in `run` and
  `trace_run` alike, and a fatal error returns no trace. A `read` of anything but one
  4-aligned word is fatal too, by name (`ReadNotOneWord`). `read`/`write` on a descriptor
  the ABI does not give that call return `-EBADF`; the recorded fd 0 stream is the bytes
  the guest consumed. **Neither a refused `read` nor a refused `write` is provable** — since
  S25a `read_descriptor` and `write_descriptor` hold each call's `a0` to its own pair of
  descriptors, and a refused `read` also stages no RAM query where `ram_mask_rule` demands
  one — so `fill::add_sub` refuses such a cycle by name rather than handing a verifier a
  shard that fails as `Constraint`. A refused `write` used to prove as an ordinary `write`
  row. The SDK never issues either: it passes fd 0, fd 1, fd 2 and fd 3 and no other.
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
- **The GKR engine's spec is `docs/spec/gkr.md`, and it is frozen**: the layer model, the
  addresses, the six gate shapes, the artifact and its wire form, the laws, and the
  backward pass's transcript schedule. A gate list is row-wise or halving, and a halving
  list halves every column of its layer in order, the child bit being the highest variable.
- **The verifier half is its own crate.** `gkr-verify` is `#![no_std]` and CI builds it
  for the guest; `gkr` is std + rayon and re-exports it, so `gkr::verify` is
  `gkr_verify::verify`. The owner chose two crates over a serial prover or an unchecked
  no_std claim.
- **`gkr_verify::eval_gate` is the one kernel.** The engine's passes read gates
  through `gkr_verify::ResolvedList`, which `gate_values` and `summand` wrap, so the
  forward and backward passes share one `G`; the checker calls the kernel directly over
  the flat relations. The prover allocates nothing per row, row pair or node
  (`crates/gkr/CLAUDE.md`).
- **Cached entries are substituted, never columns.** No table, no claim, no width; degree
  counts after substitution, which is how a degree-3 gate is written and refused; the
  prover evaluates a cached entry at every round node and never binds it. A virtual table
  is never materialized either.
- **A GKR circuit's outputs are absorbed before its top point is drawn.** Otherwise a
  prover predicts the point and forges an output table with the same value there.
- **One `LayerInconsistency { layer }` for every failing round or final check**, on the
  owner's instruction: a batched sum cannot say whether the descending claim or an
  enforcing gate is wrong, and no proof data is spent pretending otherwise.
- **The laws are enforced twice**, by `CircuitArtifact::validate` and by `checker`'s
  validators, which share no code; `from_bytes` checks encoding only, so the checker can be
  handed a broken artifact. An inner column below the top that no gate reads — on the
  normalized expansion, so `x − x` and `0·x` read nothing — a cached entry no gate
  names, and an identically zero enforcing gate are refused: a relation constructed and
  then dropped is one nothing depends on.
- **`validate` runs once, where an artifact is built or loaded, never per proof.**
  `gkr::verify`, `forward`, `self_check` and `prove` assume a validated artifact and do not
  re-check it; the later stages that load a verifying or proving key must call
  `validate` there. On an artifact that breaks a law the engine's answer means nothing:
  it may panic, and `verify` may accept.
- **The prover checks nothing about its inputs at run time** — not the base, the layer
  values, the tables or the challenge slots. Soundness is `verify`'s alone, and a cheating
  prover runs none of the prover's code; a malformed input costs only the honest prover a
  panic or a proof that fails downstream. The old shape checks stay in the source,
  uncalled or commented out, as debugging aids (`crates/gkr/CLAUDE.md`).
- **The memory argument's spec is `docs/spec/memory.md`, and it is frozen**: the tuple, the
  frame, RAM windows, the register and PC boundary, halting, binding, range obligations and
  the construction-time rules. It amends the master's absorb order and S11's identity
  recipe, and the master cites it.
- **A family's frame holds only the queries its instructions can make.** The query table has
  **nine** entries since S21 — pc, then `execution-trace.md` §7's eight roles — but no family
  holds all nine: `arg1`, `arg2` and `deleg` are an ecall row's alone, `load` a load's. The
  frozen subsets are `constraints::memory::frame_queries`, 4 queries for `JUMP_BRANCH_SLT`,
  `SHIFT_BITWISE` and `MUL_DIV`, 5 for `ATOMICS`, 6 for the two memory families and **8 for
  `ADD_SUB_LUI_AUIPC`**, giving `1 + 5w` memory and `w + 3` witness columns, `2w`
  obligations, and leaves padded to a power of two a side with leaves that are literally 1 —
  **add/sub's eight need no pad**, and its sixteen obligations push its timestamp tree to 32
  leaves and the circuit to six row-wise gate lists, which is what moved every relation
  number in `constraint-manifest.md` §3. **A column's position is a slot in
  that list; its address space and `Δ` come from its id in the table** — the two differ for
  every family. A frame narrower than its family cannot balance, so the honest prover is
  refused rather than a cheating one admitted; a wider one commits and opens columns that
  are 0 on every row. What must be exact is S16's inheritance: a frame is a **superset** of
  its instructions' queries, or S16 has no column to constrain an instruction's written
  value against. `crates/trace/tests/memory.rs` holds `frame_queries` equal to the union of
  its family's instructions' queries over all 59 of them, routed by `program::row_kind`.
- **RAM is initialized in RAM windows, by two families of one height.** Window `w` is the
  bytes `[4h·w, 4h·(w+1))`. `INIT_TEARDOWN` is window 0, exactly one shard, initialized from
  the image column identity commits, rows below `RAM_ORIGIN` masked by `V[ram_live]`;
  `ZERO_WINDOWS` is one shard per touched window above 0, initialized to 0. Both are in
  every `VmConfig` at one height, or derivation and `VmConfig::from_bytes` refuse it. The
  window ids go in the statement as `MEMORY_WINDOWS`, and `program::check_memory_windows`
  holds them strictly increasing in `[1, 2^29/h − 1]` before the challenges. A window is a
  slice of the address space; a shard's cycles are a slice of the execution.
- **Registers and the pc have no rows: they are the verifier's boundary.** A proof carries
  64 scalars — final timestamps of `x0..x31` and the pc, final values of `x1..x31` — which
  S16's global transcript absorbs as one `MEMORY_BOUNDARY` message after every memory-column
  commitment and **before** the squeeze, and `PublicInputs` decodes and refuses out of
  range: a final value chosen after the challenges solves reconciliation for any trace.
  `gkr_verify::boundary_factors` folds them and the entry pc into `(W_b, R_b)` once per
  statement, and `reconciles` is the check. `t_pc` is not a cycle count.
- **The exit row writes `next_pc = HALT_PC = 1`**, not `pc + 4`, and the verifier fixes the
  pc's final value to it. It is odd and below `RAM_ORIGIN`, so no other row writes it and a
  trace missing its exit row cannot balance. Since S16 the add/sub family's `next_pc` gate
  holds every one of its rows to it: the exit row writes `HALT_PC`, every other live row
  the decoded table's `next_pc`, which stays the fall-through, minus `2^32·pc_wrap`. **"Odd"
  is a constraint only where a family makes it one**: S17's jump family range-checks every
  `next_pc` it writes even, because a `jalr` whose `rs1 + imm` is 1 could otherwise keep
  bit 0 and write `HALT_PC` — a crashing program proven to exit cleanly. A family that
  computes a pc owes the same; one that copies the decoded fall-through owes a degree-1
  `next_pc − decoded_next_pc = 0` and no bound at all, which is S18's reading and what
  S19's three families carry. Since S19 every family has its `next_pc` gate.
- **A frame alone holds a query's mask to booleanity and nothing else.** No frame gate ties
  it to the row's pc mask or to the instruction the row looks up, so a padding row can
  carry an `rd` query that rewrites `x10` after exit, and it balances. A family's circuit
  makes `m_pc` the row's liveness and the decoder lookup's selector, and `m_q = m_pc·uses_q`
  from the row kind (`docs/spec/memory.md` §2.1). S16's add/sub family does, and
  `crates/checker/tests/tamper.rs` proves control C8's three forgeries refused; S17's jump
  family does, and its row suite refuses C8 on its frame; and since S19 every registered
  family does, each with its own `uses_q` sets read off `docs/spec/execution-trace.md` §4 —
  a load has no `rs2` query, a store no `rd`, and `lr.w` no `rs2`, which its mask rule keys
  on `b_lr` and never on `is_zero(decoded_rs2)`, a test `amoadd.w rd, x0, (rs1)` would also
  pass.
- **The artifact format is 1, and a lookup carries a selector.** `LookupExpr = (name,
  channel, selector, tuple)`: a range obligation holds where its selector is 0 or its one
  `Linear` expression is below the channel's bound. A **table** channel's tuple is 1 to
  `MAX_TUPLE` expressions wide, and every lookup of a channel is the same width, because
  one channel has one table. `checker::violated_lookups` is the range channels' native
  evaluator; `checker::channel_sums` is every channel's. `from_bytes` refuses any other
  format version.
- **The LogUp spec is `docs/spec/lookup.md`, and it is frozen**: the four channels, the two
  shard-local challenges and their derived powers, the gated-key conventions, the fraction
  tree, the multiplicity convention, the packed generic table and the decoder binding.
- **`g` and `β` are shard-local and follow every commitment.** Drawn in that order under
  `LOOKUP_CHALLENGE`, after every witness and multiplicity commitment of the shard is
  absorbed. `β^0` is the literal 1, and every power above it is a **derived** slot: a gate
  coefficient is one literal or one challenge, and `β^j` is neither. So a tuple position
  above 0 weights its columns by 1 and carries the constant 0 or 1; position 0 takes any
  literal.
- **A lookup's selector carries a booleanity gate**, which `validate` refuses it without.
  LogUp sums `s/(E + g)`, so at `s = −1` an out-of-range row cancels an in-range one and
  LogUp stops being the statement `violated_lookups` reads.
- **A channel's root check is both conditions**: `num == 0` **and** `den != 0`. A leaf pair
  of `(0, 0)` annihilates the whole tree, so the numerator check alone would accept a
  channel that proves nothing.
- **A range channel needs `BITS ≤ trace_vars`**, refused at construction: a table of `2^n`
  rows holds at most `2^n` values. With `BITS[TIMESTAMP] = 19` and Mercury's even variable
  count, **every execution family's shard is at least `2^20` rows**, so no family that runs
  cycles may default below it. S19 raised `DEFAULT_HEIGHTS[ATOMICS]` from `2^16` to `2^20`
  with the circuit that needs it, and `family_circuit`'s minimum-height arm now names
  **all seven** execution families: a family missing from it would reach the channel
  assertion and panic inside `VerifyingKey::check`, on bytes a verifier was handed, rather
  than returning `None` for a clean `Err`.
- **The `+ 1` on a gated key is for map tables only.** It keeps every real entry off the
  all-zero tuple so the `ZeroEntry` answers switched-off rows alone. A range channel has no
  offset and cannot have one — shifting `[0, 2^BITS)` up by one puts its top outside the
  table — and the decoder gates to the `MINUS_ONE` padding tuple instead, S11's table
  having no all-zero row. Those two exemptions are documented in `docs/spec/lookup.md` §4
  and nowhere else.
- **One packed mask column, and one-hotness is the table's domain.** Booleanity permits any
  subset of bits, the empty one included, and on an all-zero mask every gated constraint
  goes vacuous. Split the mask into independent boolean columns and the property is lost
  silently. A bit a circuit *extracts* from the mask still carries its own `x² = x`.
- **A multiplicity is counted over raw gated tuples**, never a compressed one: it is
  committed before `g` and `β` exist. One counter per channel per table row, the lowest row
  holding a repeated tuple, switched-off rows included.
- **A fraction tree is exempt from the product-tree padding clause.** Its identity is
  `(0, 1)`, and a padding row is not idle in a channel: it contributes the neutral entry,
  which the multiplicity column counts.
- **`check_memory` is a provenance rule.** It runs beside `validate` wherever a memory
  artifact is built, and refuses any gate or output whose cone both names a global memory
  slot (1–5) and reads a `W` column, a root whose cone reads a `W` column at all — `W` is
  committed after the memory challenges — a global-slot coefficient over anything but `M`, `S`
  and `V`, and a leaf mask that is an `M` or `S` column with no booleanity gate, or any
  virtual column but `V[ram_live]`. `S` is admitted only because its columns are bound
  before the challenges — by identity, or, for S17's generic table, by the SRS digest.
  `docs/spec/memory.md` §8.
- **The shard proof's spec is `docs/spec/shard-proof.md`, and it is frozen**: the statement,
  the global transcript G1–G11 and the shard transcript, the SRS digest, the one opening
  per shard, `verify_shard`'s check order, the verifying key and its load rules, the
  add/sub family, the wire forms, the prover's phases and the registry.
- **One statement, many shard proofs, one `PublicInputs`.** The statement's variable-length
  record — shard counts, windows, boundary, every shard's memory commitments and roots —
  is in `PublicInputs`, and a `ShardProof` has a fixed shape per key and family. A shard
  verifies only against the whole statement: its reconciliation reads every shard's roots,
  and its transcript is seeded from the global state digest.
- **`verify_shard`'s check order is its error class**: `Statement`, `Malformed`,
  `Constraint`, `Lookup`, `MemoryArgument`, `Opening`, first failure returned. The CLI and
  every test call `verify_shard` and nothing else; `verifier_core::reduce_shard` is every
  step but the opening, `#![no_std]`, for the recursion guest. S20 split those steps into
  three functions by what each reads, and the order survived it exactly.
- **A verifying key's circuits are the registry's, byte for byte.**
  `constraints::family_circuit(family, trace_vars)` is the one source of circuits, and
  loading a key refuses any other. Identity binds the program, not its circuit. A family
  becomes provable with one arm there and one fill in `prover::family_fill`, and nothing
  else in the prover or the verifier changes — S17's jump family was exactly that, plus
  the generic table's binding below.
- **A family's sub-circuit is a `constraints::memory::FamilySpec`** (owner's naming, S17):
  what a family adds beside its memory frame — witness and setup columns, virtual tables,
  enforcing gates, lookups and channels — collected once and handed to
  `frame_with_channels_artifact`. A family that factors that collection into a function of
  its own calls it `family_spec`: `add_sub` builds its spec inline, `jump_branch_slt`
  behind a private `family_spec` its `assemble` seam takes. Every sub-circuit a later
  stage factors out is named the same way. S15 called the type `Extras`.
- **The packed generic table is bound through the SRS digest, not identity** (owner's
  decisions: S16 answer 8, and at S17 "fold into the SRS digest"). Every `VerifyingKey`
  carries exactly one `generic_table`, the table's three commitments, whether or not any
  of its families reads the `GENERIC` channel, and the SRS digest covers them. So the
  global transcript is S16's G1–G11 unchanged, and the table enters it only through G2. A
  family whose circuit reads the channel (`FamilyCircuit::reads_generic_table`) opens its
  last three setup columns against them, listed after identity's setup commitments: the
  jump family's `S[7..10]`. They are constants of the ceremony, the same three points at
  every height `2^n` with `n` even and at least 18, pinned in
  `crates/program/tests/vectors/generic_table.txt`. This amends S16's frozen shard-proof
  spec at §3 and §9, so every S16 key's bytes and SRS digest changed.
  `constants::generic_table` holds the table's width and key bases.
  `docs/spec/jump-branch-slt.md` §6.
- **The shift/bitwise family's spec is `docs/spec/shift-bitwise.md`, and it is frozen.**
  One merged family, never split: `rs2 + imm` is the second operand of all twelve, one
  addend always being zero; the amount is `src2 & 31` with `high` range-checked — never
  leave the shamt free, or `sll` with `rs2 = 4` shifts by 8. **Every key this family looks
  up carries a range pair of its own**, the amount and the four `rs1` bytes alike: with
  three sub-tables in one channel an unbounded key does not miss the table, it reads a
  foreign sub-table's row, and a `byte_a_j` of 65,823 reads `ShiftPowers`' `s = 31` row and
  proves a false `and`. **One product serves both directions**:
  `shift_in` selects the multiplicand and `shift_prod = shift_in·pow` is ungated, which is
  what keeps `is_left·(rs1·pow − …)` from being degree 3. A right shift is the floor-division
  identity with `se = is_arithmetic·rs1_sign` committed; the residue bound is the copower
  pattern, and **`residue` carries its own direct 16+16 check besides**, without which a
  field-element residue absorbs `rs1 − rd·2^s` for any `rd` at all. XOR and OR are derived
  from the one AND accumulator — `or = a + b − and`, `xor = a + b − 2·and`, summed by
  linearity, no XOR table and no OR table — and the `rd` term is gated by the family bit,
  not by the bracket, since the op selectors are zero on a shift row.
- **`ShiftPowers` is a third sub-table of the packed generic table**, `(SHIFT_BASE + s + 1,
  2^s, 2^(31 − s))` for `s < 32`. Its second value is the copower `2^(32 − s)` **stored
  halved**, `2^32` not fitting the table's `u32` columns, and the two gates that read it
  carry a factor 2. Appending it moved the table's three commitments, so every S16 and S17
  verifying key's SRS digest and bytes moved with them, and
  `crates/program/tests/vectors/generic_table.txt` was re-pinned over the ceremony.
  Identity binds none of it. That is the standing price of S17's binding.
- **The mul/div family's spec is `docs/spec/mul-div.md`, and it is frozen.** Its decoded
  tuple is **six columns, not seven** — every one of its instructions is R-type, so S11's
  tuple carries no `imm`, its table is `S[0..6]` and the packed table `S[6..9]`. **One
  product identity serves all four multiplies and the division alike**, `mx` and `my`
  selecting the multiplicands; the division identity is gated to division rows, and must
  be, or a `mul` of `−2^31` by `−1` is unprovable. `r_sign` is *defined* as
  `f_div·s1·(1 − [r = 0])`, which is what separates truncated from floored division — the
  easiest line to leave out — and `|rem| < |divisor|` is one range-checked gap carrying a
  `2^32·dz` correction, so a zero divisor imposes no bound. **`q_sign` is a free boolean**,
  pinned only by `q`'s own range: tying it to bit 31 of `q` would make `−2^31 ÷ −1`
  unprovable, that being the case whose signed quotient is `+2^31`. So the signed overflow
  needs no pin; div-by-zero needs one gate.
- **`check_copowers` is selector-aware since S18.** It takes each copower-scaled column with
  the selector its scaled obligation carries and requires the direct range pair under that
  same selector. S17 matched an obligation on its expression alone, which passed a circuit
  whose direct pair sat under a narrower selector and bounded nothing on the rows that
  selector switches off.
- **The jump/branch/slt family's spec is `docs/spec/jump-branch-slt.md`, and it is frozen.**
  S11's decoded table unchanged — the prompt's five-bit mask would have rebuilt it — so
  `sc`, `cmp_imm`, the branch weights and the fall-through are linear forms over the twelve
  one-hot kind bits, and the legal masks are those twelve bits
  (`jump_branch_slt::LEGAL_MASKS`); one ungated degree-2 comparison,
  `lhs − rhs − 2^32·sc·(lhs_sign − rhs_sign) + 2^32·lt − gap = 0`, whose `gap` range check
  carries the soundness, signs from `U16GetSign` over range-checked halfwords, and no
  comparison table; `taken` a committed bit; one ungated wrap on whichever sum `next_pc`
  is; the link the table's fall-through, range-checked and with no wrap bit; a branch has no
  `rd` query. **`constraints::gadgets`** — `is_zero` (the x0 rule is built on it, bytes
  unchanged) and `comparison` — are frozen for S18 and S19.
- **The memory-op families' spec is `docs/spec/memory-ops.md`, and it is frozen.** The
  addressing is shared by all three: `addr = 4·word_index (+ 2·bit1 + bit0)` is an
  alignment check over ℤ and **nothing over Fr** — 4 is a unit there — so what makes the
  split base-4 is the range check on `word_index`, three `RANGE16` obligations whose third,
  `4·word_index_hi`, caps it at `2^30 − 1` and is exactly tight at the top of the address
  space. `MEM_WORD` carries no offset bits at all, so a misaligned `lw` or `sw` has no
  representation; `half_aligned` clears bit 0 at halfword width, and is load-bearing twice
  — it is also what keeps `w·p` a divisor of `2^32`, on which the bound on what a store
  writes rests. **Every RAM query's address is `4·word_index`**: one memory, not two.
- **There is no `MemoryOffsetGetBits` table** (owner's decision, S19). The splice power
  `p = 2^(8·offset)` and its halved copower are degree-2 gates over the address's own two
  offset bits, which pins the position more directly than a keyed table would — the table
  never carried the pinning, only the values — and adds no key to bound and no movement of
  the packed generic table's three commitments. **The packed table did not move at S19**,
  and a later stage restoring the table would pay S18's standing price for nothing.
- **A copied value is not range-checked; a computed one is.** That is the prompt's
  write-side induction, and S19 made it two one-directional inductions rather than a mutual
  one: `mem_word`'s `rd_selected` carries a 16+16 pair even though it is a copy of a RAM
  word, so **every register write in every family is locally bounded**, and the RAM side
  then follows from the register side and from `mem_subword`'s and `atomics`' own local
  bounds. **S25 closed the one hole that was left**: the word a provable `read` delivers is
  the only value add/sub writes to RAM, it is computed rather than copied — it comes from
  the prover's fd 0 stream and from no register — and it carries its own 16+16 pair under
  `m_pc`, so the induction is whole across every family.
- **`sc.w` always succeeds, and that is a conformance deviation, not a soundness one.**
  It stores `rs2` and writes `rd = 0` with no reservation state anywhere in the machine.
  The emulator has the same semantics, so emulator and circuit agree. It was the QEMU
  differential's one whitelist entry until S25; there is no register comparison now, so
  what would show it is a guest whose committed output depended on spurious failure, and
  compiled code has none — LLVM never emits an unpaired `sc.w` and the standard CAS loop
  exits on its first pass.
- **A gadget's parameters can be a family's whole soundness, and then they are asserted.**
  `atomics::assemble` holds the comparison gadget's selector, `lhs`, `rhs` and `signed` to
  what `docs/spec/memory-ops.md` §6.4 states, because each wrong choice silently breaks the
  four min/max kinds and nothing else in the circuit would catch it. Likewise every arm
  indexes `KINDS` through its `constants::extra_mask` constant and never by position: the
  stage prompt lists `amoand` and `amoor` in the opposite order to the constants.
- **EXIT, a registered delegation number, `read` and `write` are the provable ecalls**
  (owner's decision, S16; S21 added the second, S23 the third and fourth, S25 the last two).
  The add/sub family commits one boolean selector per kind and holds every ecall row to
  `a7 = 93` **or** that kind's number; what makes the gates a *partition* is that the
  numbers are pairwise distinct, which a `const` assertion over
  `constants::delegation::TYPES` and `constants::ecall` enforces. Its fill refuses any other
  ecall by name, and since S25 also a `read` that moved no word — a refused descriptor,
  which `ram_mask_rule` cannot admit. A delegation row falls through rather than halting,
  writes 0 into `a0`, and carries the `deleg` mirror query that pairs it with an invocation;
  a `read` and a `write` fall through too and write into `a0` a byte count. **Since S25a
  that count and the descriptor beside it are constrained**: one shared boolean says which of
  its call's two descriptors the row named — fd 0 or fd 3 for a `read`, fd 1 or fd 2 for a
  `write` — a `write` answers the count `a2` asked for, and a `read` answers something in
  `[0, 4]`. A descriptor outside the pair is a call the executor **refused**, with `-EBADF`
  and no byte moved, so the fill declines that cycle by name too.
- **A provable `read` is confined by two gates, its descriptor and its answer by three more,
  and its bytes by the digest.** `ram_addr_is_the_buffer` makes the RAM query's address the
  `a1` the row read, and `read_count_is_one_word` makes the `a2` it read the literal 4 — both
  degree 2 over cells of one row, because the query and the arguments it is checked against
  are on that row. **S25a added the three that say which stream a call named and what it
  answered**: `read_descriptor` and `write_descriptor`, over one shared boolean
  `fd_uncommitted` (a set of two descriptors is not an interval, so it cannot be a range
  check and `is_read·fd·(fd − 3)` is degree 3), and `write_count_is_the_request`; a `read`'s
  answer is bounded to `[0, 4]` by the `read_count_gap_range` obligation. What that buys is
  not the refusal it refuses but the line it protects: fd 0 and fd 1 are the streams
  `io_digest` binds and fd 3 and fd 2 are the streams it does not, so a prover free to
  relabel a descriptor is a prover who can move bytes across that line.
  **The one number left free is a `read`'s exact count inside `[0, 4]`**, and it cannot be
  fixed here: how many bytes a stream had left is not a fact any row holds — the cursor lives
  in the executor, and this arithmetization has no cross-row state to keep one in. That is
  the standing limitation, stated in `docs/spec/ecall-abi.md` §4.1.
  What the circuit does *not* fix otherwise is deliberate: the word delivered (bounded below
  `2^32` by a new `RANGE16` pair and free otherwise) and everything a
  `write` emits are fd 0's and fd 1's content, and they are bound by the guest's own
  `io_digest` in `x24..x31` (`docs/spec/memory.md` §10) and not by any row. Alignment and
  residence are the memory argument's: a query at an unaligned address, or at one in no
  window the statement lists, reads a tuple nothing wrote. **S24's embedded binary is
  retired**: it proved a second binary of the same program with its witness in `.rodata`,
  which meant a per-block identity, and `crates/prover/tests/revm.rs` now proves the
  normative fd 0 / fd 1 guest instead. `guest_sdk::exit_with_public_words` is what S24 left
  behind and what the binding uses. `docs/handoff/S24-revm.md` §1.
- **The delegation ABI is `docs/spec/delegation.md`, and it is frozen**: the ecall
  convention (`a7` the number, `a0` the frame base, `a0 ← 0`, fall-through), the indirect
  frame, the anchor and its 1:1 pairing, the three request-side zeroings, static detachment
  by a `.rodata` declaration record and reachability, the alignment rules, and the
  delegation-shard ts-window convention. A later delegation family consumes it frozen and
  may only append
  frame tables. **A delegation family is invoked, not decoded**: it claims no pc, has no
  decoded table, owns no cycle, and is in a `VmConfig` exactly when the linked binary
  declares it — the third presence rule, beside "claims a pc" and "is a window family".
- **The delegated backend is a target dependency, never a cargo feature.** `field` and
  `transcript` route `Fr`'s add, multiply and inverse and `poseidon2_permute` through
  `guest_sdk::recursion`'s shims under `#[cfg(target_arch = "riscv32")]`, with a
  `[target.'cfg(target_arch = "riscv32")'.dependencies]` edge to `guest-sdk`; the fallback
  is each crate's own software path, so the two are bit-identical by construction rather
  than by a test over two copies. The direction is forced — cargo refuses the cycle, so
  `guest-sdk` may not name `Fr` and its shims take frames of bytes — and the stage prompt's
  "'delegated' cargo feature" is refused by master anti-goal 1 and by
  `crates/prover/tests/one_feature.rs`. **A guest that does field arithmetic therefore
  declares both S23 families**, because the shims are reachable from `Fr`'s operators.
- **A declaration record needs a `#[link_section]` of its own.** The linker's garbage
  collection is per section, so three records sharing one section name are kept or dropped
  together and every guest reaching any shim declares every family. `.rodata.apogee.
  delegations.<family>` per record is what makes detachment mean anything with more than one
  of them (`docs/spec/delegation.md` §7).
- **The fr-arith frame carries `Fr`'s in-memory representation, not its mathematical value**
  (owner's decision, S23). Each 32-byte group is still a canonical little-endian field
  element — the circuit's borrow chain refuses one at or above `p` — but the element is
  `x·R`, so the circuit's multiply carries the literal `R^-1` and its inverse `R^2`, and the
  three operations are exactly what `Fr`'s `Add`, `Mul` and `inverse` compute. A
  mathematically canonical frame would cost a Montgomery conversion per operand, about twice
  the software multiply the delegation replaces, and a delegated multiply would be *slower*
  than not delegating. Poseidon2's frame is the other way — canonical values, so the circuit
  is `poseidon2_permute` itself — because there the conversion is six operations against 240
  the delegation removes (`docs/spec/delegation.md` §12.1, §13.2).
- **A delegation family carries no lookup channel, and that is load-bearing.** Its height is
  `2^8` (rows are invocations, not halfwords; keccak at `2^16` is 744 GB of forward pass),
  where no range channel's table fits, so every bound it makes is a bit decomposition with a
  booleanity gate — including a frame value's **canonicity**, an eight-limb borrow chain
  against `p` whose last borrow is 1 exactly when the value is below the modulus. That is also why its registry arm sits *below* `family_circuit`'s
  minimum-height guard: a family with no channel reaches no `BITS ≤ trace_vars` assertion,
  and putting it in the guard would refuse the only height it has.
- **The anchor's value column is free on both sides, and the multiset is what pairs them.**
  A request writes `T(deleg_space, base, 4c+3, v)` and an invocation reads it; nothing fixes
  `v` locally on either side, and they cancel only when equal. What *is* pinned, by three
  gates, is the other three fields: a request writes no register, and its mirror read is
  stamped 0 with value 0. Timestamp 0 is the stamp no cycle can produce, so an invocation's
  answer tuple has exactly one reader. **What the zeroings buy is that the pairing is
  local**: a request whose mirror read is stamped is refused by a gate on its own shard,
  with no appeal to the frame's chains — which a delegation family with a smaller frame
  would have nothing else to rely on. In *this* family a dropped invocation also drops its
  50 RAM frame accesses, so the global multiset catches it first;
  `checker::assert_anchor_twins_refused` is the family-parameterized proof, and it asserts
  the zeroings at **shard** level and the dropped invocation at block level, because
  `verify_block` runs `verify_global_memory` before any shard's own checks and a twin that
  expected `Constraint` there would be asserting something false.
- **A tamper twin is proved as an honest prover would prove it.** `checker::TamperHarness`
  writes the cells, recounts the multiplicities over them (unless a multiplicity is the
  tamper, or no count exists), recommits memory columns when they change, re-proves, and
  asserts the refusal's class. It works because the prover checks nothing (S13). A
  change that breaks nothing must verify, and a test says it does.
- **One execution is one block, and a block is its shards closed.** `BlockProof` carries
  the static `VmConfig`, the statement it binds and one `ShardProof` per statement shard
  in statement order — no new evidence, no accumulator entry. `verify_block` is
  `derive_global_phase` once, three structural checks (the descriptor and the statement
  against the verifier's, shard-set exactness, the ts windows), `verify_global_memory`
  once, and then `verify_shard_local` plus the opening per shard, which is exactly what
  `verify_shard` runs. The cross-shard read/write root product is the verifier's and
  never a prover self-check. `docs/spec/block-proof.md`.
- **A check that reads only the statement runs once per block, not once per shard.**
  `verifier_core`'s split is by operand, not by convenience: `derive_global_phase`
  (steps 1–3, the global transcript) and `verify_global_memory` (step 10b — the boundary
  in range, `x10`'s final value, and `gkr_verify::reconciles` over every shard's roots
  against the boundary factors) name no `ShardProof` and have one answer for a
  statement, so `verify_block` calls each once; only `verify_shard_local` takes a proof
  and runs per shard. Per shard, step 10b would refold the same 66 boundary tuples and
  remultiply the same root product `Σ shard_counts` times for that one boolean. What
  still binds a shard into the product is **step 10a**, its own GKR output roots against
  the statement's entry for its position, which stays in `verify_shard_local` and must;
  shard-set exactness then makes every root in the product a verified shard's. The
  consequence for a caller: `verify_shard_local` alone is not a verification, and a
  block verifier that omits `verify_global_memory` has checked every circuit and no
  memory argument. The order is unchanged — step 11 cannot fail, so `reduce_shard`
  running 10b after it returns gives S16's first failure, class and message.
- **The ts window is a check on the plan, not on the trace** (owner's decision, S20).
  Each shard claims `[ts_start, ts_end)`, absorbed at S2 before its witness commitments;
  a block requires the windows of each **cycle-owning** family
  (`constants::family::CYCLE_OWNING` — the seven instruction families, not the two RAM
  window ones and not a delegation family, whose window is a sub-interval of the requesting
  family's) to be non-empty, ordered and pairwise disjoint, **per family**, because
  cycle numbers are global and two families interleave. **No gate ties a claimed window
  to the rows committed under it**: the anchoring obligation the stage prompt asked for
  was removed, because the global memory multiset already forces every live row of every
  shard onto one path from the entry pc to `HALT_PC` with strictly increasing timestamps
  (`docs/spec/memory.md` §4.2). Cross-shard ordering, cycle uniqueness and pc continuity
  are carried by that and nothing else; there is no pc chaining and no tag that could
  carry one.
- **Shard proving is the block's one parallel step**, and it costs memory. It starts only
  after the global commit phase closes, each task forks its transcript from the same
  global state, and an indexed `map` collects in order — so a block is byte-identical for
  any thread count. The price is one shard's forward pass per worker, and it **grew every
  statement in the repository**: the four-shard demo is 44 s at a 24.2 GB peak on 18
  cores and 319 s at a 10.6 GB peak on one, and `guests/mem`'s seven-shard statement went
  from 14.7 GB / 119 s to **32.3 GB / 87 s** — about 2.2× the peak for about 1.4× the
  speed, growing with the family count. There is no knob; a caller that must bound the
  peak runs `prove_block` inside a `rayon::ThreadPoolBuilder` pool of its own, which is
  what the determinism test does. Every deferred suite's peak was re-measured and the
  numbers above the line, in `.github/workflows/ci.yml` and in
  `docs/handoff/S20-orchestration.md` are that measurement.
- **A cycle-owning family's shard cannot be smaller than `2^20` rows**, so a two-shard
  family is two `2^20` shards whatever the guest. That is why the S20 demo is a new guest
  — `guests/shards`, a counted loop running 1,064,970 add/sub cycles — and not an
  existing one at `2^16`: the stage prompt's `2^16` is impossible
  (`docs/spec/lookup.md` §3), and the two guests that read an fd 0 input are unprovable
  while `EXIT` is the only provable ecall.
- **`BlockWitness` is NOT frozen, and `revm`'s version is** (owner's decisions, S24).
  `prompts/S24-revm.md` asked to freeze the witness; the owner withdrew that at the close
  of the stage because a field it is already known to need is missing. revm answers
  `BLOCKHASH` from its `Database` and `revm_block::run` gives it an empty one, so the
  opcode returns **`keccak256` of the block number's decimal string** — a placeholder,
  agreed on by guest and host, not any block's hash, and EIP-2935's history contract does
  not rescue it because revm 42 serves the opcode from the host and not from state. The
  field that closes it is a `block_hashes: Vec<(u64, Word32)>` loaded into `CacheDB`'s
  cache, and the stage that records a real block adds it; `crates/emulator/tests/revm.rs::
  blockhash_reads_a_placeholder_today` pins today's answer so it cannot close by accident.
  The **output commitment stays frozen**, and so does §1.1: whatever fields the witness
  gains, the field order is the canonical order and `decode` re-encodes and compares, so
  one logical state has exactly one encoding. `revm` is pinned `=42.0.1` for the opposite
  reason — a guest's identity is a digest of its compiled image, so a patch bump moves it
  and every number pinned against it, in both lockfiles.
- **The block's gas limit is a running bound, and `run` is what enforces it.** revm checks
  `tx.gas_limit <= block.gas_limit` per transaction and can check no more: `transact_one`
  is one transaction and revm keeps no cumulative gas anywhere. In a real client that is
  the block executor's job, and `revm_block::run` **is** the block executor, so it carries
  a running `gasUsed` and refuses a transaction whose limit does not fit in what the block
  has left — the Yellow Paper's intrinsic-validity condition, and what makes the block's
  own `gasUsed <= gasLimit` true. Without it a witness may carry any number of
  transactions that individually fit the header and together do not.
  `docs/spec/revm-block.md` §1.4. The total is not added to the output commitment: every
  transaction's `gas_used` is already a field there.
- **A guest may take a crates.io dependency when the guest is the workload.** S24's
  `revm` is the first, and the distinction is the whole licence: master rule 2 keeps the
  *proving stack's* cryptography in this repository, and a guest program is the thing
  being proven, not part of it. `revm-precompile` brings arkworks, `k256`, `p256`, `sha2`
  and `ripemd` with it for the EVM's own precompiles, and the same reading covers them —
  nothing there is reachable from a prover, a verifier or another guest. A dependency's
  own `[features]` table is invisible to `crates/prover/tests/one_feature.rs`, which reads
  only manifests inside the repository; a `features = [...]` key in *our* dependency entry
  selects an upstream crate's features and always was allowed, which is how
  `alloy-primitives`' `native-keccak` routes every keccak in a revm image through the S21
  shim.
- **`guests/revm-block` has no committed ELF**, and it is the one guest that does not
  (owner's decision, S24). It is 2.2 MB at `--release` and 7.8 MB at `debug`, where it
  expands to 1.88 million instruction slots; nothing is derived from its bytes but its
  identity, which needs the ceremony. Committing it would enrol it in every suite that
  decodes every committed guest — at `2^22` rows across 12 families, inside
  `cargo test --workspace`. `tools/artifact-dump/tests/manual.rs`'s
  `NOT_A_COMMITTED_FIXTURE` is the one exemption, checked in both directions so it cannot
  outlive its reason.
- **A decoded table's height is 1.9375 MiB of `.text` at `2^20`, and 7.9375 MiB at
  `2^22`.** Row `i` is pc `2i`, absolute, so a family's height must satisfy
  `last_pc <= 2*height - 4` — and `.text` starts at `RAM_ORIGIN` exactly. S24's release
  image uses 82% of the `2^20` reach and its debug image does not fit at all, which is why
  that guest is proven at `--release`. `2^22` is the menu's last entry; there is no step
  above it.
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
| S13 — GKR engine, circuit artifact, checker suite | done | `docs/handoff/S13-gkr.md` |
| S14 — Memory multiset argument, RAM windows, register/PC boundary | done | `docs/handoff/S14-multiset.md` |
| S15 — LogUp lookup channels + decoder lookup | done | `docs/handoff/S15-lookup.md` |
| S16 — Vertical slice: add/sub family end to end | done | `docs/handoff/S16-add-sub.md` |
| S17 — Jump/branch/slt family | done | `docs/handoff/S17-control-flow.md` |
| S18 — Shift/bitwise + mul/div families | done | `docs/handoff/S18-shift-mul.md` |
| S19 — Memory-op families + atomics | done | `docs/handoff/S19-mem.md` |
| S20 — Sharding + block orchestration | done | `docs/handoff/S20-orchestration.md` |
| S21 — keccak256 delegation + the delegation ABI | done | `docs/handoff/S21-keccak256.md` |
| S22 — secp256k1 ecrecover delegation | **cancelled** | `prompts/00-master.md`, "Stage register" |
| S23 — Fr-arithmetic + Poseidon2 delegations | done | `docs/handoff/S23-fr-poseidon2.md` |
| S24 — revm guest, synthetic-state block | done | `docs/handoff/S24-revm.md` |
| S25 — Witness pipeline, real blocks, bench harness | **in progress**: S25a, the public-I/O binding, is the first of its PRs | at the stage's end |
