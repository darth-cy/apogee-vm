# Architecture

Apogee proves executions of RV32IMAC programs. This page is the system end to end: what a proof
states, how one is made and checked, what it assumes and where it stops. Each paragraph names the
page that specifies its subject; [glossary.md](glossary.md) indexes the vocabulary.

## 0. ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME

**This repository is UNCOMMITTED, and every proof it makes is UNSOUND.** The polynomial commitment
scheme was removed, with everything built on it, and nothing was put in its place: the void is
deliberate, and a later commitment scheme must fill it. Until one does:

- **No column of any shard is committed.** The verifier checks every GKR pass, every LogUp channel
  and the memory argument's arithmetic, and then takes every base-layer column value on the
  prover's word: the claims `verifier_core::reduce_shard` returns are dropped unchecked in
  `verifier::discharge`.
- **No challenge binds a column.** The memory challenges are drawn with no shard's memory columns
  absorbed, and each shard's lookup challenges `g` and `β` with none of its witness columns, so a
  prover may choose its columns after the challenges. The memory and lookup arguments are unsound.
- **The program identity binds no code.** It digests the code version, the `VmConfig` and the entry
  pc ([program.md](spec/program.md) §8). Nothing commits the decoded tables, the image column or the
  generic lookup table, so two programs with one config and one entry pc share an identity.
- **Nothing carries a commitment.** The verifying key has no setup commitments, the statement no
  memory commitments, and a shard proof neither witness commitments nor an opening.

Every place a commitment or an opening belongs is marked in the code, and every test of a property
only a commitment scheme can restore is `#[ignore]`d with an `UNFINISHED` reason and named
`UNFINISHED_*`:

```console
$ grep -rn "NO COMMITMENT SCHEME" crates tools
$ grep -rn "UNFINISHED_" crates tools
```

| where | what belongs there |
| --- | --- |
| `verifier_core::identity_digest` | each family's setup-column commitments, digested into the identity |
| `verifier_core::global_transcript` | every statement shard's memory-column commitments, before the boundary and the memory challenges |
| `verifier_core::shard_transcript` | the shard's witness commitments, multiplicities included, before `g` and `β` |
| `verifier_core::derive_global_phase`, step 3 | each shard's memory commitment list, held to its family's memory width |
| `verifier_core::reduce_shard` and `ColumnClaims` | the commitments every column claim is opened against |
| `verifier::discharge` | the commitment scheme's verifier: one opening of every committed column at the claims' point |
| `VerifyingKey`, `PublicInputs`, `ShardProof` | the fields that carry the commitments and the opening |
| `prover::ProverSetup::new` | committing the setup columns |
| `prover::statement_inputs`, `prover::global_commit_phase` | committing every shard's memory columns |
| `prover`'s `gkr_part` and `proof_part`, `phases.rs` | committing the witness columns; the opening |
| `prover::streaming`, pass 1 and pass 2 | committing each shard's memory columns as it fills; opening them |
| `checker::TamperHarness` | re-committing a tampered memory column |

The field is BN254's scalar field `Fr` ([primitives.md](spec/primitives.md) §1), and stays it until a
later stage moves it.

## 1. What a proof states

A verifier holds two things it does not take from the prover's word, one of them from a channel the
prover does not control ([proof.md](spec/proof.md) §1, §3):

- the **program identity**, one field element: a digest of the code version, the program's
  `VmConfig` — the circuit families it uses and their heights — and its entry pc
  ([program.md](spec/program.md) §8). **UNFINISHED** (§0): it is meant to commit the program's
  instruction tables and initial memory image too, and does not;
- a **verifying key**: that config and each family's circuit. Loading it recomputes the identity
  from its own contents and holds its circuits to the registry's bytes ([proof.md](spec/proof.md)
  §7).

The proof's **statement**, `PublicInputs`, carries the public input bytes, the public output bytes
(the **journal**), the exit status, and the record of the execution's shape — shard counts, memory
windows, the final registers and pc, and every shard's memory roots ([proof.md](spec/proof.md) §1).

A proof that verifies is meant to establish that the program of that identity, started at its entry
pc over its image, with the public input in its input window and some advice of the prover's
choosing, executes instruction by instruction to `EXIT` with that status, having written that
journal. **Until a commitment scheme exists it establishes nothing** (§0). Nothing is claimed of the
advice, and nothing is hidden: no proof is blinded.

## 2. From a binary to a proof

1. **The program.** `loader` reads the ELF into a `ProgramImage`, expanding compressed instructions
   in place; `isa` decodes; `program` routes each instruction to one of seven instruction families,
   builds every family's decoded table — a row per halfword of code — and digests the identity
   ([program.md](spec/program.md)).
2. **Execution.** `emulator` runs the guest. A cycle is one row of the family that owns its
   instruction, recording its memory queries: timestamped reads and writes of the pc, registers and
   RAM ([execution-trace.md](spec/execution-trace.md)). A guest issues no system call but `EXIT`:
   its input, journal and advice are regions of memory ([public-values.md](spec/public-values.md),
   [ecall-abi.md](spec/ecall-abi.md)).
3. **Shards.** A family's rows are cut into **shards** of the family's height, a power of two
   between `2^12` and `2^22`. The memory an execution touches is covered by shards of the window
   families, which give each word its initial and final tuple ([memory.md](spec/memory.md) §3). A
   shard is the unit of proving ([circuits.md](spec/circuits.md) §1).
4. **A shard's proof.** The family's GKR circuit is run backward from its outputs to its base
   columns, a sumcheck a layer ([gkr.md](spec/gkr.md)), ending on one point at which every base
   column is claimed ([proof.md](spec/proof.md) §5). **UNFINISHED** (§0): no column is committed
   and no claim is opened.
5. **The block.** A `BlockProof` is the statement and its shard proofs. `verify_block` runs the
   global transcript once, each shard's checks, and once the memory reconciliation over every
   shard's roots ([proof.md](spec/proof.md) §6).

The prover executes the guest twice: once to fix the statement and its challenges, and once to
prove each shard as it fills. Its memory is bounded by the shards in flight, not by the execution
([streaming.md](spec/streaming.md)).

## 3. How soundness composes

**None of this is sound until a commitment scheme exists** (§0). Each shard's GKR pass ties its
circuit's outputs to its base columns' claimed values, and nothing ties those values to anything. On
top of that, these arguments are meant to span the execution:

| claim | carried by | |
| --- | --- | --- |
| every row obeys its instruction | the family circuit's enforcing gates, zero on every row | the family pages, [circuits.md](spec/circuits.md) |
| a row's instruction is the program's at its pc | a lookup of the row's pc and fields in the family's decoded table, which the identity is meant to commit | [lookup.md](spec/lookup.md) §10 |
| every read returns the last write | one multiset over all shards: an access reads a tuple `(space, address, timestamp, value)` and writes one with a later timestamp; the verifier multiplies every shard's read and write roots against boundary factors for the registers and the pc | [memory.md](spec/memory.md) |
| the rows are one path from the entry pc to the exit, in program order | the pc is a cell of that multiset: a row reads its pc and writes the next one at least four timestamps later, so shard order, cycle uniqueness and continuity need no other argument | [memory.md](spec/memory.md) §5, §9 |
| a value is in range, a sign, a byte-wise AND | LogUp channels over range tables and the generic table | [lookup.md](spec/lookup.md) |
| the public input and the journal are the claimed bytes | the two public windows' initial and final columns, held to the bytes' multilinear extensions | [public-values.md](spec/public-values.md) §5 |

Challenges come from a Poseidon2 duplex transcript ([transcript.md](spec/transcript.md)). The
global transcript absorbs the whole statement before the memory challenges exist, but none of a
shard's columns (§0); each shard's transcript is seeded from its final state
([proof.md](spec/proof.md) §2, §4).

## 4. What it assumes

- **Cryptography.** Poseidon2 as a random oracle for Fiat–Shamir. There is no commitment scheme,
  so there is no soundness for any other assumption to carry (§0).
- **What a verifier must obtain itself.** The program identity. A key loads under whatever identity
  its own contents give, so a key for another program is refused only by comparing identities; the
  `verifier` CLI makes that comparison, and `host::verify` does not ([proof.md](spec/proof.md) §1).
- **Trusted code.** Soundness is the verifier's alone: `constants`, `field`, `transcript`, `poly`,
  `sumcheck`, `gkr-verify`, `verifier-core`, `verifier`, and `constraints` — the circuits are part of
  the statement, and a missing gate is a soundness bug. Computing an identity from an ELF trusts
  `loader`, `isa` and `program`. `prover`, `emulator`, `trace` and `host` are untrusted: the prover
  validates nothing, and a wrong input costs an honest prover a proof that fails.
- **Nothing is constant-time** ([primitives.md](spec/primitives.md)). No proof is zero-knowledge, so
  proving keeps nothing secret.

## 5. Limits

| | |
| --- | --- |
| **unsound** | there is no commitment scheme (§0) |
| not zero-knowledge | no blinding in GKR |
| advice is unbound | a guest checks it against something a proof binds ([public-values.md](spec/public-values.md) §6) |
| public values | at most 16,380 bytes each of input and journal ([public-values.md](spec/public-values.md) §9) |
| `sc.w` always succeeds | the one deviation from RV32IMAC's semantics; there is no reservation state ([memory-ops.md](spec/memory-ops.md) §6) |
| traps are not provable | a misaligned access, an access outside mapped memory, `ebreak` or a pc with no instruction ends an execution with no proof ([execution-trace.md](spec/execution-trace.md) §10) |
| code is static | the instruction stream is the image decoded at load; one undecodable word in an executable segment refuses the program ([program.md](spec/program.md)) |
| code size | `.text` within a decoded table's reach of its load address, 7.94 MiB at `2^22`, and the image within `bytecode_size_words`, 4 MiB by default ([program.md](spec/program.md) §5, §7) |
| execution length | timestamps are 38 bits: `2^36 − 1` cycles ([execution-trace.md](spec/execution-trace.md) §1) |
| prover memory | set by the shards in flight ([streaming.md](spec/streaming.md) §5) |

## 6. How the code is checked

No component is checked against a second implementation of the whole system; each layer has its
own independent oracle.

| layer | checked against |
| --- | --- |
| the field | known-answer vectors generated from arkworks' `ark-ff`, which the tests also run live |
| multilinear polynomials | known-answer vectors generated from `ark-poly` |
| Poseidon2 and the transcript | `tools/transcript-ref`: Plonky3 and zkhash |
| the decoder | every 32-bit word of the instruction space against counts from the ISA; `llvm-objdump` over the committed guests |
| circuits as data | `checker`: the circuit laws, the lookup rules and the padding contract re-implemented without `constraints`' code, sharing only the gate kernel ([circuits.md](spec/circuits.md) §3) |
| each family's gates | row suites that build rows with Rust's own integer arithmetic and evaluate them through the checker; the arithmetic cores exhaustively at reduced word widths; **tamper twins**, a forged witness proved as an honest prover would and refused in the expected class |
| the memory and lookup arguments | native evaluators in `checker` over executed traces |
| the executor | its own trace's self-check and the arguments above; there is no second executor |

Committed fixtures are regenerated and compared in CI ([tools.md](tools.md) §7). The suites that
prove real shards need tens of GiB and run outside CI; `.github/workflows/ci.yml` lists them.

## 7. Cost

[circuits.md](spec/circuits.md) §1 gives every circuit's width and proof size, which a shard's cost
follows, and [streaming.md](spec/streaming.md) §5 what bounds the prover's memory.
