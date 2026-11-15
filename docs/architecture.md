# Architecture

Apogee proves executions of RV64IMAC programs, written in Rust or in C and C++
([guest-program-manual.md](guest-program-manual.md)). This page is the system end to end: what a proof
states, how one is made and checked, what it assumes and where it stops. Each paragraph names the
page that specifies its subject; [glossary.md](glossary.md) indexes the vocabulary.

## 0. ALARM — UNFINISHED — WARNING — TODO: A64-C5 CHARACTERISTIC

**Every proof this repository makes is UNSOUND.** The base field is A64-C5, `p = 2^64 − 59`, and
every challenge is an element of its quadratic extension ([primitives.md](spec/primitives.md) §1).
One integer argument does not hold at `p ≈ 2^64`: the memory argument's count of timestamps,
which nothing bounds ([memory.md](spec/memory.md) §4.2). Every execution family's identities are
exact over the integers, `MUL_DIV`'s product among them ([mul-div.md](spec/mul-div.md) §5.1). Each
seam is marked:

```console
$ grep -rn "A64-C5 CHARACTERISTIC" crates
```

Every committed column is committed, and every claim on one opened, by Akita
([pcs.md](spec/pcs.md)): the setup columns in the key, digested into the identity; each shard's
memory columns in the statement, before the memory challenges; its witness columns in its proof,
before its lookup challenges ([proof.md](spec/proof.md) §3). The suites that prove a statement are
`#[ignore]`d for their cost, and run by name.

## 1. What a proof states

A verifier holds two things it does not take from the prover's word, one of them from a channel the
prover does not control ([proof.md](spec/proof.md) §1, §3):

- the **program identity**, a digest of eight field elements: of the code version, the program's
  `VmConfig` — the circuit families it uses and their heights — its entry pc, and the commitments
  to its instruction tables, its initial memory image and the generic lookup table
  ([program.md](spec/program.md) §8);
- a **verifying key**: that config, those commitments and each family's circuit. Loading it
  recomputes the identity from its own contents and holds its circuits to the registry's bytes
  ([proof.md](spec/proof.md) §7).

The proof's **statement**, `PublicInputs`, carries the public input bytes, the public output bytes
(the **journal**), the exit status, and the record of the execution's shape — shard counts, memory
windows, the final registers and pc, and every shard's memory commitment and roots
([proof.md](spec/proof.md) §1).

A proof that verifies is meant to establish that the program of that identity, started at its entry
pc over its image, with the public input in its input window and some advice of the prover's
choosing, executes instruction by instruction to `EXIT` with that status, having written that
journal — **UNFINISHED** (§0). Nothing is claimed of the advice, and nothing is hidden: no proof is
blinded.

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
   column is claimed, and every claim is opened at once against the columns' commitments
   ([proof.md](spec/proof.md) §5, [pcs.md](spec/pcs.md)).
5. **The block.** A `BlockProof` is the statement and its shard proofs. `verify_block` runs the
   global transcript once, each shard's checks, and once the memory reconciliation over every
   shard's roots ([proof.md](spec/proof.md) §6).

The prover executes the guest twice: once to fix the statement and its challenges, and once to
prove each shard as it fills. Its memory is bounded by the shards in flight, not by the execution
([streaming.md](spec/streaming.md)).

## 3. How soundness composes

Each shard's GKR pass ties its circuit's outputs to its base columns' claimed values, and its
opening ties those to the committed columns. On top of that, these arguments span the execution —
**UNFINISHED** where §0 says:

| claim | carried by | |
| --- | --- | --- |
| every row obeys its instruction | the family circuit's enforcing gates, zero on every row | the family pages, [circuits.md](spec/circuits.md) |
| a row's instruction is the program's at its pc | a lookup of the row's pc and fields in the family's decoded table, which the identity commits | [lookup.md](spec/lookup.md) §10 |
| every read returns the last write | one multiset over all shards: an access reads a tuple `(space, address, timestamp, value)` and writes one with a later timestamp; the verifier multiplies every shard's read and write roots against boundary factors for the registers and the pc | [memory.md](spec/memory.md) |
| the rows are one path from the entry pc to the exit, in program order | the pc is a cell of that multiset: a row reads its pc and writes the next one at least four timestamps later, so shard order, cycle uniqueness and continuity need no other argument | [memory.md](spec/memory.md) §5, §9 |
| a value is in range, a sign, a byte-wise AND | LogUp channels over range tables and the generic table | [lookup.md](spec/lookup.md) |
| the public input and the journal are the claimed bytes | the two public windows' initial and final columns, held to the bytes' multilinear extensions | [public-values.md](spec/public-values.md) §5 |

Challenges come from a Poseidon2 duplex transcript over A64-C5, each an element of its quadratic
extension ([transcript.md](spec/transcript.md)). The
global transcript absorbs the whole statement, every shard's memory commitment among it, before the
memory challenges exist; each shard's transcript is seeded from its final state and absorbs the
shard's witness commitment before its lookup challenges ([proof.md](spec/proof.md) §2, §4).

## 4. What it assumes

- **Cryptography.** Poseidon2 as a random oracle for Fiat–Shamir, and Module-SIS at 128 bits of
  quantum Core-SVP security for Akita's binding ([pcs.md](spec/pcs.md) §6).
- **What a verifier must obtain itself.** The program identity. A key loads under whatever identity
  its own contents give, so a key for another program is refused only by comparing identities; the
  `verifier` CLI makes that comparison, and `host::verify` does not ([proof.md](spec/proof.md) §1).
- **Trusted code.** Soundness is the verifier's alone: `constants`, `field`, `transcript`, `poly`,
  `sumcheck`, `gkr-verify`, `pcs-verify`, `verifier-core`, `verifier`, and `constraints` — the circuits are part of
  the statement, and a missing gate is a soundness bug. Computing an identity from an ELF trusts
  `loader`, `isa`, `program` and `pcs`. `prover`, `emulator`, `trace` and `host` are untrusted: the prover
  validates nothing, and a wrong input costs an honest prover a proof that fails.
- **Nothing is constant-time** ([primitives.md](spec/primitives.md)). No proof is zero-knowledge, so
  proving keeps nothing secret.

## 5. Limits

| | |
| --- | --- |
| **unsound** | the memory argument's timestamp count fails at A64-C5's characteristic (§0) |
| not zero-knowledge | no blinding in GKR |
| advice is unbound | a guest checks it against something a proof binds ([public-values.md](spec/public-values.md) §6) |
| public values | at most 16,380 bytes each of input and journal ([public-values.md](spec/public-values.md) §9) |
| `sc` always succeeds | the one deviation from RV64IMAC's semantics; there is no reservation state ([memory-ops.md](spec/memory-ops.md) §6) |
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
| the field and its extension | Rust's own `u128` arithmetic |
| multilinear polynomials | `ark-poly` over arkworks' own A64-C5 field and its extension: known-answer vectors it generates, and live |
| Poseidon2 and the transcript | the generator's own Poseidon2 in Sage ([tools.md](tools.md) §8); spongefish's duplex, transcribed |
| the decoder | every 32-bit word of the instruction space against counts from the ISA; `llvm-objdump` over the guests, built from source |
| circuits as data | `checker`: the circuit laws, the lookup rules and the padding contract re-implemented without `constraints`' code, sharing only the gate kernel ([circuits.md](spec/circuits.md) §3) |
| each family's gates | row suites that build rows with Rust's own integer arithmetic and evaluate them through the checker; the arithmetic cores exhaustively at reduced word widths; **tamper twins**, a forged witness proved as an honest prover would and refused in the expected class |
| the memory and lookup arguments | native evaluators in `checker` over executed traces |
| the executor | its own trace's self-check and the arguments above; there is no second executor |

The suites that prove real shards need up to 22 GB and run outside CI;
`.github/workflows/ci.yml` lists them.

## 7. Cost

[circuits.md](spec/circuits.md) §1 gives every circuit's width and proof size, which a shard's cost
follows, and [streaming.md](spec/streaming.md) §5 what bounds the prover's memory.
