# Architecture

Apogee proves executions of RV32IMAC programs. This page is the system end to end: what a proof
states, how one is made and checked, what it assumes and where it stops. Each paragraph names the
page that specifies its subject; [glossary.md](glossary.md) indexes the vocabulary.

## 1. What a proof states

A verifier holds three things it does not take from the prover's word, and two of them from a
channel the prover does not control ([proof.md](spec/proof.md) §1, §3):

- the **program identity**, one field element: a digest of the program's instruction tables, its
  initial memory image, its entry pc and its `VmConfig` — the circuit families it uses and their
  heights ([program.md](spec/program.md) §8);
- the **SRS digest** of the ceremony, which a verifying key must carry;
- a **verifying key**: that config, each family's circuit and setup commitments, the SRS's verifier
  points and the generic lookup table's commitments. Loading it recomputes the identity and the SRS
  digest from its own contents and holds its circuits to the registry's bytes
  ([proof.md](spec/proof.md) §7).

The proof's **statement**, `PublicInputs`, carries the public input bytes, the public output bytes
(the **journal**), the exit status, and the record of the execution's shape — shard counts, memory
windows, the final registers and pc, every shard's memory commitments and roots
([proof.md](spec/proof.md) §1).

A proof that verifies establishes that the program of that identity, started at its entry pc over
its image, with the public input in its input window and some advice of the prover's choosing,
executes instruction by instruction to `EXIT` with that status, having written that journal.
Nothing is claimed of the advice, and nothing is hidden: no commitment or proof is blinded.

## 2. From a binary to a proof

1. **The program.** `loader` reads the ELF into a `ProgramImage`, expanding compressed instructions
   in place; `isa` decodes; `program` routes each instruction to one of seven instruction families,
   builds every family's decoded table — a row per halfword of code — and commits to them as the
   identity ([program.md](spec/program.md)).
2. **Execution.** `emulator` runs the guest. A cycle is one row of the family that owns its
   instruction, recording its memory queries: timestamped reads and writes of the pc, registers and
   RAM ([execution-trace.md](spec/execution-trace.md)). A guest issues no system call but `EXIT`:
   its input, journal and advice are regions of memory ([public-values.md](spec/public-values.md),
   [ecall-abi.md](spec/ecall-abi.md)). Hashing and big-integer arithmetic are **delegated**: an
   `ecall` names a frame in RAM, and a row of a delegation family does the work on it
   ([delegation.md](spec/delegation.md), [delegation-circuits.md](spec/delegation-circuits.md)).
3. **Shards.** A family's rows are cut into **shards** of the family's height, a power of two
   between `2^8` and `2^22`. The memory an execution touches is covered by shards of the window
   families, which give each word its initial and final tuple ([memory.md](spec/memory.md) §3). A
   shard is the unit of proving; a block is hundreds ([circuits.md](spec/circuits.md) §1).
4. **A shard's proof.** Its columns are committed with Mercury ([mercury.md](spec/mercury.md)). The
   family's GKR circuit is run backward from its outputs to those columns, a sumcheck a layer
   ([gkr.md](spec/gkr.md)), and every column is opened at the one point that pass ends on, in one
   batched opening ([proof.md](spec/proof.md) §5).
5. **The block.** A `BlockProof` is the statement and its shard proofs. `verify_block` runs the
   global transcript once, each shard's checks, and once the memory reconciliation over every
   shard's roots ([proof.md](spec/proof.md) §6).
6. **Recursion.** Verifier programs, proved by this VM in a format of its own, verify runs of shards
   and fold their deferred pairings; a tree of them ends in a root, a Groth16 circuit re-verifies
   the root, and `ApogeeVerifier.sol` checks that proof and the folded pairing
   ([recursion.md](spec/recursion.md)).

The prover executes the guest twice: once to commit every shard's memory columns, which fixes the
statement and its challenges, and once to prove each shard as it fills. Its memory is bounded by the
shards in flight, not by the execution ([streaming.md](spec/streaming.md)).

## 3. How soundness composes

Each shard's GKR pass and opening tie its circuit's outputs to committed columns. On top of that,
these arguments span the execution:

| claim | carried by | |
| --- | --- | --- |
| every row obeys its instruction | the family circuit's enforcing gates, zero on every row | the family pages, [circuits.md](spec/circuits.md) |
| a row's instruction is the program's at its pc | a lookup of the row's pc and fields in the family's decoded table, which the identity commits | [lookup.md](spec/lookup.md) §10 |
| every read returns the last write | one multiset over all shards: an access reads a tuple `(space, address, timestamp, value)` and writes one with a later timestamp; the verifier multiplies every shard's read and write roots against boundary factors for the registers and the pc | [memory.md](spec/memory.md) |
| the rows are one path from the entry pc to the exit, in program order | the pc is a cell of that multiset: a row reads its pc and writes the next one at least four timestamps later, so shard order, cycle uniqueness and continuity need no other argument | [memory.md](spec/memory.md) §5, §9 |
| a value is a byte, a word, a sign, an XOR | LogUp channels over range, byte and generic tables | [lookup.md](spec/lookup.md) |
| the public input and the journal are the claimed bytes | the two public windows' initial and final columns, held to the bytes' multilinear extensions | [public-values.md](spec/public-values.md) §5 |
| a delegated computation is the function's | invocation rows that read and write the frame through the same multiset, paired one to one with their `ecall` by an anchor tuple | [delegation.md](spec/delegation.md) §5 |

Challenges come from a Poseidon2 duplex transcript ([transcript.md](spec/transcript.md)). The
global transcript absorbs the whole statement, every shard's memory commitments included, before
the memory challenges exist; each shard's transcript is seeded from its final state
([proof.md](spec/proof.md) §2, §4).

## 4. What it assumes

- **Cryptography.** Mercury's and KZG's knowledge soundness in the algebraic group model under
  q-DLOG ([mercury.md](spec/mercury.md) §7); Poseidon2 as a random oracle for Fiat–Shamir; for the
  last step, Groth16's own assumptions. BN254 gives about 100 bits.
- **Setup.** The SRS is the PSE perpetual powers of tau, sound while one contributor was honest. The
  code checks a file's structure and decodes every point; nothing proves it is that ceremony's, and
  no proving path runs `Srs::validate` ([srs.md](spec/srs.md) §3). The decider's Groth16 key comes
  from a second, circuit-specific ceremony ([recursion.md](spec/recursion.md) §9).
- **What a verifier must obtain itself.** The program identity and the ceremony's SRS digest. A key
  loads under whatever digest its own points give, so a key built over a known `τ` is refused only
  by that comparison; the `verifier` CLI compares identity only, and `host::verify` neither
  ([proof.md](spec/proof.md) §1, §3).
- **Trusted code.** Soundness is the verifier's alone: `constants`, `field`, `curve`, `transcript`,
  `poly`, `sumcheck`, `pcs-verify`, `pcs`, `gkr-verify`, `verifier-core`, `verifier`, and
  `constraints` — the circuits are part of the statement, and a missing gate is a soundness bug.
  Computing an identity from an ELF trusts `loader`, `isa` and `program`. The last step adds
  `guests/recursion`, `groth16`, the decider's circuit and the contract. `prover`, `emulator`,
  `trace` and the proving half of `host` are untrusted: the prover validates nothing, and a wrong
  input costs an honest prover a proof that fails.
- **Nothing is constant-time** ([primitives.md](spec/primitives.md)). No proof is zero-knowledge, so
  proving keeps nothing secret; the one secret the code handles is a Groth16 ceremony contributor's
  factor, which `groth16::phase2` multiplies in with the same variable-time ladder.

## 5. Limits

| | |
| --- | --- |
| not zero-knowledge | no blinding in Mercury, GKR or the Groth16 decider |
| advice is unbound | a guest checks it against something a proof binds ([public-values.md](spec/public-values.md) §6) |
| public values | at most 16,380 bytes each of input and journal ([public-values.md](spec/public-values.md) §9) |
| `sc.w` always succeeds | the one deviation from RV32IMAC's semantics; there is no reservation state ([memory-ops.md](spec/memory-ops.md) §6) |
| traps are not provable | a misaligned access, an access outside mapped memory, `ebreak` or a pc with no instruction ends an execution with no proof ([execution-trace.md](spec/execution-trace.md) §10) |
| code is static | the instruction stream is the image decoded at load; one undecodable word in an executable segment refuses the program ([program.md](spec/program.md)) |
| code size | `.text` within a decoded table's reach of its load address, 7.94 MiB at `2^22`, and the image within `bytecode_size_words`, 4 MiB by default ([program.md](spec/program.md) §5, §7) |
| execution length | timestamps are 38 bits: `2^36 − 1` cycles ([execution-trace.md](spec/execution-trace.md) §1) |
| delegations are a fixed set | six in the base format; an EVM `MULMOD` with an arbitrary modulus is not one; a delegation proves one step of its function, and composing steps, validating curve points among them, is the calling code's ([delegation.md](spec/delegation.md) §11, [delegation-circuits.md](spec/delegation-circuits.md)) |
| prover memory | set by the shards in flight: the measured full block peaked at 174 GiB ([streaming.md](spec/streaming.md) §1) |
| block witnesses | the stateless validator takes its input from an external witness producer; the built-in recorder cannot record every block ([ethereum.md](spec/ethereum.md) §4, §6) |
| the decider's key | one per root shape, and only as trustworthy as its ceremony; the development key is forgeable ([recursion.md](spec/recursion.md) §9) |
| on-chain cost | about 3.6M gas for the measured block ([recursion.md](spec/recursion.md) §10) |

## 6. How the code is checked

No component is checked against a second implementation of the whole system; each layer has its
own independent oracle.

| layer | checked against |
| --- | --- |
| fields, curve, pairing, MSM | known-answer vectors generated from arkworks, which the tests also run live |
| Poseidon2 and the transcript | `tools/transcript-ref`: Plonky3 and zkhash |
| the decoder | every 32-bit word of the instruction space against counts from the ISA; `llvm-objdump` over the committed guests |
| circuits as data | `checker`: the circuit laws, the lookup rules and the padding contract re-implemented without `constraints`' code, sharing only the gate kernel ([circuits.md](spec/circuits.md) §3) |
| each family's gates | row suites that build rows with Rust's own integer arithmetic and evaluate them through the checker; the arithmetic cores exhaustively at reduced word widths; **tamper twins**, a forged witness proved as an honest prover would and refused in the expected class |
| the memory and lookup arguments | native evaluators in `checker` over executed traces |
| the executor | its own trace's self-check and the arguments above; there is no second executor, and no executor here takes a delegation shim's software fallback |
| the revm guest | native revm, built from unpatched upstream crates |
| the stateless validator | a committed subset of `tests-zkevm` v21.0.1 natively in CI; the whole release natively and the subset through the guest binary by hand; `tools/stateless-ref` for the input encoding |
| the decider | the proof checked natively, and the contract executed in revm |

Committed fixtures are regenerated and compared in CI ([tools.md](tools.md) §7). The suites that
prove real shards, over a toy SRS, need tens of GiB and run outside CI ([README](../README.md)).

## 7. Cost

[recursion.md](spec/recursion.md) §10 has the end-to-end measurements for one block, from the base
proof to the contract call; [streaming.md](spec/streaming.md) §1 breaks the base proof down; and
[circuits.md](spec/circuits.md) §1 gives every circuit's width and proof size, which a shard's cost
follows.

## References

- L. Eagen, A. Gabizon. *MERCURY: A multilinear polynomial commitment scheme with constant proof
  size and linear field work.* ePrint 2025/385. `publication/2025-385.pdf`
- D. Boneh, J. Drake, B. Fisch, A. Gabizon. *Efficient polynomial commitment schemes for multiple
  points and polynomials.* ePrint 2020/081. `publication/2020-081.pdf`
- J.-L. Beuchat et al. *High-speed software implementation of the optimal ate pairing over
  Barreto–Naehrig curves.* ePrint 2010/354. `publication/2010-354.pdf`
