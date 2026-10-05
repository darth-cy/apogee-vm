# Glossary

The project's own vocabulary, one line a term, each linked to the section that defines it. Terms
the literature fixes (GKR, LogUp, KZG, RISC-V) are not listed.

| term | meaning | defined in |
| --- | --- | --- |
| accumulator, accumulator entry | a deferred Mercury check as twelve `(side, scalar, point)` entries | [mercury.md §6](spec/mercury.md) |
| advice | memory whose initial values the prover chose, bound by nothing | [public-values.md §6](spec/public-values.md) |
| anchor, anchor space | tuples in a delegation type's own space pairing a request with one invocation | [delegation.md §5](spec/delegation.md) |
| archived path | proving from a held `TraceArchive`; only the tamper harness does | [streaming.md §6](spec/streaming.md) |
| artifact | a circuit as data, `CircuitArtifact`; also an exported `ProgramImage` | [gkr.md §4](spec/gkr.md), [program.md §3](spec/program.md) |
| base claims | each committed column's claimed value where the backward pass ends | [gkr.md §5](spec/gkr.md) |
| base format, recursion format | recursion if a statement's `VmConfig` holds `FIELD_WINDOWS`, else base | [recursion.md §1](spec/recursion.md) |
| block | `BlockProof`: config, statement and its shards' proofs | [proof.md §1](spec/proof.md) |
| bound wire | a decider value the verifier holds, committed instead of a public input | [recursion.md §9](spec/recursion.md) |
| boundary | the registers' and pc's final timestamps and values; they have no rows | [memory.md §4](spec/memory.md) |
| cached entry | a sub-expression inlined into its list's gates, not a column | [gkr.md §3](spec/gkr.md) |
| canonical form | an element as its value, 32 bytes little-endian, below the modulus | [primitives.md §1](spec/primitives.md) |
| challenge slot | a gate coefficient's challenge: drawn, or derived by the verifier | [gkr.md §3, §5](spec/gkr.md) |
| channel | one LogUp identity over a shard's lookups into one table | [lookup.md §1](spec/lookup.md) |
| copower | `x < p` as `x·2^32/p < 2^32`, void without a direct bound | [lookup.md §11](spec/lookup.md) |
| cycle-owning | the execution families 0–6, whose time windows are ordered | [proof.md §8](spec/proof.md) |
| decider | a Groth16 proof that the recursion root verifies, for the contract | [recursion.md §9](spec/recursion.md) |
| declaration record, static detachment | 12 bytes a linked shim leaves in the image: how a delegation is declared | [delegation.md §7](spec/delegation.md) |
| decoded table | an instruction family's setup columns: row `i` is pc `2i` | [program.md §5](spec/program.md) |
| delegation | a family proving a function of a RAM frame, invoked by `ecall` | [delegation.md §1](spec/delegation.md) |
| discharge | spending an accumulator; the rule that each lookup is one leaf of its tree | [mercury.md §6](spec/mercury.md), [lookup.md §11](spec/lookup.md) |
| enforcing, producing | a gate vanishing on every row; one writing the next layer | [gkr.md §1](spec/gkr.md) |
| extra mask, kind, kind bit | `family_extra_mask` = `1 << kind`, a kind being a mnemonic's index; `b_k` its bit | [program.md §6](spec/program.md) |
| family | a circuit and the rows it proves: instructions (0–6), memory locations or invocations | [circuits.md §1](spec/circuits.md) |
| field memory | address space `FIELD`: cells of one `Fr`, for the recursion families | [recursion.md §2](spec/recursion.md) |
| fold | merging a node's deferred Mercury checks into one `(A, B)` | [recursion.md §8](spec/recursion.md) |
| frame | an execution family's queries; a delegation's RAM words at `a0` | [memory.md §2](spec/memory.md), [delegation.md §4](spec/delegation.md) |
| gate list, row-wise, halving | the gates from layer `k` to `k + 1`, keeping the height or halving it | [gkr.md §1](spec/gkr.md) |
| gated key, neutral tuple | a lookup tuple under its selector; off, it reads a neutral table row | [lookup.md §4](spec/lookup.md) |
| generic table | the committed table of `ZeroEntry`, AND, `U16GetSign`, `ShiftPowers` | [lookup.md §9](spec/lookup.md) |
| global transcript, global state digest | G1–G11: the statement, `M` commitments, memory challenges; G11 seeds each shard | [proof.md §2](spec/proof.md) |
| `HALT_PC` | 1: the exit row's `next_pc`, the pc's final value | [memory.md §5](spec/memory.md) |
| height | a family's rows a shard: `2^8`, `2^12`, `2^16`, `2^18`, `2^20` or `2^22` | [program.md §7](spec/program.md) |
| identity, image column | one `Fr` digest of the decoded tables, the image, the entry pc, `VmConfig` | [program.md §8](spec/program.md) |
| in flight | shards worked at once, at most `max_in_flight` | [streaming.md §5](spec/streaming.md) |
| invocation, request | a delegation's row doing one call; the `ecall` row asking for it | [delegation.md §1, §5](spec/delegation.md) |
| journal | the public output: what the guest leaves in the output window | [public-values.md §1](spec/public-values.md) |
| laws | Laws 1–4: locality, derived width, top layer, single source of truth | [gkr.md §4](spec/gkr.md) |
| layer | layer 0 the committed columns, the top the outputs; `L{k}[j]` between | [gkr.md §1](spec/gkr.md) |
| leaf, node, root | recursion programs: a leaf verifies base shards, a node 2–4 child proofs; the root, all | [recursion.md §8](spec/recursion.md) |
| live row, padding row | `m_pc = 1`, or a zero row; in a decoded table, an instruction, or −1 throughout | [memory.md §2](spec/memory.md), [program.md §5](spec/program.md) |
| `M`, `W`, `S`, `V` | memory, witness and setup columns; virtual tables | [gkr.md §2](spec/gkr.md) |
| memory form | an `Fr`'s Montgomery limbs `x·R`; on the wire only in `FR_ARITH`'s frame | [primitives.md §1](spec/primitives.md) |
| mini-block | the `revm-block` binary: transactions over a recorded pre-state | [ethereum.md §1](spec/ethereum.md) |
| multiplicity | a channel's `W` column counting each table row's lookups | [lookup.md §7](spec/lookup.md) |
| padding contract | `padding.row` makes row-local relations vanish and tree inputs 1 | [gkr.md §4](spec/gkr.md) |
| pairing side | `G2One` or `G2X`: an entry's G2 argument, `[1]_2` or `[x]_2` | [mercury.md §6](spec/mercury.md) |
| pass 1, pass 2 | executing to commit every shard's `M` columns; again to prove each | [streaming.md §2](spec/streaming.md) |
| phase 1, phase 2 | the decider key's ceremonies: powers of tau, then the circuit's own | [recursion.md §9](spec/recursion.md) |
| public window | windows 2 and 3 at `2^12`: input at `0x8000`, journal at `0xC000` | [public-values.md §2](spec/public-values.md) |
| query | one read and one write at one address in one cycle | [execution-trace.md §3](spec/execution-trace.md) |
| RAM glue | invocations chained through their frame's words in RAM | [delegation-circuits.md §1](spec/delegation-circuits.md) |
| reconciliation | `∏ read roots · R_b = ∏ write roots · W_b`, once a statement | [memory.md §4](spec/memory.md) |
| registry | `family_circuit`, `recursion_circuit`: each family's one circuit | [circuits.md §1](spec/circuits.md) |
| scratch | `scratch[i]`, a flat relation's intermediate, one per inner column | [gkr.md §2](spec/gkr.md) |
| shard | `h` rows of one family, or one window, proved alone but for the memory argument | [streaming.md §4](spec/streaming.md) |
| slot | `Δ` in a cycle's timestamps `4c + Δ`; a `ProgramImage` halfword; a frame position | [execution-trace.md §1](spec/execution-trace.md), [program.md §2](spec/program.md), [memory.md §2](spec/memory.md) |
| SRS digest | a digest of the `SrsVerifier` and the generic table's commitments | [proof.md §3](spec/proof.md) |
| stack | `2^σ` columns committed as one, in the recursion format | [recursion.md §1](spec/recursion.md) |
| statement | `PublicInputs`: input, journal, exit status and the execution's record | [proof.md §1](spec/proof.md) |
| statement shard, shard-set exactness | a `(family, index)` below its count; a block proves each once, in order | [proof.md §1](spec/proof.md) |
| tamper twin | a forgery proved as an honest prover would, refused in its class | [circuits.md §3](spec/circuits.md) |
| tape | straight-line coprocessor calls a node replays; `checker tape`'s listing | [recursion.md §7](spec/recursion.md), [tools.md §4](tools.md) |
| time window | a shard's claimed `[ts_start, ts_end)`; it binds nothing | [proof.md §8](spec/proof.md) |
| transcript form | a G1 point as four 128-bit `Fr` limbs; infinity, four `2^128` | [transcript.md §4](spec/transcript.md) |
| tuple | `T(AS, ADDR, TS, VAL)`: a memory access as one field element | [memory.md §1](spec/memory.md) |
| `u1`, `u2` | a Mercury opening point's halves, pairing with an index's low and high bits | [mercury.md §1](spec/mercury.md) |
| `VmConfig` | a program's families, their heights, `bytecode_size_words` | [program.md §7](spec/program.md) |
| window | `h` words from byte `4h·w`, initialized and torn down by one shard | [memory.md §3](spec/memory.md) |
| write-side induction | an execution family writes only words, so operands need no bound | [memory-ops.md §5](spec/memory-ops.md) |
