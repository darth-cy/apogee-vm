# Glossary

The project's own vocabulary, one line a term, each linked to the section that defines it. Terms
the literature fixes (GKR, LogUp, RISC-V) are not listed.

| term | meaning | defined in |
| --- | --- | --- |
| advice | memory whose initial values the prover chose, bound by nothing | [public-values.md §6](spec/public-values.md) |
| archived path | proving from a held `TraceArchive`; only the tamper harness does | [streaming.md §6](spec/streaming.md) |
| artifact | a circuit as data, `CircuitArtifact`; also an exported `ProgramImage` | [gkr.md §4](spec/gkr.md), [program.md §3](spec/program.md) |
| base claims | each committed column's claimed value where the backward pass ends | [gkr.md §5](spec/gkr.md) |
| block | `BlockProof`: config, statement and its shards' proofs | [proof.md §1](spec/proof.md) |
| boundary | the registers' and pc's final timestamps and values; they have no rows | [memory.md §4](spec/memory.md) |
| cached entry | a sub-expression inlined into its list's gates, not a column | [gkr.md §3](spec/gkr.md) |
| canonical form | an element as its value, 32 bytes little-endian, below the modulus | [primitives.md §1](spec/primitives.md) |
| challenge slot | a gate coefficient's challenge: drawn, or derived by the verifier | [gkr.md §3, §5](spec/gkr.md) |
| channel | one LogUp identity over a shard's lookups into one table | [lookup.md §1](spec/lookup.md) |
| column claims | `ColumnClaims`: every committed column's base claim at one point, which nothing opens | [proof.md §5](spec/proof.md) |
| commitment void, UNFINISHED | every place a commitment or an opening belongs and none is: every proof is unsound | [architecture.md §0](architecture.md), [proof.md §3](spec/proof.md) |
| copower | `x < p` as `x·2^32/p < 2^32`, void without a direct bound | [lookup.md §11](spec/lookup.md) |
| cycle-owning | the execution families 0–6, whose time windows are ordered | [proof.md §8](spec/proof.md) |
| decoded table | an instruction family's setup columns: row `i` is pc `2i` | [program.md §5](spec/program.md) |
| discharge | the rule that each lookup is one leaf of its tree; `verifier::discharge`, which drops the column claims unchecked | [lookup.md §11](spec/lookup.md), [proof.md §5](spec/proof.md) |
| enforcing, producing | a gate vanishing on every row; one writing the next layer | [gkr.md §1](spec/gkr.md) |
| extra mask, kind, kind bit | `family_extra_mask` = `1 << kind`, a kind being a mnemonic's index; `b_k` its bit | [program.md §6](spec/program.md) |
| family | a circuit and the rows it proves: instructions (0–6) or memory locations | [circuits.md §1](spec/circuits.md) |
| frame | an execution family's queries | [memory.md §2](spec/memory.md) |
| gate list, row-wise, halving | the gates from layer `k` to `k + 1`, keeping the height or halving it | [gkr.md §1](spec/gkr.md) |
| gated key, neutral tuple | a lookup tuple under its selector; off, it reads a neutral table row | [lookup.md §4](spec/lookup.md) |
| generic table | the table of `ZeroEntry`, AND, `U16GetSign`, `ShiftPowers` | [lookup.md §9](spec/lookup.md) |
| global transcript, global state digest | G1–G9: the statement, then the memory challenges; G9 seeds each shard | [proof.md §2](spec/proof.md) |
| `HALT_PC` | 1: the exit row's `next_pc`, the pc's final value | [memory.md §5](spec/memory.md) |
| height | a family's rows a shard: `2^12`, `2^16`, `2^18`, `2^20` or `2^22` | [program.md §7](spec/program.md) |
| identity, image column | one `Fr` digest of the code version, `VmConfig` and entry pc; meant to commit the decoded tables and the image column too | [program.md §8](spec/program.md) |
| in flight | shards worked at once, at most `max_in_flight` | [streaming.md §5](spec/streaming.md) |
| journal | the public output: what the guest leaves in the output window | [public-values.md §1](spec/public-values.md) |
| laws | Laws 1–4: locality, derived width, top layer, single source of truth | [gkr.md §4](spec/gkr.md) |
| layer | layer 0 the committed columns, the top the outputs; `L{k}[j]` between | [gkr.md §1](spec/gkr.md) |
| live row, padding row | `m_pc = 1`, or a zero row; in a decoded table, an instruction, or −1 throughout | [memory.md §2](spec/memory.md), [program.md §5](spec/program.md) |
| `M`, `W`, `S`, `V` | memory, witness and setup columns; virtual tables | [gkr.md §2](spec/gkr.md) |
| multiplicity | a channel's `W` column counting each table row's lookups | [lookup.md §7](spec/lookup.md) |
| padding contract | `padding.row` makes row-local relations vanish and tree inputs 1 | [gkr.md §4](spec/gkr.md) |
| pass 1, pass 2 | executing to fix the statement; again to prove each shard | [streaming.md §2](spec/streaming.md) |
| public window | windows 2 and 3 at `2^12`: input at `0x8000`, journal at `0xC000` | [public-values.md §2](spec/public-values.md) |
| query | one read and one write at one address in one cycle | [execution-trace.md §3](spec/execution-trace.md) |
| reconciliation | `∏ read roots · R_b = ∏ write roots · W_b`, once a statement | [memory.md §4](spec/memory.md) |
| registry | `family_circuit`: each family's one circuit | [circuits.md §1](spec/circuits.md) |
| scratch | `scratch[i]`, a flat relation's intermediate, one per inner column | [gkr.md §2](spec/gkr.md) |
| shard | `h` rows of one family, or one window, proved alone but for the memory argument | [streaming.md §4](spec/streaming.md) |
| slot | `Δ` in a cycle's timestamps `4c + Δ`; a `ProgramImage` halfword; a frame position | [execution-trace.md §1](spec/execution-trace.md), [program.md §2](spec/program.md), [memory.md §2](spec/memory.md) |
| statement | `PublicInputs`: input, journal, exit status and the execution's record | [proof.md §1](spec/proof.md) |
| statement shard, shard-set exactness | a `(family, index)` below its count; a block proves each once, in order | [proof.md §1](spec/proof.md) |
| tamper twin | a forgery proved as an honest prover would, refused in its class | [circuits.md §3](spec/circuits.md) |
| tape | `checker tape`'s listing of the global transcript's messages | [tools.md §4](tools.md) |
| time window | a shard's claimed `[ts_start, ts_end)`; it binds nothing | [proof.md §8](spec/proof.md) |
| tuple | `T(AS, ADDR, TS, VAL)`: a memory access as one field element | [memory.md §1](spec/memory.md) |
| `VmConfig` | a program's families, their heights, `bytecode_size_words` | [program.md §7](spec/program.md) |
| window | `h` words from byte `4h·w`, initialized and torn down by one shard | [memory.md §3](spec/memory.md) |
| write-side induction | an execution family writes only words, so operands need no bound | [memory-ops.md §5](spec/memory-ops.md) |
