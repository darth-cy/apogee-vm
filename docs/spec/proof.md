# The proof

What a verifier checks and the formats it reads, from the statement to the bytes. The memory
argument, LogUp, GKR and Mercury are their own pages; this one is how they compose.
`crates/verifier-core` (`#![no_std]`) implements everything here but step 12, the opening, which
`crates/verifier` runs.

## 1. The statement

A **statement** is a `PublicInputs` under a verifying key (§7): one execution of the key's
program. It is proved by one `ShardProof` per **statement shard**, a `(family, index)` with `index`
below the family's shard count, each verified against the same `PublicInputs`. A shard's proof
establishes its own circuit and opening, and the reconciliation it joins reads the roots the
statement claims for every other shard, which only their own proofs establish: a statement is
verified when its proofs are exactly its shards and all pass, never by a subset.

Every entry point is `(&VerifyingKey, proof, &PublicInputs)`: `verifier::verify_shard`,
`verifier::verify_block`, `verifier_core::reduce_shard`. A verifier holds two values from a channel
the prover does not control, the program identity and the SRS digest (§3), and compares them with
the key's; the key itself may come from anyone (§7). The `verifier` CLI compares identity only
([tools.md](../tools.md) §6); `host::verify(vk, block)`, which is
`verify_block(vk, block, block.statement())`, compares neither and leaves its caller to check the
statement's input, output and exit status too.

### 1.1 `PublicInputs`

| field | |
| --- | --- |
| `input: Vec<u8>` | the public input window's payload, at most `PUBLIC_PAYLOAD_BYTES` = 16,380 ([public-values.md](public-values.md) §3) |
| `output: Vec<u8>` | the journal, the public output window's payload, as long |
| `exit_status: u32` | `x10`'s final value |
| `shard_counts: Vec<u32>` | one per family of the `VmConfig`, in its order, possibly 0 |
| `windows: Vec<u32>` | `ZERO_WINDOWS`' window ids, one per shard ([memory.md](memory.md) §3.5) |
| `boundary: BoundaryFinals` | the 64 register and pc boundary scalars ([memory.md](memory.md) §4.1) |
| `memory_commitments: Vec<Vec<[u8; 64]>>` | per statement shard, its `M` columns' commitments in layout order |
| `memory_roots: Vec<[Fr; 2]>` | per statement shard, `[read_root, write_root]` |

The first three are the claim; the rest is the execution's record, which the prover chooses. All of
it but the roots and the exit status is absorbed before any challenge (§2).

### 1.2 Statement order

`verifier_core::statement_shards(config, counts)`:

```text
(INIT_TEARDOWN, 0)
(ZERO_WINDOWS, 0) … (ZERO_WINDOWS, k − 1)
every other family of the VmConfig, ascending by id, shards 0 … count − 1 each
```

It orders `memory_commitments`, `memory_roots`, G8's groups and a block's proofs. The two leading
families are ids 7 and 8, so the order is not ascending by id. A family with count 0 has no entry.

### 1.3 The block

`verifier_core::BlockProof { config, statement, shards }` is one execution closed: the static
`VmConfig`, the statement and one proof per statement shard, in statement order; it adds no
evidence to the proofs'. The config and counts are public data of the proof, absorbed at G3 and G4,
so the block carries both and check B1 holds them to the key's and the verifier's.

**Shard-set exactness**, `BlockProof::shape`, at decode and again in `verify_block`: one count per
config family; the counts' total, summed in `u64` before any list is built from them, equal to the
numbers of proofs, commitment lists and root pairs; the proofs naming `statement_shards` in order.
No `(family, index)` is missing, repeated or extra.

`BlockProof::reconciliation` is the cross-shard record set, a `BlockReconciliation` of one
`ShardRecord { family, shard_index, ts_window, memory_commitments, roots }` per statement shard,
assembled from the shard's proof (the window) and the statement (the rest).

## 2. The global transcript

`verifier_core::global_commit(vk, statement)`, run by the verifier in `derive_global_phase` and by
the prover once every shard's `M` columns are committed ([streaming.md](streaming.md) §2): a fresh
transcript, tag values in [transcript.md](transcript.md) §5.

| # | op | tag | message |
| --- | --- | --- | --- |
| G1 | absorb | `PROTOCOL_SUITE` | `[PROTOCOL_VERSION]`, 0 |
| G2 | absorb | `SRS_DIGEST` | `[vk.srs_digest]` (§3) |
| G3 | absorb | `VM_CONFIG` | the config ([program.md](program.md) §7) |
| G4 | absorb | `SHARD_COUNTS` | `shard_counts` |
| G5 | absorb | `MEMORY_WINDOWS` | `windows` |
| G6 | absorb | `PROGRAM_IDENTITY` | `[vk.identity]` |
| G7 | absorb | `PUBLIC_INPUTS`, bytes | the 32 bytes of `io_digest(input, output)` ([public-values.md](public-values.md) §5) |
| G8 | per family | `MEMORY_GROUP`, `COMMITMENT` | below |
| G9 | absorb | `MEMORY_BOUNDARY` | the 64 boundary scalars |
| G10 | squeeze ×4 | `MEMORY_CHALLENGE` | `γ_M, α_addr, α_ts, α_val`, challenge slots 1–4 |
| G11 | squeeze | `GLOBAL_STATE_DIGEST` | the **global state digest** |

G3–G5 are `verifier_core::absorb_statement_descriptor`. G8 is one group per family of the config,
in statement order, a family with count 0 included:

```text
MEMORY_GROUP   [family, shard count]
COMMITMENT     per shard, ascending: its memory_commitments, one message of 4k limbs
```

A statement's or proof's points are absorbed as limbs ([transcript.md](transcript.md) §4) and
decoded only at step 12.

Everything a memory tuple or the reconciliation reads precedes G10 ([memory.md](memory.md) §6.1
says why for each). Two fields are not absorbed: `memory_roots`, which depend on the challenges and
are bound by each shard's own GKR proof (step 10a), and `exit_status`, which step 10b holds to
`v_10`, absorbed at G9. The digest seeds every shard (§4); a proof carries the digest it was seeded
with (`ShardProof::global_digest`) and step 5 compares it with the replay, so a shard proof is for
one statement under one key.

## 3. The SRS digest

```text
t ← Transcript::new()
t.append_bytes(SRS_VERIFIER, srs_verifier)           320 bytes, srs.md §5
append_g1_points(t, GENERIC_TABLE, generic_table)    the table's 3 points, one 12-limb message
srs_digest ← t.sample()                              one raw squeeze
```

`verifier_core::srs_digest`; `GENERIC_TABLE` is absorbed in this sponge and nowhere else, the points
key column first. G2 absorbs the digest, so a proof is bound to the three points its pairings read
and the table its `GENERIC` lookups read. Both are constants of the ceremony
([lookup.md](lookup.md) §9), so one digest serves every key. It does not cover the powers, which
only a prover reads: an opening is checked against `g2_tau` whatever powers made the commitment.

A key's load recomputes the digest from the key's own points (§7), which shows they agree, not that
they are the ceremony's, and identity binds neither ([program.md](program.md) §8). So the verifier
compares `vk.srs_digest` with the ceremony's ([srs.md](srs.md) §3). Without that comparison,
whoever built the key chose `τ`, so can open anything, and chose the table every `GENERIC` lookup
is held to.

## 4. The shard transcript

Shard `(family, index)` runs a fresh sponge (`verifier_core::shard_transcript`), not a restored
global one:

| # | op | tag | message |
| --- | --- | --- | --- |
| S1 | absorb | `SHARD_SEED` | `[global state digest, family, index]` |
| S2 | absorb | `SHARD_TS_WINDOW` | `[ts_start, ts_end]` (§8) |
| S3 | absorb | `COMMITMENT` | the shard's `W` commitments, multiplicities included, one message |
| S4 | squeeze ×2 | `LOOKUP_CHALLENGE` | `g`, then `β` ([lookup.md](lookup.md) §2) |
| S5 | | | the GKR backward pass ([gkr.md](gkr.md) §5.2) |
| S6 | | | the batch opening (§5): B1–B3 of [mercury.md](mercury.md) §5, then the sixteen steps of its §3 |

S4 is drawn for every shard, whether or not its circuit has a channel. Every challenge follows
every commitment the circuit reads: `M` at G8, `S` through identity at G6 or the SRS digest at G2,
`W` at S3, as GKR requires of its caller ([gkr.md](gkr.md) §5.1).

The circuit's external challenges (`verifier_core::shard_challenges`) are slots 1–4 from G10; for a
window family, slot 5 at the window `verifier_core::shard_window` gives the shard
([memory.md](memory.md) §3.3); then the lookup slots from `g` and `β`. Its outputs, the top layer,
are the two memory roots and then each channel's `(num, den)` ([lookup.md](lookup.md) §6), `2 + 2c`
of them for `c` channels.

In the recursion format a shard commits `M` and `W` as stacks of `2^σ` columns, and S6 opens with
`σ` `STACK_CHALLENGE` squeezes extending the opening point ([recursion.md](recursion.md) §1.3). At
`σ = 0`, the base format, there are none.

## 5. The opening

After S5 every committed column has one claim, layer 0's, all at one point `u`
([gkr.md](gkr.md) §5.2). So there is nothing for a claim-merging sumcheck to merge, and S6 opens
every column as one batch ([mercury.md](mercury.md) §5), one 704-byte Mercury proof a shard:

```text
columns      the circuit's committed layout: M[0..], W[0..], S[0..]
commitments  M  PublicInputs.memory_commitments[the shard's position]
             W  ShardProof.witness_commitments
             S  VerifyingKey.setup_commitments[family], then VerifyingKey.generic_table
                when the circuit reads GENERIC (FamilyCircuit::reads_generic_table)
point        u, variable j at index j
values       layer 0's claims, ShardProof.gkr.layers[0].final_evals
```

Column `i` carries `ρ^i`, so this order is part of what is proved. Virtual columns are neither
claimed nor opened: the verifier evaluates their closed forms. Taking `S` from the key is what makes
the opening bind the columns identity commits, the decoded tables and the image column
([memory.md](memory.md) §6.2), and the generic table the SRS digest covers.

`reduce_shard` ends at an `OpeningClaim`: these commitments, the point, the values and the live
shard transcript. `verify_shard` spends it with `pcs::batch_verify` (step 12); a recursion node
defers it ([recursion.md](recursion.md) §8.3).

## 6. Verification

`verifier::verify_shard(vk, proof, public)` returns the first failure, in this order, as a
`VerifyError`:

| step | class | check |
| --- | --- | --- |
| 1 | `Statement` | one shard count per config family; the key's circuits are its config's families, in order, with one setup list each |
| 2 | `Statement` | `check_memory_windows` ([memory.md](memory.md) §3.5); `input` and `output` each at most `PUBLIC_PAYLOAD_BYTES` |
| 3 | `Statement` | one root pair and one commitment list per statement shard, each list its family's `M` width; the total summed in `u64` first |
| | | G1–G11 (§2) |
| 4 | `Statement` | `ts_start ≤ ts_end ≤ 2^38` |
| 5 | `Statement` | the replayed global state digest is `proof.global_digest` |
| 6 | `Malformed` | `(family, index)` is a statement shard; the witness commitments and outputs have the circuit's counts |
| 7 | `Constraint { layer }` | `gkr_verify::verify` over the shard transcript: `LayerInconsistency { layer }`; its `ProofShape`, `OutputShape` and `MissingChallenge` are `Malformed` |
| 8 | `Constraint { layer: 0 }` | every base claim at one point |
| 9 | `Lookup { channel }` | `gkr_verify::channel_holds` on each channel's root pair, in channel order ([lookup.md](lookup.md) §8) |
| 10a | `MemoryArgument` | the proof's two roots are the statement's for its position |
| 10c | `MemoryArgument` | a `PUBLIC_INPUT` or `PUBLIC_OUTPUT` shard's value column is the statement's string ([public-values.md](public-values.md) §5) |
| 10b | `MemoryArgument` | every boundary timestamp below `2^38`; `v_10 = exit_status`; `gkr_verify::reconciles` over every shard's roots and `boundary_factors(challenges, vk.entry_pc, boundary)` ([memory.md](memory.md) §4.2) |
| 11 | — | the opening claim (§5) |
| 12 | `Opening` | the `SrsVerifier`, every commitment and the Mercury proof through their validating decoders, then `pcs::batch_verify`; any failure |

Step 8 cannot fail on `verify`'s output, whose base claims share layer 0's point; it states what
step 11 relies on. Steps 1–3 hold the statement to the key before the replay indexes by it, so
nothing a proof or statement carries makes the core panic, for a loaded key.

**The split**, by what each part reads (`verifier_core`):

| function | reads | steps | runs |
| --- | --- | --- | --- |
| `derive_global_phase(vk, public)` → `GlobalChallenges` | key, statement | 1–3, G1–G11 | once a statement |
| `verify_shard_local(vk, global, proof, public)` → `OpeningClaim` | and one `ShardProof` | 4–10a, 10c, 11 | once a shard |
| `verify_global_memory(vk, global, public)` | key, statement, challenges | 10b | once a statement |

`GlobalChallenges` is the four memory challenges and the digest. `reduce_shard` is the three in that
order, `verify_shard` that and step 12; step 11 cannot fail, so 10b after it is 10b in place. Step
10b reads only `vk.entry_pc`, the boundary, the roots and the challenges, so a block runs it once;
step 10a puts each shard into the product by holding the roots its GKR proof outputs to the
statement's entry, and shard-set exactness makes every root there a verified shard's.
**`verify_shard_local` alone verifies no memory argument**: without `verify_global_memory` it
accepts shards, each valid, whose multiset does not close.

`verifier::verify_block(vk, block, public)`:

| | class | check |
| --- | --- | --- |
| B1 | `Statement` | `block.config` is `vk.config`, and `block.statement` is `public` |
| B2 | `Statement` | `derive_global_phase`, once |
| B3 | `Statement` | `BlockProof::shape` (§1.3) |
| B4 | `Statement` | `check_ts_windows` over the records (§8) |
| B5 | `MemoryArgument` | `verify_global_memory`, once |
| B6 | as `verify_shard` | per shard, in statement order: `verify_shard_local`, then step 12 |

B1–B5 read no GKR proof or opening, so a statement that cannot reconcile is refused before any
circuit runs, and the class can differ from `verify_shard`'s: a change to anything G1–G9 absorb
that B1–B4 admit moves the challenges, so the honest roots stop reconciling and `verify_block`
answers `MemoryArgument` where `verify_shard` names the seed at step 5; a forgery that unbalances
the multiset is `MemoryArgument` even where it also breaks a gate. A dropped shard fails B5: the
truncated statement, re-proved honestly with its counts, lists and roots adjusted, passes B1–B4 and
misses that shard's memory events on one side of the product.

In `verify_shard`'s order the class names the fault: a tampered witness proved honestly, its
multiplicities recounted, columns recommitted and statement rebuilt, fails at the gate
(`Constraint`), table membership (`Lookup`) or multiset (`MemoryArgument`) it broke, which
`checker::TamperHarness` asserts ([circuits.md](circuits.md) §3).

## 7. The verifying key

### 7.1 Fields

| field | |
| --- | --- |
| `code_version: u32` | `constants::family::CODE_VERSION`, 0 |
| `config: VmConfig` | the static shape ([program.md](program.md) §7) |
| `entry_pc: u32` | the image's entry pc |
| `identity: ProgramIdentity` | [program.md](program.md) §8 |
| `setup_commitments: Vec<Vec<[u8; 64]>>` | identity's commitment lists, one per config family, in its order |
| `srs_verifier: [u8; 320]` | the `SrsVerifier` ([srs.md](srs.md) §5) |
| `generic_table: [[u8; 64]; 3]` | the generic table's commitments, key column first, in every key ([lookup.md](lookup.md) §9) |
| `srs_digest: Fr` | §3 |
| `circuits: Vec<FamilyCircuit>` | one per config family, in its order: the family, its `CircuitArtifact` and its `ChannelSpec`s ([lookup.md](lookup.md) §11) |

A key carries every family's artifact, so its size is mostly its delegation families'
([circuits.md](circuits.md) §1).

### 7.2 Loading

`VerifyingKey::from_bytes` decodes (§9), refuses bytes that are not the key's canonical encoding,
and runs `VerifyingKey::check`, which refuses, in order:

1. a `VmConfig` no derivation produces (`VmConfig::from_bytes` of its own bytes), or a
   `code_version` other than `CODE_VERSION`;
2. a setup list count other than the config's family count;
3. an `identity` that `identity_digest(code_version, config, entry_pc, setup_commitments)` does not
   reproduce;
4. an `srs_digest` that `srs_digest(srs_verifier, generic_table)` does not reproduce;
5. a circuit count other than the family count; then, family by family: a circuit for another
   family; a height the registry has no circuit for; a circuit, artifact or channel specs, other
   than `config.circuit(family, trace_vars)`, the registry of the config's format
   ([circuits.md](circuits.md) §1); an artifact failing `CircuitArtifact::validate`,
   `constraints::memory::check_memory` or `constraints::lookup::check_discharge`; a setup list
   whose length, plus 3 if the circuit reads `GENERIC`, is not the artifact's `S` count; and
   `GENERIC` specs naming anything but the 3 setup columns after identity's, §5's order, which no
   registry circuit fails.

`verifier::load_verifying_key` then decodes every curve point: the `SrsVerifier`'s three, each
setup commitment and each generic-table commitment, through the validating readers. The circuits
are held to the registry because nothing else binds them: identity binds the program, not the
circuit that proves it.

**A key from an untrusted source.** Every field is recomputed from or compared with one of the
verifier's two trusted values (§1), or fixed by the code: `config`, `entry_pc` and the setup lists
through identity; `srs_verifier` and `generic_table` through the SRS digest; `code_version` and the
circuits by the verifier's own registry. So a key may come from the prover, provided both
comparisons are made.

Validation runs once, at load; `verify_shard` and `verify_block` assume a loaded key. On one edited
in memory a changed config or circuit list is still refused as `Statement`, but an edit inside a
circuit may go unnoticed.

`prover::ProverSetup::new(program, srs)` builds the key: each family's circuit from
`VmConfig::circuit` and fill from `prover::family_fill` (`ProverError::Unregistered` if either is
missing), identity's and the generic table's commitments over `srs`, then `check`
(`ProverError::Key`). `srs` needs as many powers as the tallest family has rows, and `2^18` for the
generic table (`program::lookup_tables::GENERIC_LOG_HEIGHT`); fewer panics.

## 8. Time windows

Each shard claims `[ts_start, ts_end)` (`ShardProof::ts_window`): the slice of the clock
([execution-trace.md](execution-trace.md) §1) its rows write in, their reads reaching back before
it. S2 absorbs it before the witness commitments, so a proof made under one window fails under
another; step 4 holds it to `ts_start ≤ ts_end ≤ 2^38` and nothing more.

`verifier_core::check_ts_windows` (B4), over the records in statement order: within each
**cycle-owning** family (`constants::family::CYCLE_OWNING`, the execution families 0–6), every
window is non-empty and no shard's `ts_end` exceeds the next shard's `ts_start`; a family's records
are consecutive and ascending, so neighbours suffice. It is per family because families interleave
— `ADD_SUB_LUI_AUIPC` may own cycles 1 and 3 and `JUMP_BRANCH_SLT` cycle 2 — and every other family
is exempt: a window family's rows are words, a delegation family's invocations at their requesting
cycles ([delegation.md](delegation.md) §8).

The prover reads a window off the shard's committed `M[0]` cycle column (`ts_window`,
`crates/prover/src/lib.rs`): `[4·c_0, 4·c_max + 4)`, `c_0` row 0's cycle and `c_max` the largest,
padding rows carrying 0, for cycle-owning and delegation families alike. Window families claim
`verifier_core::TRIVIAL_TS_WINDOW = [0, 2^38)`.

**A window binds nothing.** No gate ties it to the rows committed under it, so a prover may claim
any windows the rule admits; cross-shard order, cycle uniqueness and pc continuity are the memory
multiset's alone ([memory.md](memory.md) §9). B4 checks the shape of the shard plan and adds
nothing to soundness.

## 9. Wire forms and the proof archive

`verifier_core::wire`: integers little-endian; an `Fr` its 32 canonical bytes
([primitives.md](primitives.md) §1), refused at or above `p`; a `G1` its 64 bytes
([primitives.md](primitives.md) §3), opaque to the core; `bytes` a `u32` length then the bytes;
`list<T>` a `u32` count then the items; `T[k]` exactly `k` items, no count. Every decoder is
total: it refuses a count the remaining bytes cannot hold, so it reserves nothing an untrusted
length asks for, and refuses trailing bytes.

```text
PublicInputs   input bytes, output bytes, exit_status u32,
               shard_counts list<u32>, windows list<u32>,
               boundary Fr[64]                     memory.md §4.1's order and ranges
               memory_commitments list<list<G1>>, memory_roots list<Fr[2]>

ShardProof     family u32, shard_index u32, ts_start u64, ts_end u64, global_digest Fr,
               witness_commitments list<G1>, outputs list<Fr>,
               gkr list<(rounds list<Fr[4]>, final_evals list<Fr>)>       transition 0 first
               opening u8[704]                     pcs::MercuryProof, mercury.md §4

BlockProof     config bytes                        VmConfig, program.md §7
               statement bytes                     PublicInputs
               shards list<bytes>                  each a ShardProof; then BlockProof::shape

VerifyingKey   code_version u32, config bytes, entry_pc u32, identity Fr,
               setup_commitments list<list<G1>>, srs_verifier u8[320], generic_table G1[3],
               srs_digest Fr,
               circuits list<(family u32, artifact bytes,          CircuitArtifact, gkr.md §4.1
                              channels list<(channel u32, table list<Address>,
                                             multiplicity Address)>)>
Address        tag u8 (0 M, 1 W, 2 S, 3 V), index u32; a V's index is its gkr.md §2.1 kind tag

BlockReconciliation   list<(family u32, shard_index u32, ts_start u64, ts_end u64,
                            memory_commitments list<G1>, read_root Fr, write_root Fr)>
```

A `ShardProof`'s lengths are fixed by its key and family, and steps 6–7 hold them: transition `k`
carries `n_{k+1}` rounds and `w_k` claims, twice that if halving ([gkr.md](gkr.md) §5.5). For a
base-format circuit at `2^n` with `W` witness, `C` committed and `I` inner columns, `O` outputs, and
`R` row-wise lists before its `n` halving ones, that is

```text
772 + 64·W + 32·O + 8·(R + n) + 128·(R·n + n(n − 1)/2) + 32·(C + I + O·(n − 1))   bytes
```

which [circuits.md](circuits.md) §1 tabulates per family.

**The proof archive.** `verifier::proof_archive::write_proof(dir, stem, vk, block)`, re-exported
as `host::proof_archive`, writes four files, each a bare `to_bytes` with no header of its own:

```text
<stem>.vk         VerifyingKey
<stem>.identity   the key's identity: its 32 bytes in order, 64 lowercase hex digits, a newline
<stem>.public     PublicInputs: the block's own statement
<stem>.block      BlockProof
```

`read_proof(dir, stem)` is the inverse, each file through its type's decoder and the key through
`load_verifying_key`. `.identity` records what the run claimed, and `read_proof` returns it
unchecked: a verifier's identity comes from its own channel (§1). `.public` repeats the statement
`.block` carries, for the CLI, which takes it as a file ([tools.md](../tools.md) §6).
