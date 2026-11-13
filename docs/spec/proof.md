# The proof

What a verifier checks and the formats it reads, from the statement to the bytes. The memory
argument, LogUp and GKR are their own pages; this one is how they compose.
`crates/verifier-core` (`#![no_std]`) implements everything here, the opening of step 11 through
`crates/pcs-verify` ([pcs.md](pcs.md)).

## 1. The statement

A **statement** is a `PublicInputs` under a verifying key (§7): one execution of the key's
program. It is proved by one `ShardProof` per **statement shard**, a `(family, index)` with `index`
below the family's shard count, each verified against the same `PublicInputs`. A shard's proof
establishes its own circuit — over base columns its commitments bind (§3) — and the reconciliation it joins
reads the roots the statement claims for every other shard, which only their own proofs establish:
a statement is verified when its proofs are exactly its shards and all pass, never by a subset.

Every entry point is `(&VerifyingKey, proof, &PublicInputs)`: `verifier::verify_shard`,
`verifier::verify_block`, `verifier_core::reduce_shard`. A verifier holds one value from a channel
the prover does not control, the program identity, and compares it with the key's; the key itself
may come from anyone (§7). The `verifier` CLI makes that comparison ([tools.md](../tools.md) §6);
`host::verify(vk, block)`, which is `verify_block(vk, block, block.statement())`, does not, and
leaves its caller to check the identity and the statement's input, output and exit status too.

### 1.1 `PublicInputs`

| field | |
| --- | --- |
| `input: Vec<u8>` | the public input window's payload, at most `PUBLIC_PAYLOAD_BYTES` = 16,380 ([public-values.md](public-values.md) §3) |
| `output: Vec<u8>` | the journal, the public output window's payload, as long |
| `exit_status: u32` | `x10`'s final value |
| `shard_counts: Vec<u32>` | one per family of the `VmConfig`, in its order, possibly 0 |
| `windows: Vec<u32>` | `ZERO_WINDOWS`' window ids, one per shard ([memory.md](memory.md) §3.5) |
| `boundary: BoundaryFinals` | the 64 register and pc boundary scalars ([memory.md](memory.md) §4.1) |
| `memory_commitments: Vec<Commitment>` | per statement shard, the commitment to its `M` columns (§3) |
| `memory_roots: Vec<[Fp2; 2]>` | per statement shard, `[read_root, write_root]` |

The first three are the claim; the rest is the execution's record, which the prover chooses. All of
it but the roots and the exit status is absorbed before any challenge (§2).

### 1.2 Statement order

`verifier_core::statement_shards(config, counts)`:

```text
(INIT_TEARDOWN, 0)
(ZERO_WINDOWS, 0) … (ZERO_WINDOWS, k − 1)
every other family of the VmConfig, ascending by id, shards 0 … count − 1 each
```

It orders `memory_commitments`, `memory_roots` and a block's proofs. The two leading families are ids 7 and 8, so the
order is not ascending by id. A family with count 0 has no entry.

### 1.3 The block

`verifier_core::BlockProof { config, statement, shards }` is one execution closed: the static
`VmConfig`, the statement and one proof per statement shard, in statement order; it adds no
evidence to the proofs'. The config and counts are public data of the proof, absorbed at G2 and G3,
so the block carries both and check B1 holds them to the key's and the verifier's.

**Shard-set exactness**, `BlockProof::shape`, at decode and again in `verify_block`: one count per
config family; the counts' total, summed in `u64` before any list is built from them, equal to the
numbers of proofs and root pairs; the proofs naming `statement_shards` in order. No
`(family, index)` is missing, repeated or extra.

`BlockProof::reconciliation` is the cross-shard record set, a `BlockReconciliation` of one
`ShardRecord { family, shard_index, ts_window, roots }` per statement shard, assembled from the
shard's proof (the window) and the statement (the roots).

## 2. The global transcript

`verifier_core::global_commit(vk, statement)`, run by the verifier in `derive_global_phase` and by
the prover once the execution has fixed the statement ([streaming.md](streaming.md) §2): a fresh
transcript, tag values in [transcript.md](transcript.md) §4.

| # | op | tag | message |
| --- | --- | --- | --- |
| G1 | absorb | `PROTOCOL_SUITE` | `[PROTOCOL_VERSION]` |
| G2 | absorb | `VM_CONFIG` | the config ([program.md](program.md) §7) |
| G3 | absorb | `SHARD_COUNTS` | `shard_counts` |
| G4 | absorb | `MEMORY_WINDOWS` | `windows` |
| G5 | absorb | `PROGRAM_IDENTITY` | `vk.identity`'s 8 lanes |
| G6 | absorb | `PUBLIC_INPUTS` | `io_digest(input, output)`'s 8 lanes ([public-values.md](public-values.md) §5) |
| G6a | absorb, per shard | `MEMORY_COMMITMENT` | each statement shard's memory commitment, in statement order: its payloads concatenated |
| G7 | absorb | `MEMORY_BOUNDARY` | the 64 boundary scalars |
| G8 | squeeze ×4 | `MEMORY_CHALLENGE` | `γ_M, α_addr, α_ts, α_val`, challenge slots 1–4 |
| G9 | squeeze | `GLOBAL_STATE_DIGEST` | the **global state digest**, one `Fp2` |

G2–G4 are `verifier_core::absorb_statement_descriptor`.

Everything a memory tuple or the reconciliation reads precedes G8 ([memory.md](memory.md) §6.1
says why for each), the memory columns through their commitments at G6a. Two
fields are not absorbed: `memory_roots`, which depend on the challenges and are bound by each
shard's own GKR proof (step 10a), and `exit_status`, which step 10b holds to `v_10`, absorbed at
G7. The digest seeds every shard (§4); a proof carries the digest it was seeded with
(`ShardProof::global_digest`) and step 5 compares it with the replay, so a shard proof is for one
statement under one key.

## 3. Binding

A proof binds every column it reads before every challenge that column's argument depends on. Each
of a shard's three groups has one Akita commitment ([pcs.md](pcs.md) §3), formed under its family's
opening schedule, `verifier_core::opening_schedule(artifact)` — a function of the circuit's trace
height and its `M`, `W` and `S` widths alone — and every claim on it is opened at step 11 (§5):

| columns | committed | carried by | absorbed |
| --- | --- | --- | --- |
| `M`, a shard's memory columns | by the prover, as the shard fills ([streaming.md](streaming.md) §2) | the statement, `memory_commitments` | the global transcript, G6a, before the memory challenges |
| `W`, a shard's witness columns, multiplicities included | by the prover, in the shard | the proof, `witness_commitment` | the shard transcript, S2a, before `g` and `β` |
| `S`, a family's decoded table or `INIT_TEARDOWN`'s image column, then the packed generic table if it reads it | at setup, into the key | the key, `setup_commitments` | identity ([program.md](program.md) §8), so G5 |

A group of no column has the empty commitment, absorbed as an empty message, and no part in the
opening. A commitment's shape — one payload per outer slice, each of the schedule's length — is
the schedule's, and steps 3 and 6 and the key's load hold every one to it.

## 4. The shard transcript

Shard `(family, index)` runs a fresh sponge (`verifier_core::shard_transcript`), not a restored
global one:

| # | op | tag | message |
| --- | --- | --- | --- |
| S1 | absorb | `SHARD_SEED` | `[digest.c0, digest.c1, family, index]`, the global state digest first |
| S2 | absorb | `SHARD_TS_WINDOW` | `[ts_start, ts_end]` (§8) |
| S2a | absorb | `WITNESS_COMMITMENT` | the shard's `W` commitment: its payloads concatenated |
| S3 | squeeze ×2 | `LOOKUP_CHALLENGE` | `g`, then `β` ([lookup.md](lookup.md) §2) |
| S4 | | | the GKR backward pass ([gkr.md](gkr.md) §5.2) |
| S5 | | | the opening of every committed column (§5, [pcs.md](pcs.md) §7) |

S3 is drawn for every shard, whether or not its circuit has a channel. GKR requires of its caller
that every challenge follow every commitment the circuit reads ([gkr.md](gkr.md) §5.1): the setup
commitments precede both transcripts through the identity, the memory commitments G8 and the
witness commitment S3.

The circuit's external challenges (`verifier_core::shard_challenges`) are slots 1–4 from G8; for a
window family, slot 5 at the window `verifier_core::shard_window` gives the shard
([memory.md](memory.md) §3.3); then the lookup slots from `g` and `β`. Its outputs, the top layer,
are the two memory roots and then each channel's `(num, den)` ([lookup.md](lookup.md) §6), `2 + 2c`
of them for `c` channels.

## 5. The column claims and the opening

After S4 every committed column has one claim, layer 0's, all at one point `u`
([gkr.md](gkr.md) §5.2):

```text
columns      the circuit's committed layout: M[0..], W[0..], S[0..]
point        u, variable j at index j
values       layer 0's claims, ShardProof.gkr.layers[0].final_evals
```

Virtual columns are not claimed: the verifier evaluates their closed forms. S5 opens every claim at
once, in the live shard transcript: `pcs_verify::verify` over the groups `M`, `W`, `S` in that
order — the statement's commitment for this shard, the proof's, the key's for its family — each
with its column count, a group of no column left out, and the values in layout order
([pcs.md](pcs.md) §7). Its refusal is step 11's.

## 6. Verification

`verifier::verify_shard(vk, proof, public)` returns the first failure, in this order, as a
`VerifyError`:

| step | class | check |
| --- | --- | --- |
| 1 | `Statement` | one shard count per config family; the key's circuits are its config's families, in order |
| 2 | `Statement` | `check_memory_windows` ([memory.md](memory.md) §3.5); `input` and `output` each at most `PUBLIC_PAYLOAD_BYTES` |
| 3 | `Statement` | one root pair and one memory commitment per statement shard, the total summed in `u64` first; each commitment of its family's `M` shape (§3) |
| | | G1–G9 (§2) |
| 4 | `Statement` | `ts_start ≤ ts_end ≤ 2^38` |
| 5 | `Statement` | the replayed global state digest is `proof.global_digest` |
| 6 | `Malformed` | `(family, index)` is a statement shard; the witness commitment has the circuit's `W` shape; the outputs have the circuit's count |
| 7 | `Constraint { layer }` | `gkr_verify::verify` over the shard transcript: `LayerInconsistency { layer }`; its `ProofShape`, `OutputShape` and `MissingChallenge` are `Malformed` |
| 8 | `Constraint { layer: 0 }` | every base claim at one point |
| 9 | `Lookup { channel }` | `gkr_verify::channel_holds` on each channel's root pair, in channel order ([lookup.md](lookup.md) §8) |
| 10a | `MemoryArgument` | the proof's two roots are the statement's for its position |
| 10c | `MemoryArgument` | a `PUBLIC_INPUT` or `PUBLIC_OUTPUT` shard's value column is the statement's string ([public-values.md](public-values.md) §5) |
| 10b | `MemoryArgument` | every boundary timestamp below `2^38`; `v_10 = exit_status`; `gkr_verify::reconciles` over every shard's roots and `boundary_factors(challenges, vk.entry_pc, boundary)` ([memory.md](memory.md) §4.2) |
| 11 | `Opening` | the opening of the column claims (§5) |

Step 8 cannot fail on `verify`'s output, whose base claims share layer 0's point; it states what
step 11 relies on. Steps 1–3 hold the statement to the key before the replay indexes by it, so
nothing a proof or statement carries makes the core panic, for a loaded key.

**The split**, by what each part reads (`verifier_core`):

| function | reads | steps | runs |
| --- | --- | --- | --- |
| `derive_global_phase(vk, public)` → `GlobalChallenges` | key, statement | 1–3, G1–G9 | once a statement |
| `verify_shard_local(vk, global, proof, public)` | and one `ShardProof` | 4–10a, 10c, 11 | once a shard |
| `verify_global_memory(vk, global, public)` | key, statement, challenges | 10b | once a statement |

`GlobalChallenges` is the four memory challenges and the digest. `reduce_shard` and `verify_shard`
are the three in that order, so a proof that fails both step 11 and 10b is refused at 11. Step
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
| B6 | as `verify_shard` | per shard, in statement order: `verify_shard_local` |

B1–B5 read no GKR proof, so a statement that cannot reconcile is refused before any circuit runs,
and the class can differ from `verify_shard`'s: a change to anything G1–G7 absorb that B1–B4 admit
moves the challenges, so the honest roots stop reconciling and `verify_block` answers
`MemoryArgument` where `verify_shard` names the seed at step 5; a forgery that unbalances the
multiset is `MemoryArgument` even where it also breaks a gate. A dropped shard fails B5: the
truncated statement, re-proved honestly with its counts and roots adjusted, passes B1–B4 and misses
that shard's memory events on one side of the product.

In `verify_shard`'s order the class names the fault: a tampered witness proved honestly, its
multiplicities recounted, its memory columns recommitted and statement rebuilt, fails at the gate
(`Constraint`), table membership (`Lookup`) or multiset (`MemoryArgument`) it broke, which
`checker::TamperHarness` asserts ([circuits.md](circuits.md) §3). A tamper only an opening sees — a
setup column moved with the memory it initializes, a generic-table row no lookup reads — is
`Opening`: the key fixes the setup commitments.

## 7. The verifying key

### 7.1 Fields

| field | |
| --- | --- |
| `code_version: u32` | `constants::family::CODE_VERSION`, 0 |
| `config: VmConfig` | the static shape ([program.md](program.md) §7) |
| `entry_pc: u32` | the image's entry pc |
| `identity: ProgramIdentity` | [program.md](program.md) §8 |
| `setup_commitments: Vec<Commitment>` | one per config family, in its order: its `S` columns' commitment (§3), empty for a family with none |
| `circuits: Vec<FamilyCircuit>` | one per config family, in its order: the family, its `CircuitArtifact` and its `ChannelSpec`s ([lookup.md](lookup.md) §11) |
| `pcs: Setup` | Akita's public setup ([pcs.md](pcs.md) §2), `verifier_core::pcs_setup_len(circuits)` coefficients: derived, never on the wire |

A key carries every family's artifact, which [circuits.md](circuits.md) §1 tabulates.

### 7.2 Loading

`VerifyingKey::from_bytes` decodes (§9), refuses bytes that are not the key's canonical encoding,
and runs `VerifyingKey::check`, which refuses, in order:

1. a `VmConfig` no derivation produces (`VmConfig::from_bytes` of its own bytes), or a
   `code_version` other than `CODE_VERSION`;
2. a setup-commitment count other than the family count, or an `identity` that
   `identity_digest(code_version, config, entry_pc, setup_commitments)` does not reproduce;
3. a circuit count other than the family count; then, family by family: a circuit for another
   family; a height the registry has no circuit for; a circuit, artifact or channel specs, other
   than `config.circuit(family, trace_vars)`, the registry's ([circuits.md](circuits.md) §1); an
   artifact failing `CircuitArtifact::validate`; a setup commitment not of its `S` columns' shape
   (§3); an artifact failing `constraints::memory::check_memory` or
   `constraints::lookup::check_discharge`; and `GENERIC` specs naming anything but the generic
   table's 3 setup columns after the family's own, which no registry circuit fails.

Then it expands `pcs`, which `check` does not read. `verifier::load_verifying_key` is
`VerifyingKey::from_bytes`. The circuits are held to the registry because nothing else binds them:
identity binds the program, not the circuit that proves it.

**A key from an untrusted source.** Every field is recomputed from or compared with the verifier's
one trusted value (§1), or fixed by the code: `config`, `entry_pc` and the setup commitments
through identity; `code_version` and the circuits by the verifier's own registry; `pcs` by the
setup seed. So a key may come from the prover, provided the identity comparison is made.

Validation runs once, at load; `verify_shard` and `verify_block` assume a loaded key. On one edited
in memory a changed config or circuit list is still refused as `Statement`, but an edit inside a
circuit may go unnoticed.

`prover::ProverSetup::new(program)` builds the key: each family's circuit from `VmConfig::circuit`
and fill from `prover::family_fill` (`ProverError::Unregistered` if either is missing), every
family's setup columns committed (`program::setup_openers`, whose openers it keeps for the
openings), the identity over those commitments, then `check` (`ProverError::Key`).

## 8. Time windows

Each shard claims `[ts_start, ts_end)` (`ShardProof::ts_window`): the slice of the clock
([execution-trace.md](execution-trace.md) §1) its rows write in, their reads reaching back before
it. S2 absorbs it before the lookup challenges, so a proof made under one window fails under
another; step 4 holds it to `ts_start ≤ ts_end ≤ 2^38` and nothing more.

`verifier_core::check_ts_windows` (B4), over the records in statement order: within each
**cycle-owning** family (`constants::family::CYCLE_OWNING`, the execution families 0–6), every
window is non-empty and no shard's `ts_end` exceeds the next shard's `ts_start`; a family's records
are consecutive and ascending, so neighbours suffice. It is per family because families interleave
— `ADD_SUB_LUI_AUIPC` may own cycles 1 and 3 and `JUMP_BRANCH_SLT` cycle 2 — and every other family
is exempt: a window family's rows are words.

The prover reads a window off the shard's `M[0]` cycle column (`ts_window`,
`crates/prover/src/lib.rs`): `[4·c_0, 4·c_max + 4)`, `c_0` row 0's cycle and `c_max` the largest,
padding rows carrying 0. Window families claim `verifier_core::TRIVIAL_TS_WINDOW = [0, 2^38)`.

**A window binds nothing.** No gate ties it to the rows proved under it, so a prover may claim any
windows the rule admits; cross-shard order, cycle uniqueness and pc continuity are the memory
multiset's alone ([memory.md](memory.md) §9). B4 checks the shape of the shard plan and adds
nothing to soundness.

## 9. Wire forms and the proof archive

`verifier_core::wire`: integers little-endian; an `Fp` its 8 canonical bytes and an `Fp2` its 16
([primitives.md](primitives.md) §1), a lane at or above `p` refused; `bytes` a `u32` length then the
bytes; `list<T>` a `u32` count then the items; `T[k]` exactly `k` items, no count; `opt<T>` a
presence byte, 0 or 1, then `T` if 1. Every decoder is
total: it refuses a count the remaining bytes cannot hold, so it reserves nothing an untrusted
length asks for, and refuses trailing bytes.

```text
PublicInputs   input bytes, output bytes, exit_status u32,
               shard_counts list<u32>, windows list<u32>,
               boundary Fp[64]                     memory.md §4.1's order and ranges
               memory_commitments list<Commitment>
               memory_roots list<Fp2[2]>

ShardProof     family u32, shard_index u32, ts_start u64, ts_end u64, global_digest Fp2,
               witness_commitment Commitment,
               outputs list<Fp2>,
               gkr list<(rounds list<Fp2[4]>, final_evals list<Fp2>)>     transition 0 first
               opening Opening

Commitment     list<list<Fp>>                      one payload per outer slice
Opening        folds list<Fold>, terminal Terminal                         pcs.md §7
Fold           tensor opt<Tensor>, opening list<Fp>, nonce u32, successor list<list<Fp>>,
               digest opt<Fp[8]>, norm opt<Fp>, range list<(rounds Rounds, claims list<Fp2>)>,
               fused Rounds, value Fp2
Tensor         partials Fp2[2], rounds Rounds
Terminal       tensor Tensor, partials list<list<Fp>>, digest Fp[8], nonce u32, response bytes
Rounds         list<list<Fp2>>

BlockProof     config bytes                        VmConfig, program.md §7
               statement bytes                     PublicInputs
               shards list<bytes>                  each a ShardProof; then BlockProof::shape

VerifyingKey   code_version u32, config bytes, entry_pc u32, identity Fp[8],
               setup_commitments list<Commitment>,
               circuits list<(family u32, artifact bytes,          CircuitArtifact, gkr.md §4.1
                              channels list<(channel u32, table list<Address>,
                                             multiplicity Address)>)>
Address        tag u8 (0 M, 1 W, 2 S, 3 V), index u32; a V's index is its gkr.md §2.1 kind tag

BlockReconciliation   list<(family u32, shard_index u32, ts_start u64, ts_end u64,
                            read_root Fp2, write_root Fp2)>
```

A `ShardProof`'s GKR lengths are fixed by its key and family, and steps 6–7 hold them: transition `k`
carries `n_{k+1}` rounds and `w_k` claims, twice that if halving ([gkr.md](gkr.md) §5.5). For a
circuit at `2^n` with `C` committed and `I` inner columns, `O` outputs, and `R` row-wise lists
before its `n` halving ones, that is

```text
48 + 16·O + 8·(R + n) + 64·(R·n + n(n − 1)/2) + 16·(C + I + O·(n − 1))   bytes
```

which [circuits.md](circuits.md) §1 tabulates per family. The witness commitment adds
`4 + s·(4 + 8ℓ)` bytes for its schedule's `s` payloads of `ℓ` lanes, and the opening its own,
every length the schedule's but the Rice-coded response's ([pcs.md](pcs.md) §7).

**The proof archive.** `verifier::proof_archive::write_proof(dir, stem, vk, block)`, re-exported
as `host::proof_archive`, writes four files, each a bare `to_bytes` with no header of its own:

```text
<stem>.vk         VerifyingKey
<stem>.identity   the key's identity: its 64 bytes in order, 128 lowercase hex digits, a newline
<stem>.public     PublicInputs: the block's own statement
<stem>.block      BlockProof
```

`read_proof(dir, stem)` is the inverse, each file through its type's decoder and the key through
`load_verifying_key`. `.identity` records what the run claimed, and `read_proof` returns it
unchecked: a verifier's identity comes from its own channel (§1). `.public` repeats the statement
`.block` carries, for the CLI, which takes it as a file ([tools.md](../tools.md) §6).
