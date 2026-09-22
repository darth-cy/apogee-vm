# The shard proof: statement, transcripts, the verifying key and the add/sub family

Frozen as of S16. Changing anything here is a protocol-version change. S17 amended it for
the generic table's binding and the second registered execution family: decision 2 and §3
(the SRS digest also covers the table's three commitments), §9 (the key's layout gains
them, 192 bytes), and §4, §5, §7, §8.5 and §11 to match. The global transcript's
schedule, §2, did not change; a note there says where the table is bound.
`docs/spec/jump-branch-slt.md` is that family's page.

S18 registered the third and fourth execution families and **changed nothing in this
page's protocol**: §3's recipe, §9's layout and §2's schedule are as S17 left them. What
moved is the value inside one message — the packed table gained `ShiftPowers`' 32 rows, so
its three commitments and every key's SRS digest and bytes moved again (§3). §5.1, §7.2
and §11 gain the two new readers. `docs/spec/shift-bitwise.md` and `docs/spec/mul-div.md`
are those families' pages.

S20 **amended two things and added a page**. The time window, §4, is no longer the
trivial one: S20 generalizes its value, not its field or its position, so §6's step 4
became a well-formedness check and the block's own ordering rule moved to
`docs/spec/block-proof.md` §4. And §6's eleven steps are now reachable in two public
halves, `derive_global_phase` (steps 1–3 and the global transcript) and
`verify_shard_local` (steps 4–11), so a block pays for the global transcript once
instead of once per shard; `reduce_shard` is their composition and its order, its
classes and its answers are unchanged. §10's `PostGkr` entry gained the shard's time
window. Nothing else here moved: the global transcript's schedule, the SRS digest, the
key's layout and load rules, the opening and the registry are as S19 left them.
`docs/spec/block-proof.md` is the block layer's page.

S19 registered the fifth, sixth and seventh — the last three — and **changed nothing in
this page's protocol either**, not even the value inside a message: it appended nothing to
the packed table, so the three commitments, every key's SRS digest and every key's bytes
are S18's. §5.1 and §11 gain the three new families, two of which read the generic channel
and one of which does not. `docs/spec/memory-ops.md` is their page. With them
`family_circuit` holds every family the master prompt names.

This page is S16's vertical slice as the repository owner decided it: the statement a
proof is about, the global and per-shard transcripts, the three proof-side types and
their wire forms, the order `verify_shard` checks things in, the `ADD_SUB_LUI_AUIPC`
family's circuit, and the prover's phase snapshots. It cites
`docs/spec/memory.md`, `docs/spec/lookup.md`, `docs/spec/gkr.md` and
`docs/spec/mercury.md` for everything they already fix, and restates none of it.

| crate | what |
| --- | --- |
| `crates/transcript` | the curve-free G1 absorption (§2.4), which `pcs` now calls |
| `crates/verifier-core` | `#![no_std]`: `VmConfig`, the statement descriptor, the window rules, the identity digest, the SRS digest, `PublicInputs`, `ShardProof`, `VerifyingKey`, `VerifyError`, the global transcript and `reduce_shard` |
| `crates/verifier` | `std`: `verify_shard`, the one entry point, which ends in `pcs::batch_verify`; the `verifier` CLI |
| `crates/constraints` | `add_sub`: the family's circuit; `family_circuit`: the registry of every family's circuit |
| `crates/prover` | the verifying key's construction, the statement inputs, `global_commit_phase`, `prove_shard`, the family fills, the phase snapshots and resume |
| `crates/trace` | `TraceArchive::fill` and `content`, through which the prover writes its phases |
| `crates/checker` | `TamperHarness` |

The owner's decisions this page records, each put before any code:

1. **The verifier is two crates.** A `#![no_std]` core does everything but the one
   Mercury opening and returns that opening's claim; a thin `std` wrapper decodes the
   curve points and calls `pcs::batch_verify`. `pcs` is **not** split: the curve-free
   Mercury field-side module stays with the recursion stage, together with S09's open
   question of how a guest obtains `cm* = Σ ρ^i·cm_i`.
2. **The SRS digest is a digest of the `SrsVerifier`** (§3), not of every power. At S17
   the owner folded the packed generic table's three commitments into it (§3).
3. **EXIT is the only provable ecall** (§8.4). The tiny guest's committed result is its
   exit status.
4. **The statement's variable-length record lives in `PublicInputs`** (§1). A
   `ShardProof` has a fixed shape per `(VerifyingKey, family)`.
5. **`next_pc` is the decoder's fall-through**, not `pc + 4` (§8.5).
6. **No separate claim-merging sumcheck** (§5.3).

---

## 1. The statement

A statement is one execution of one program. It is proven by one `ShardProof` per
shard of every family, **every one of them verifying against one `PublicInputs`**: a
single shard proof establishes its own circuit and its own opening, and checks the
memory argument's reconciliation over roots the other shards' proofs establish. S20
aggregates them.

### 1.1 `PublicInputs`

| field | what |
| --- | --- |
| `input: Vec<u8>` | the fd 0 bytes the guest consumed |
| `output: Vec<u8>` | the fd 1 bytes it wrote |
| `exit_status: u32` | the guest's result: `x10`'s final value |
| `shard_counts: Vec<u32>` | one per family of the `VmConfig`, in its order (S11) |
| `windows: Vec<u32>` | `ZERO_WINDOWS`' window ids, `docs/spec/memory.md` §3.5 |
| `boundary: BoundaryFinals` | the 64 boundary scalars, `docs/spec/memory.md` §4.1 |
| `memory_commitments: Vec<Vec<G1>>` | per shard, in statement order (§1.2), that shard's memory columns `M[0..]` in layout order |
| `memory_roots: Vec<[Fr; 2]>` | per shard, in statement order, its `[read_root, write_root]` |

The first three are what the outside world asserts. The rest is the statement's
record: chosen by the prover, absorbed into the global transcript before any
challenge (§2) — every field but `memory_roots`, which are computed after the
challenges and bound instead by each shard's own GKR proof (§6, step 10a).

### 1.2 Statement order

The shards of a statement, in this order, which is the order of
`memory_commitments`, `memory_roots` and the global transcript's groups:

```text
(INIT_TEARDOWN, 0)
(ZERO_WINDOWS, 0) … (ZERO_WINDOWS, k − 1)
then every other family of the VmConfig, ascending by id, shards 0 … count − 1 each
```

`verifier_core::statement_shards(config, counts)` is this list. A family with count 0
has no entry. `ZERO_WINDOWS` shard `i` is window `windows[i]`; `INIT_TEARDOWN` shard 0
is window 0.

---

## 2. The global transcript

`verifier_core::global_commit(vk, statement)` is this section, run identically by
`prover::global_commit_phase` and by the verifier. A fresh `Transcript`:

| # | op | tag | message |
| --- | --- | --- | --- |
| G1 | absorb | `PROTOCOL_SUITE` (1) | `[PROTOCOL_VERSION]` |
| G2 | absorb | `SRS_DIGEST` (34) | `[vk.srs_digest]` |
| G3 | absorb | `VM_CONFIG` (23) | the static `VmConfig`, S11 |
| G4 | absorb | `SHARD_COUNTS` (24) | `shard_counts` |
| G5 | absorb | `MEMORY_WINDOWS` (30) | `windows` |
| G6 | absorb | `PROGRAM_IDENTITY` (22) | `[vk.identity]` |
| G7 | absorb | `PUBLIC_INPUTS` (2, bytes) | the 32 canonical bytes of `io_digest(input, output)` |
| G8 | per group | `MEMORY_GROUP` (36), then `COMMITMENT` (3) per shard | see below |
| G9 | absorb | `MEMORY_BOUNDARY` (31) | `t_0 … t_31, t_pc, v_1 … v_31` |
| G10 | squeeze ×4 | `MEMORY_CHALLENGE` (37) | `γ_M, α_addr, α_ts, α_val`: slots 1 to 4 |
| G11 | squeeze | `GLOBAL_STATE_DIGEST` (38) | the global state digest |

G3 to G5 are `absorb_statement_descriptor`, S11's three adjacent messages as S14
amended them. G1 is the protocol suite tag carrying `PROTOCOL_VERSION`: the suite is
the tag, the version its payload.

**The generic table has no step of its own (S17).** The packed generic table of
`docs/spec/lookup.md` §9 is committed setup that program identity does not bind (owner's
decision, S16 answer 8). Its three commitments are inside the SRS digest (§3), so G2 binds
them before every challenge of the statement and of every shard seeded from it.
`docs/spec/jump-branch-slt.md` §6 is the binding in full.

**G8, the memory-column groups.** One group per family of the `VmConfig` — the
`INIT_TEARDOWN` group, then the `ZERO_WINDOWS` group, then every other family's
ascending by id, a family with no shards included:

```text
append_scalars(MEMORY_GROUP, [family, shard count])        domain separation and the count
per shard, in shard order:
    append_g1_points(COMMITMENT, that shard's memory commitments)    one message, 4k limbs
```

The two init families lead and are therefore excluded from "every other family"
(master, *Statement binding*). Each group is domain-separated by its header and
length-delimited by its count and by each list's framed length; given the verifying
key, which fixes every list's length (the family's `M` column count), the absorbed
stream parses back uniquely.

**The global state digest** is G11's value. It is drawn once, after the memory
challenges, and seeds every shard (§4). The prover's `GlobalCommitState` carries the
transcript after G11, the statement, the four challenges and the digest.

### 2.4 G1 points, curve-free

A commitment is carried as its 64-byte canonical encoding `x ‖ y`, all zero for
infinity (S05). `transcript::g1_limbs` turns one into the frozen four limbs of
`docs/spec/mercury.md` §4 without any curve arithmetic: all-zero bytes give the
infinity sentinel four times, and anything else gives `x[0..16], x[16..32],
y[0..16], y[16..32]` as little-endian integers. `transcript::append_g1_points` absorbs
a list as one message of `4k` limbs, and `pcs::append_g1_list` is that function over
`G1Affine::to_bytes`. A point whose bytes are not a valid encoding is absorbed as
those bytes say, and refused where it is decoded (§6, step 12).

---

## 3. The SRS digest

`verifier_core::srs_digest(verifier, generic_table)`: a fresh `Transcript` absorbs two
messages,

```text
append_bytes(SRS_VERIFIER (35), srs_verifier)          320 bytes: g1_gen ‖ g2_gen ‖ g2_tau, S07's layout
append_g1_points(GENERIC_TABLE (41), generic_table)    3 points, one message of 12 limbs       S17
```

and the digest is one raw `sample()`, as `io_digest`'s is: raw, because a challenge under
a bytes tag would be one tag in two kinds. The three points are in tuple order — key,
value, result — each as §2.4's four limbs. Tag 41 is absorbed in this sponge and nowhere
else.

The digest binds the points a verifier's pairings read and the table every generic lookup
reads, so a proof is bound to the setup its verifier checks it against. It is not a digest
of the powers: S07's full-SRS digest remains dropped (`docs/spec/srs.md` §4), and a
prover's powers are bound only through the pairing check against `g2_tau`.

**S17's amendment.** At S16 the digest was the first message alone. S17 added the second,
on the owner's decision to fold the generic table into the SRS digest. Every S16 key's
digest therefore changed, and so did its bytes (§9). The table enters the global
transcript only through this digest, which G2 absorbs.

**S18 changed the table, not the recipe.** Appending `ShiftPowers` to the packed table
moved its three commitments, so every S16 and S17 key's digest and bytes moved with them.
The message, its tag, its position and the rest of this section are unchanged.

**Why one digest can carry the table.** Both messages are constants of the ceremony. A
Mercury commitment is a plain KZG commitment of the evaluation table read as coefficients
(`docs/spec/mercury.md` §2), and `program::lookup_tables::generic_table(n)` is zero past
its entries — 131,073 at S17, 131,105 since S18. So the table over `2^n` rows commits to the same three points at
every even `n ≥ 18`, which is every height Mercury commits at from `2^18` up, and every
key carries that one set, whatever its program and heights.
`program::lookup_tables::generic_commitments(srs)` computes it at `GENERIC_LOG_HEIGHT`,
18. It panics on an SRS of fewer than `2^18` powers, which no provable program's SRS is:
that SRS holds at least its tallest family's rows, and every execution family's shard is
at least `2^20` rows. `crates/program/tests/vectors/generic_table.txt` pins the three
points over the PSE ceremony.

**Where the trust sits.** A key's loader recomputes the digest from the key's own
`srs_verifier` and `generic_table` (§7.2), so a loaded key's digest agrees with its own
points and says nothing about whether they are the ceremony's. A verifier therefore
obtains the SRS digest from a trusted channel, as it obtains identity. Instead of the
digest it may obtain the ceremony's `SrsVerifier` and the table's three commitments, which
anyone holding the ceremony recomputes with `generic_commitments`. Take a key whose table
commitments were swapped for another table's. With the honest digest, it does not load.
With its own recomputed digest, it loads, but that digest is not the trusted one; G2 then
absorbs a different digest, and every honest proof is refused under the key as
`Statement("the proof was made for another statement")`. A verifier that uses a key's
digest without comparing it with the trusted one has not checked which table its generic
lookups read: whoever built the key can commit another table in it, and proofs whose
lookups hold only in that table verify under that key. Identity is unchanged, and binds
neither the SRS nor the generic table.

---

## 4. The shard transcript

For shard `(family, index)`, a fresh `Transcript`:

| # | op | tag | message |
| --- | --- | --- | --- |
| S1 | absorb | `SHARD_SEED` (39) | `[digest, family, index]` |
| S2 | absorb | `SHARD_TS_WINDOW` (40) | `[start, end]` |
| S3 | absorb | `COMMITMENT` (3) | the shard's witness commitments `W[0..]`, one message |
| S4 | squeeze ×2 | `LOOKUP_CHALLENGE` (33) | `g`, then `β` |
| S5 | the GKR schedule | | `docs/spec/gkr.md` §5.2: outputs, point, then per transition |
| S6 | the batch opening | | `docs/spec/mercury.md` §11.1 then §5: B1–B3 and the sixteen steps |

S4 is drawn for every shard, whether or not its circuit names a lookup slot: one
schedule, not two. **The time window** at S16 was the trivial one, `[0, 2^38)` — the
whole clock — and a verifier refused any other. **Since S20 it is the shard's own**,
`[4·cycle(row 0), 4·max cycle + 4)` for a cycle-owning family and the trivial window for
one whose rows are RAM words; step 4 holds it to `start <= end <= 2^38` and nothing more,
and the block's rule — ordered and disjoint within each cycle-owning family — is
`docs/spec/block-proof.md` §4, which needs every shard and so is `verify_block`'s. S20
generalized the value, not the field or its position, and the S16 seed is unaltered. **Every local challenge follows every commitment the shard reads**: the memory
columns before G10, the setup columns through the identity before G10, the generic
table's columns through the SRS digest at G2 (S17), the witness columns at S3.

**The external challenges** the shard's circuit reads: slots 1 to 4 from G10; for a
RAM window family, the derived slot 5 through
`gkr_verify::window_challenges(memory, window, trace_vars)`, window 0 for
`INIT_TEARDOWN` and `windows[index]` for `ZERO_WINDOWS`; then
`gkr_verify::insert_lookup_challenges(g, β, artifact)`.

**The output claims** are the top layer, which has zero variables: one value per
output-map entry, in output-map order — the memory roots, then each channel's
`(num, den)` pair in channel order (`docs/spec/lookup.md` §6).

---

## 5. The opening

### 5.1 One opening per shard

After S5, every committed column of the shard's circuit has one `BaseClaim`, all at
**one** point — layer 0's transition reduces them together (`docs/spec/gkr.md` §5.2).
S6 opens all of them in one RLC-batched Mercury opening at that point:

```text
columns      the circuit's committed layout: M[0..], W[0..], S[0..]
commitments  M from PublicInputs.memory_commitments[position]
             W from ShardProof.witness_commitments
             S from VerifyingKey.setup_commitments[family],
               then VerifyingKey.generic_table if the circuit reads GENERIC    (S17)
point        the base claims' point, variable j at index j (Mercury's u1 first, S08)
values       layer 0's L3 message: ShardProof.gkr.layers[0].final_evals
```

Virtual columns are never claimed and never opened: `gkr_verify::verify` evaluates
their closed form itself.

`FamilyCircuit::reads_generic_table` is whether any of the circuit's channel specs is
`GENERIC`; `reduce_shard`'s step 11 and the prover's opening both list the key's one
`generic_table` after identity's commitments exactly when it is true. **Five of the seven**
registered execution families read it: `JUMP_BRANCH_SLT`, whose `S[0..7]` are the decoded
table and whose `S[7..10]` are the packed generic table; S18's `SHIFT_BITWISE` and S19's
`MEM_SUBWORD`, the same shape; and S18's `MUL_DIV` and S19's `ATOMICS`, whose decoded
tuples have no immediate, so each table is `S[0..6]` and the packed table `S[6..9]`.
`ADD_SUB_LUI_AUIPC` and S19's `MEM_WORD` do not, and each opens identity's list alone. So `guests/alu`'s shards at
`2^20` open `21 + 44 + 10` = 75, `21 + 61 + 10` = 92 and `21 + 54 + 9` = 84 commitments,
each ending with the key's `generic_table`, and its add/sub shard opens `36 + 31 + 7`.
**Nothing in the key changed when the second and third readers arrived**, which is the
point of carrying the triple in every key whatever its families read.

### 5.2 What the setup commitments bind

The verifying key's setup commitments are program identity's lists
(`docs/spec/memory.md` §6.2). So the `INIT_TEARDOWN` shard's `S[0]` is opened against
identity's `cm(image column)`, which is S14's owed binding of the image the proof reads
to the image identity commits, and an instruction family's decoder table is opened
against the table identity commits. A family that reads the generic channel names the
packed table as its setup columns right after identity's, and they are opened against the
key's `generic_table`, which the SRS digest covers and G2 absorbs (§3, S17). The honest
table's `2^n`-row columns commit to those three points at every even `n ≥ 18`, so one set
serves every height.

### 5.3 No claim-merging sumcheck

The master's zerocheck-discharge bullet reduces "all base-layer claims to one point per
shard" with a final claim-merging sumcheck. In this engine a shard is one circuit, and
the GKR backward pass already leaves every committed column's claim at one point, so a
merging sumcheck would merge one point into itself. There is none. The prover asserts
the base claims share one point and the verifier re-derives it.

---

## 6. `verify_shard`

`verifier::verify_shard(vk, proof, public_inputs) -> Result<(), VerifyError>` is the one
verification path. Its first eleven steps are `verifier_core::reduce_shard`, which
returns the opening's claim; the twelfth is the wrapper's. Checks run in this order,
and the first that fails names the class:

| step | class | check |
| --- | --- | --- |
| 1 | `Statement` | one shard count per `VmConfig` family; the key's circuits are its config's families, in order |
| 2 | `Statement` | `docs/spec/memory.md` §3.5's window rules (`check_memory_windows`) |
| 3 | `Statement` | `memory_commitments` has one list per statement shard, each as long as its family's `M` layout; `memory_roots` one pair per statement shard |
| 4 | `Statement` | the time window is a window: `start <= end <= 2^38` (S20; at S16, `[0, 2^38)` exactly) |
| 5 | `Statement` | the replayed global state digest (§2) equals the one the proof carries |
| 6 | `Malformed` | the proof's family is in the config and its index below its count; its witness commitments, outputs and GKR transitions have the circuit's shape |
| 7 | `Constraint` | `gkr_verify::verify` over the shard transcript (§4): any `LayerInconsistency` |
| 8 | `Constraint` | every base claim at one point |
| 9 | `Lookup` | `gkr_verify::channel_holds` on every channel's root pair, in channel order |
| 10a | `MemoryArgument` | the proof's two memory roots are the statement's for its shard |
| 10b | `MemoryArgument` | every boundary timestamp below `2^38`; `v_10 = exit_status`; `gkr_verify::reconciles` over every shard's roots with `boundary_factors(memory challenges, vk.entry_pc, boundary)` |
| 11 | — | return the opening claim (§5.1) |
| 12 | `Opening` | decode every commitment, the `SrsVerifier` and the Mercury proof, and `pcs::batch_verify` |

`VerifyError` is `Statement(reason)`, `Malformed(reason)`, `Constraint { layer }`,
`Lookup { channel }`, `MemoryArgument(reason)`, `Opening`. `reduce_shard` never panics
on anything a proof or public inputs carry, for a key that passed its load (§7.2). S20
added no class: a block's own refusals are `Statement`.

**The split (S20).** The steps divide by *what they read*, so a block pays for each
exactly as often as its operands change:

| part | reads | run |
| --- | --- | --- |
| `verifier_core::derive_global_phase(vk, public) -> Result<GlobalChallenges, VerifyError>` | the key and the statement | steps 1 to 3 and the global transcript, **once per statement** |
| `verifier_core::verify_global_memory(vk, global, public) -> Result<(), VerifyError>` | the key, the statement and the memory challenges | step 10b, **once per statement** |
| `verifier_core::verify_shard_local(vk, global, proof, public) -> Result<OpeningClaim, VerifyError>` | one `ShardProof` besides | steps 4 to 10a and 11, **once per shard** |

**Step 10b names no `ShardProof`, and that is the whole of why it is its own
function.** Its operands are `vk.entry_pc`, `public.boundary`, `public.memory_roots`
and the four memory challenges — the statement's and the key's, every one of them — so
it has one answer for a statement and a verifier that ran it per shard would fold the
same 66 boundary tuples and multiply the same root product `Σ shard_counts` times over
for that one answer. What puts a *particular* shard's proof into that product is step
10a, which holds the roots its own GKR outputs claim to the statement's entry for its
position; with shard-set exactness on top (`docs/spec/block-proof.md` §2.1) every root
the product reads belongs to a shard that was verified.

`reduce_shard` is `derive_global_phase`, then `verify_shard_local`, then
`verify_global_memory`, and `verifier::verify_shard` is that plus step 12. **The order
is S16's** and not merely close to it: step 11 builds the opening claim and has no
failure, so running 10b after it returns yields the same first failure, in the same
class, with the same message, as S16's single step 10 did. `verify_block` runs the two
statement parts once each for the whole block (`docs/spec/block-proof.md` §3).

**A statement is verified when its proofs are exactly its shards**, `statement_shards(config,
shard_counts)`, each once in any order, and every one passes `verify_shard`. One shard's
proof establishes its own circuit and opening and checks the reconciliation over roots
the statement *claims* for the others; only their own proofs establish those. A caller
that verifies a subset has verified nothing about the rest, and the `verifier` CLI refuses
a proof list that is not the statement's shards.

Steps 1 to 4 run before the replay so that a statement the key does not describe is
refused rather than indexed out of range. The exit status is step 10b's because it is
a teardown: `v_10` is `x10`'s final value, which the boundary carries.

**Why this order classifies.** A prover that proves a tampered witness honestly —
recounting its multiplicities, recommitting its columns, rebuilding its statement —
produces a proof whose first failing check is the one the tamper broke: a gate
(`Constraint`), then a table membership (`Lookup`), then the multiset (`MemoryArgument`).
A statement the verifier did not agree to fails the digest (`Statement`). Claims that
do not match the commitments fail the opening (`Opening`).

---

## 7. The verifying key

### 7.1 Fields

| field | what |
| --- | --- |
| `code_version: u32` | the decoded tables' version, `constants::family::CODE_VERSION` |
| `config: VmConfig` | the static shape |
| `entry_pc: u32` | the entry pc, bound by identity |
| `identity: ProgramIdentity` | the program's identity |
| `setup_commitments: Vec<Vec<G1>>` | identity's per-family commitment lists, `docs/spec/memory.md` §6.2 |
| `srs_verifier: [u8; 320]` | the `SrsVerifier`, S07's layout |
| `generic_table: [G1; 3]` | the packed generic table's `constants::generic_table::WIDTH` commitments, key column first (S17): in every key, whether or not a family reads the `GENERIC` channel; covered by the SRS digest, not in identity |
| `srs_digest: Fr` | §3, over `srs_verifier` and `generic_table` |
| `circuits: Vec<FamilyCircuit>` | one per config family, in its order: the family, its `CircuitArtifact` and its `ChannelSpec`s |

`FamilyCircuit` is `constraints::FamilyCircuit`. A key conveys the artifact **and** the
channel specs: which output pair is whose root, which columns are a table and which
column counts it are not recorded in an artifact (`docs/spec/lookup.md` §13).

### 7.2 Loading

`VerifyingKey::from_bytes` decodes (§9) and then `VerifyingKey::check` refuses:

- a `VmConfig` that `VmConfig::from_bytes` refuses, or a code version other than
  `CODE_VERSION`;
- a setup list count that is not the config's family count;
- an `identity` that `identity_digest(code_version, config, entry_pc,
  setup_commitments)` does not reproduce;
- an `srs_digest` that `srs_digest(srs_verifier, generic_table)` does not reproduce, as
  "the SRS digest is not the digest of the key's SrsVerifier and generic table" (the
  table since S17);
- circuits that are not the config's families in its order, at its heights;
- a circuit that is not **byte-for-byte** `constraints::family_circuit(family,
  trace_vars)` — the artifact and the specs both. The circuits are protocol constants
  given a family and a height, and nothing binds them otherwise: identity binds the
  program, not the circuit that proves it;
- a circuit that fails `CircuitArtifact::validate`, `memory::check_memory` or
  `lookup::check_discharge` — run at every load, as S14 and S15 owed, although the
  constructor already ran them;
- a family whose setup list, plus `WIDTH` when its circuit reads the `GENERIC` channel,
  is not its artifact's `S` count, as "family F: N setup commitments and G of the generic
  table for S setup columns" (S17);
- a circuit whose `GENERIC` channel specs do not name the table as the `WIDTH` setup
  columns right after identity's — `S[N..N + WIDTH]`, `N` the family's setup list
  length — as "family F: the circuit does not name the generic table as its last setup
  columns" (S17). This one holds the registry to the order the opening lists the
  commitments in (§5.1), and no key whose circuit is the registry's can trip it. It
  guards a later registry entry: `ProverSetup::new` runs `check`, so such an entry fails
  where its key is built.

`verifier::load_verifying_key(bytes)` is that, plus decoding every curve point: the
`SrsVerifier` through S07's validating reader, and every setup commitment and the three
generic-table commitments through `G1Affine::from_bytes`, a bad table point refused as
"a generic-table commitment is not a point". **A verifier takes the identity from a
channel the prover does not control** and compares it with the loaded key's; the
`verifier` CLI takes it as an argument.

**A load does not check the ceremony.** Identity binds the setup commitments, not the SRS
they were computed over, and the SRS digest is recomputed from the key's own
`SrsVerifier` and generic table. So a key whose `SrsVerifier` is replaced by points whose
`tau` someone knows, digest recomputed, loads and matches the true identity, and whoever
knows that `tau` can open any commitment to any value. A key whose generic table is
another table's, digest recomputed, loads too and matches the true identity (§3).
The digest makes a proof specific to one set of verifier points and one table; it does
not make them the ceremony's. That is `docs/spec/srs.md` §4's presumption, narrowed and
not removed: a verifier must hold the ceremony's SRS digest from a trusted channel, as it
holds identity, or hold the ceremony's `SrsVerifier` and the table's three commitments and
recompute the digest from them (§3).

Validation runs at load, once. `verify_shard` assumes a loaded key and does not check
it again; on a key that did not pass, its answer means nothing. Steps 1 to 5 still refuse,
as `Statement`, a key edited in memory whose config differs from the one the proof was
made under or whose circuit list is not its config's families; an edit inside a circuit
is not caught before step 6, and may not be caught at all.

---

## 8. The `ADD_SUB_LUI_AUIPC` family

`constraints::add_sub::artifact(trace_vars)` and `add_sub::channels()`, through S15's
`frame_with_channels_artifact`. `trace_vars ≥ 20`: the timestamp channel needs 19
variables and Mercury an even count.

### 8.1 Columns

The frame is `docs/spec/memory.md` §2.1's over the family's **eight** queries — `pc rs1
rs2 arg1 arg2 ram rd deleg` at slots 0 to 7 — so `M[0..41]` and `W[0..11]` are the frame's,
and `M[41] deleg_space` follows them: the one extra memory column a frame holding the
delegation mirror carries, which is the requested type's address-space tag and what that
query's leaf reads for its `AS` term (`docs/spec/delegation.md` §5.1). `deleg` is S21's, a
delegation request's mirror query; every column index below moved by five in `M` and by one
in `W` when it was added, and so did every relation number in
`docs/spec/constraint-manifest.md` §3. The circuit adds:

| column | name | what |
| --- | --- | --- |
| `W[11]`–`W[16]` | `decoded_next_pc`, `decoded_rs1`, `decoded_rs2`, `decoded_rd`, `decoded_imm`, `decoded_mask` | the claimed decoded row |
| `W[17]`–`W[22]` | `kind_system`, `kind_addi`, `kind_auipc`, `kind_add`, `kind_sub`, `kind_lui` | the mask's bits, `constants::extra_mask::add_sub_lui_auipc` order |
| `W[23]`, `W[24]` | `is_ecall`, `is_fence` | the system kind, split by its code |
| `W[25]`–`W[27]` | `is_deleg_9`, `is_deleg_10`, `is_deleg_11` | **S21**, widened at **S23**: the ecall row is a delegation request of exactly one type, not the exit. One selector per row of `constants::delegation::TYPES` |
| `W[28]` | `wrap` | the sum's carry, or the difference's borrow |
| `W[29]` | `rd_hi` | `rd_selected >> 16` |
| `W[30]` | `pc_wrap` | `next_pc`'s wrap |
| `W[31]` | `next_pc_hi` | `next_pc >> 16` |
| `W[32]`–`W[34]` | `mult_timestamp`, `mult_range16`, `mult_decoder` | one multiplicity per channel, last |
| `S[0]`–`S[6]` | `table_pc` … `table_extra_mask` | the decoded table, `program::lookup_tuple` order |
| `V[range19]`, `V[range16]` | | the two range tables |

`rd_selected` (`W[10]`) is the value the instruction **computes**, before the x0 rule
masks it: the family's fill writes it on every live row, `rd = x0` included, where
S14's frame builder leaves it 0.

### 8.2 Gates

In the frame's gate list 0, after its own **16** (eight booleanity, four write-backs, four
x0 — `deleg` is not read-only and carries no write-back), with `m_q` the query `q`'s mask,
`v_q` its read value, `a_q` its address,
`pc` the pc query's read value, `next_pc` its write value, `sel = rd_selected`, and
`b_kind` the kind bits:

| gate | polynomial | what it holds |
| --- | --- | --- |
| `kind_<k>_boolean` ×6 | `b − b²` | each bit is 0 or 1 |
| `decoded_mask_bits` | `Σ_k 2^k·b_k − decoded_mask` | the packed mask is its bits (degree 1) |
| `is_ecall_boolean`, `is_fence_boolean` | `x − x²` | |
| `system_split` | `is_ecall + is_fence − b_system` | a system row is exactly one of the two |
| `ecall_code` | `is_ecall·decoded_imm` | an ecall row's code is 0 |
| `fence_code` | `is_fence·decoded_imm − 2·is_fence` | a fence row's code is 2; so no row is an `ebreak` |
| `is_deleg_{t}_boolean` | `x − x²` | **S21**, one per type since **S23** |
| `deleg_{t}_is_an_ecall` | `is_deleg_t·(1 − is_ecall)` | **S21**: a delegation request is an ecall row and takes the ecall frame |
| `deleg_{t}_number` | `is_deleg_t·(v_rs1 − N_t)` | **S21**: `a7` is that type's number. `N_t` is read from `constants::delegation::TYPES`, never spelled |
| `ecall_is_exit` | `(is_ecall − Σ_t is_deleg_t)·(v_rs1 − 93)` | `a7 = EXIT` on every ecall row **that is not a delegation**. With the rows above these partition the ecalls this family proves — because the numbers are pairwise distinct, which a `const` assertion enforces |
| `rs1_mask_rule` | `m_rs1 − m_pc·(b_add + b_sub + b_addi + is_ecall)` | |
| `rs2_mask_rule` | `m_rs2 − m_pc·(b_add + b_sub + is_ecall)` | |
| `arg1_mask_rule`, `arg2_mask_rule`, `ram_mask_rule` | `m_q` | no `read`/`write` arguments, no transfer |
| `rd_mask_rule` | `m_rd − m_pc·(b_add + b_sub + b_addi + b_auipc + b_lui + is_ecall)` | |
| `deleg_mask_rule` | `m_deleg − m_pc·Σ_t is_deleg_t` | **S21**: exactly the delegation rows make the mirror query |
| `deleg_space_rule` | `deleg_space − Σ_t tag_t·is_deleg_t` | **S23**: the mirror's leaf names the requested type through this column, because a leaf may read no `W` column (`docs/spec/delegation.md` §5.1) |
| `rs1_addr_rule` | `m_rs1·(a_rs1 − decoded_rs1 − 17·is_ecall)` | `rs1`, or `a7` on an ecall |
| `rs2_addr_rule` | `m_rs2·(a_rs2 − decoded_rs2 − 10·is_ecall)` | `rs2`, or `a0` |
| `rd_addr_rule` | `m_rd·(a_rd − decoded_rd − 10·is_ecall)` | `rd`, or `a0` |
| `rs1_value_masked`, `rs2_value_masked` | `v_q − m_q·v_q` | an absent operand reads 0 |
| `add_addi_auipc` | `(b_add + b_addi + b_auipc)·(v_rs1 + v_rs2 + decoded_imm − sel − 2^32·wrap) + b_auipc·pc` | the three sums, one gate |
| `sub` | `b_sub·(v_rs1 − v_rs2 − sel + 2^32·wrap)` | |
| `lui` | `b_lui·(decoded_imm − sel)` | |
| `exit_status` | `(is_ecall − Σ_t is_deleg_t)·(v_rd − sel)` | the exit row writes back `a0`; a delegation row does not |
| `deleg_writes_no_register` | `m_deleg·sel` | **S21**: a delegation answers 0 |
| `deleg_read_ts_zero` | `m_deleg·read_ts_deleg` | **S21**: the mirror query reads the invocation's answer tuple |
| `deleg_read_value_zero` | `m_deleg·v_deleg` | **S21**: and that tuple's value is 0 |
| `deleg_addr_rule` | `m_deleg·(a_deleg − v_rs2)` | **S21**: the mirror sits at the frame base the request passed in `a0` |
| `wrap_boolean`, `pc_wrap_boolean` | `x − x²` | |
| `next_pc_rule` | `next_pc + 2^32·pc_wrap − (1 − is_ecall + Σ_t is_deleg_t)·decoded_next_pc − HALT_PC·(is_ecall − Σ_t is_deleg_t)` | the fall-through, or `HALT_PC` on the exit row; **a delegation row falls through** |

Every gate is of degree at most 2 — `decoded_mask_bits`, `system_split` and the three
`arg1`/`arg2`/`ram` mask rules are linear — and 0 on the all-zero row. **All eight S21 gates
are degree 2, and the three they amended stayed degree 2**: each gained terms on an existing
product's other factor, never a third factor. S23 did the same — three gates per type where
S21 had four for the one, plus `deleg_space_rule`, which is degree 1. By
`deleg_{t}_is_an_ecall` the factor `is_ecall − Σ_t is_deleg_t` is 0 or 1 on any row that
passes, never negative. The semantic gates are gated by a
decoder bit, never by `m_pc` times a bit: on a live row the bits are the table's, and on
a padding row every mask is 0, so whatever the bits say reaches no memory event.

### 8.3 Lookups

After the frame's **16** timestamp obligations — two per query, and `deleg` is the eighth —
all under the selector `m_pc`:

| lookup | channel | tuple |
| --- | --- | --- |
| `rd_hi_range` | `RANGE16` | `rd_hi` |
| `rd_lo_range` | `RANGE16` | `sel − 2^16·rd_hi` |
| `next_pc_hi_range` | `RANGE16` | `next_pc_hi` |
| `next_pc_lo_range` | `RANGE16` | `next_pc − 2^16·next_pc_hi` |
| `decode_row` | `DECODER` | `pc, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_imm, decoded_mask` |

**16** timestamp, 4 `RANGE16` and 1 decoder obligation; the constructor asserts the counts.
Seventeen `TIMESTAMP` leaves — sixteen obligations and the table fraction — pad to a 32-leaf
tree, so this circuit is six row-wise gate lists deep rather than five
(`docs/spec/constraint-manifest.md` §1.3).
The channels, in output order, are `TIMESTAMP` over `V[range19]`, `RANGE16` over
`V[range16]` and `DECODER` over `S[0..7]`.

### 8.4 Why it is sound

On a **live row** (`m_pc = 1`) the decoder lookup binds the claimed row to the table
row at `pc`. `pc` is a 32-bit value — the entry pc, or an earlier row's range-checked
`next_pc` — so the row cannot be the table's `MINUS_ONE` padding; its mask is one-hot
among `{1, 2, 4, 8, 16, 32}`, so exactly one bit is set: `Σ 2^k·b_k` over booleans is a
power of two only for a single set bit. **One-hotness is the table's domain**: an
all-zero mask satisfies booleanity and the recomposition and is refused by the decoder
channel alone. On a system row exactly one of `is_ecall`, `is_fence` is 1, and the code
in `imm` picks which; the `ebreak` code 1 satisfies neither, so no row is an `ebreak`.

The mask rules fix every query's presence from the kind, exactly as
`docs/spec/execution-trace.md` §4 and §6 list it for an EXIT row; the address rules fix
every present query's address; an absent operand reads 0. With read values 32-bit —
every value any row writes is range-checked, and every init value and boundary value is
a `u32` — each sum is below `2^33` and each difference above `−2^32`, so with `sel` in
`[0, 2^32)` and `wrap` boolean the equations are the RISC-V results, wrap and borrow
included. An R-type row's `imm` is 0 and an I-type or U-type row's absent `rs2` reads 0,
so no third addend is live and one wrap bit suffices. The x0 rule of the frame masks
`sel` into the `rd` write.

`next_pc` is `decoded_next_pc − 2^32·pc_wrap` on every live row but the exit row, and
`HALT_PC − 2^32·pc_wrap` there; `next_pc` in `[0, 2^32)` forces `pc_wrap = 0`, since the
table's fall-through is below `2^31`. The table's `next_pc` is `pc + 2` or `pc + 4` by
the instruction's length (S11), so a compressed instruction of this family is proven at
its own length.

**EXIT only.** Every ecall row reads `a7 = 93`, writes `a0` back, and writes `HALT_PC`;
no row reads `a1` or `a2` or touches RAM. A program that makes any other ecall is not
provable at S16 — a completeness gap, not a soundness one — and the family's fill refuses
such a trace by name. The first exit row writes `HALT_PC`, which no table row claims, so
nothing follows it (`docs/spec/memory.md` §5).

On a **padding row** every mask is 0 by the mask rules, so the row reaches no memory
event, and every lookup is switched off by its selector.

### 8.5 Owed elsewhere, and what this family does not do

- `read`, `write`, `-EBADF`, `-ENOSYS` and transfer rows: the I/O-binding stage, which
  also chooses how a transfer is confined (S14's open question 10). **A delegation call is
  no longer among them**: S21 made `PRECOMPILE_KECCAK_F` the second provable ecall, with
  four gates of its own and three S16 gates amended (§8.2), and S23 added
  `PRECOMPILE_POSEIDON2` and `PRECOMPILE_FR_ARITH` beside it — one selector and three gates
  per type, with the shared gates gaining a term apiece and every one of them still degree
  2 (`delegation.md` §10). What makes it *correct* is not here but in the delegation
  family's circuit; this family only witnesses that the request was made
  (`docs/spec/delegation.md` §5).
- Binding fd 0 and fd 1 to the execution: that stage too (S14's D3, D5). At S16 the
  public I/O digest is in the statement, and nothing ties the streams to a row.
- The generic channel: the family does not look it up. **S17**, the first family that
  does, binds the exact packed-table commitment into the proof's statement or
  transcript before its lookup challenges are drawn — not into program identity
  (owner's decision, S16). S17 did, through the SRS digest (§3), which G2 absorbs
  before every challenge; `docs/spec/jump-branch-slt.md` §6 is the binding.

---

## 9. Wire forms

Every integer little-endian: `u32` four bytes, `u64` eight. An `Fr` is its 32 canonical
bytes, refused at or above `p`. A `G1` is 64 bytes, opaque to the core. `bytes` is a
`u32` length then the bytes; `list<T>` a `u32` count then the items. Every decoder is
total, reserves nothing an untrusted length asks for, refuses trailing bytes, and takes
only the encoding its encoder writes.

```text
PublicInputs   input bytes, output bytes, exit_status u32,
               shard_counts list<u32>, windows list<u32>,
               boundary 64 × Fr             t_0..t_31, t_pc, v_1..v_31; each t < 2^38 and
                                            each v < 2^32, or refused
               memory_commitments list<list<G1>>,
               memory_roots list<(Fr, Fr)>

ShardProof     family u32, shard_index u32, ts_window u64 u64, global_digest Fr,
               witness_commitments list<G1>, outputs list<Fr>,
               gkr list<(rounds list<[Fr; 4]>, final_evals list<Fr>)>    transition 0 first
               opening 704 bytes             MercuryProof::to_bytes

VerifyingKey   code_version u32, config bytes (VmConfig::to_bytes), entry_pc u32,
               identity Fr, setup_commitments list<list<G1>>,
               srs_verifier 320 bytes,
               generic_table 3 × G1          192 bytes, no count; S17
               srs_digest Fr,
               circuits list<(family u32, artifact bytes (CircuitArtifact::to_bytes),
                              channels list<(channel u32, table list<Address>,
                                             multiplicity Address)>)>
Address        tag u8 (0 M, 1 W, 2 S, 3 V), index u32 (a V's is its kind's wire tag)
```

A `ShardProof`'s lengths are data on the wire and fixed per `(VerifyingKey, family)`:
step 6 of §6 holds them to the circuit, and a `ShardProof` holds exactly one Mercury
proof.

S17 inserted `generic_table`, 192 fixed bytes, between `srs_verifier` and `srs_digest`,
so every S16 key's bytes changed, and its digest with them (§3).

---

## 10. The prover's phases

`prover::advance(setup, archive, until)` fills the S12 `TraceArchive`'s later phases
in order, each timed into S12's timing section, stopping after `until`; a phase already
filled is read back instead of recomputed. **Resume** is `TraceArchive::import` and
`advance`: an archive exported after any phase finishes to the same bytes as an
uninterrupted run.

| phase | content |
| --- | --- |
| `PostCommit` | `GlobalCommitState`: `bytes`, the statement's `PublicInputs` encoding (no roots); the global transcript's 226-byte snapshot after G11; the four memory challenges; the digest |
| `PostGkr` | `list<ShardGkr>` in statement order: family u32, shard u32, **ts_start u64, ts_end u64** (S20), witness commitments `list<G1>`, outputs `list<Fr>`, gkr, the base claims' point `list<Fr>`, the shard transcript's snapshot after S5 |
| `PostOpening` | `list<bytes>`: each shard's `ShardProof` encoding, statement order |
| `Final` | `bytes`, the complete `PublicInputs` encoding; then `list<bytes>` of the proofs |

A snapshot is `postcard`'s encoding of S02's `TranscriptSnapshot`, 226 bytes. Every
other field uses §9's encodings. The columns are not stored: they are a deterministic
function of the post-execution section and the program, and a resumed phase rebuilds
them.

**Determinism.** Every parallel step — commitments, the forward pass, the sumcheck, the
MSMs — combines its parts in a fixed order, so proofs do not depend on the thread count.

---

## 11. The registry

`constraints::family_circuit(family, trace_vars)` returns a family's circuit for
`ADD_SUB_LUI_AUIPC`, S17's `JUMP_BRANCH_SLT` (`docs/spec/jump-branch-slt.md`), S18's
`SHIFT_BITWISE` and `MUL_DIV` (`docs/spec/shift-bitwise.md`, `docs/spec/mul-div.md`) and
S19's `MEM_WORD`, `MEM_SUBWORD` and `ATOMICS` (`docs/spec/memory-ops.md`) — **every family
the master prompt names, since S19** — each built from 19 variables and provable from 20
(§8), for `INIT_TEARDOWN` (`image_window_artifact`, no channels) and for `ZERO_WINDOWS`
(`zero_window_artifact`, no channels). It returns `None` for a height its circuit cannot be
built at, and its minimum-height arm names **all seven** execution families, so a key
naming one at the menu's `2^16` or `2^18` is a clean `Err` at load and not a panic. `prover::family_fill` is the matching table of column builders. A
later family is added by one constructor, one arm in each table and one fill, with no
edit to `global_commit_phase`, `prove_shard`, `reduce_shard` or `verify_shard`. A later
family that reads the generic channel needs nothing more: every key already carries the
table's commitments, and `FamilyCircuit::reads_generic_table` adds them to its opening
(§5.1) and its setup count (§7.2). **S18's two families were exactly that** — two
constructors, two registry arms, two fills — plus the 32 rows they appended to the packed
table, which moved the table's commitments and so every key's SRS digest (§3), and nothing
in this crate's code. **S19's three were that and less**: three constructors, three registry
arms, three fills, and not even a row appended to the packed table, so no key's digest or
bytes moved. `MEM_WORD`, which reads no generic lookup, went down `ADD_SUB_LUI_AUIPC`'s
path and needed nothing of the generic machinery at all.

**S21's `KECCAK_F` was one constructor, one registry arm and one fill too** — plus the
`deleg` query, which is `docs/spec/memory.md` §2.1's table and not this crate's. Its arm sits
**after** the minimum-height guard, because a delegation family carries no lookup channel and
so meets no `BITS ≤ trace_vars` assertion: it is built at every `n` the artifact accepts, and
in practice at `2^8`. It reads no generic channel and lists no setup commitment at all, so its
opening claim is `M ++ W` — the first of any family. `docs/spec/delegation.md` is the ABI and
`docs/spec/constraint-manifest.md` §12 the accounting.

**S23's `POSEIDON2` and `FR_ARITH` were two constructors, two registry arms and two fills**,
both below the guard for the same reason, both opening `M ++ W`, and both at `2^8`. What they
cost beyond that is in the *request* side, not here: a second and third delegation number mean
the add/sub family carries one `is_deleg_t` bit per registered type rather than S21's one
`is_keccak`, and a frame holding the mirror carries the `deleg_space` column that says which
type the request names (§8.1, §8.2). Both are `docs/spec/memory.md` §2.1's table again and not
this crate's: `global_commit_phase`, `prove_shard`, `reduce_shard` and `verify_shard` are
unchanged, and no key's SRS digest moved, the packed generic table having gained no row.
`docs/spec/delegation.md` §12 and §13 are the two ABIs and
`docs/spec/constraint-manifest.md` §13 and §14 the accounting.
