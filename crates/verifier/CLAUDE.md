# `crates/verifier`

## What this crate owns
The two verification entry points — `verify_shard` for one shard and `verify_block` for a
whole block — and the `verifier` CLI. Both are the no_std core's steps plus the shard's
one batched Mercury opening through `pcs::batch_verify`, which is where a base
verification's pairings happen. `docs/spec/shard-proof.md` §6 and §7.2 and
`docs/spec/block-proof.md` §3 are normative. Nothing of the protocol lives here but step
12 and the block's four structural checks.

```rust
pub fn verify_shard(vk: &VerifyingKey, proof: &ShardProof, public: &PublicInputs)
    -> Result<(), VerifyError>;
pub fn verify_block(vk: &VerifyingKey, proof: &BlockProof, public: &PublicInputs)
    -> Result<(), VerifyError>;                                          // S20
pub fn load_verifying_key(bytes: &[u8]) -> Result<VerifyingKey, String>;
pub fn decode_srs_verifier(bytes: &[u8; 320]) -> Option<SrsVerifier>;
pub fn encode_srs_verifier(vsrs: &SrsVerifier) -> [u8; 320];
pub use verifier_core::{BlockProof, BlockReconciliation, PublicInputs, ShardProof, ShardRecord,
                        VerifyError, VerifyingKey, OPENING_BYTES, SRS_VERIFIER_BYTES};
```

```
verifier <verifying-key> <identity-hex> <public-inputs> <proof>...
verifier block <verifying-key> <identity-hex> <public-inputs> <block>
```
Exit 0 when the first form's proofs are exactly the statement's shards, each once in any
order, and every one verifies, or when the second form's block verifies; 1 naming the
first file refused and why, or when the proofs are not the statement's shards; 2 on a
usage error. The identity is the program's 32 canonical bytes, little-endian, as 64
lowercase hex digits, and it comes from the caller — a verifier never takes identity from
the key or the proof, and it takes the statement from a channel the prover does not
control even in the `block` form, where the block carries a copy the verifier holds it
to.

## Frozen invariants
- **One verification path.** The CLI, every test and `checker::TamperHarness` call
  `verify_shard`, and nothing else verifies a shard. Its signature is
  `(&VerifyingKey, &ShardProof, &PublicInputs)` and `tests/signature.rs` pins it at
  compile time.
- **`verify_block` composes that path, it does not repeat it** (S20). It is
  `derive_global_phase` once, the block's four structural checks — the descriptor and
  the statement against the verifier's, `BlockProof::shape()`, and `check_ts_windows` —
  then `verify_global_memory` **once**, and then `verify_shard_local` plus the opening
  per shard, which are exactly the parts `verify_shard` runs. Its signature is
  `(&VerifyingKey, &BlockProof, &PublicInputs)` and nothing else. The cross-shard
  read/write root product is the verifier's and never a prover self-check.
- **Everything that reads only the statement runs once; only `verify_shard_local` runs
  per shard.** The cross-shard root product and the boundary fold are a function of the
  statement, so a block checks them once (B5) and not once a shard; what each shard
  still owes is step 10a, its own roots against the statement's entry for it, which
  `verify_shard_local` keeps. B3's shard-set exactness is what makes the two add up to
  S16's step 10: every root in the product belongs to a shard that was verified.
  Because B1–B5 verify no shard — they read the block's shape and its statement, never
  a GKR transition or an opening — a statement that cannot reconcile is refused before
  any shard's circuit is run.
- **Every curve point is decoded through its validating reader** — the `SrsVerifier`'s
  three through S05's `from_bytes`, every commitment through `G1Affine::from_bytes`, the
  Mercury proof through `MercuryProof::from_bytes` — and a point that is not one is
  `Opening`. The `SrsVerifier` is the only SRS material a verifier reads; the generic
  table's three commitments (S17) are the key's, and the key's SRS digest covers both.
- **`load_verifying_key` is the key's load**: `VerifyingKey::from_bytes` (the core's
  §7.2, which recomputes the SRS digest over the `SrsVerifier` and the generic table),
  then every curve point the key carries, through its validating decoder: the
  `SrsVerifier`, every setup commitment and, since S17, the generic table's three
  commitments, a bad one refused as "a generic-table commitment is not a point". Run once
  per key; `verify_shard` does not load again. A key that loads has a digest that agrees
  with its own points, which need not be the ceremony's: a verifier must hold the
  ceremony's SRS digest from a trusted channel, as it holds identity
  (`docs/spec/shard-proof.md` §3, §7.2). The CLI takes no SRS digest argument. It compares
  the key's identity with the one given and uses the key's SRS digest as the key file
  carries it, so that file's `SrsVerifier` and generic table are trusted as far as the
  file is.
- **A statement is its shards, all of them.** `verify_shard` answers for one shard: its
  reconciliation reads the roots the statement claims for every other shard, and only
  those shards' own proofs establish them. The CLI therefore requires the proof list to
  be `statement_shards(config, shard_counts)` exactly, after each proof verifies — so
  step 1 has already held the counts to the config — and a later statement-level caller
  must do the same (`docs/spec/shard-proof.md` §6).
- **No accumulator entries.** A base verification pairs inside `pcs`; the deferred path is
  the recursion stage's.

## Tests
| File | Covers |
| --- | --- |
| `src/lib.rs` (unit) | the core's opening width is `pcs::PROOF_BYTES`; `every_generic_table_commitment_is_decoded_at_load` (S17): a key with the jump family over real points loads back to itself, and each of the three generic-table commitments off the curve, the SRS digest recomputed over it, or a setup commitment off the curve, identity recomputed, is refused by name; `the_block_checks_the_statement_s_memory_argument_before_any_shard` (S20): a block of one shell shard over a statement whose boundary is out of the clock answers `MemoryArgument`, which only check 5 can give — the per-shard loop would have answered `Statement`, and the test asserts that too. It fails if check 5 is deleted or folded back into the loop |
| `tests/signature.rs` | acceptance 12: `verify_shard` and `reduce_shard` pinned to `(&VerifyingKey, &ShardProof, &PublicInputs)` at compile time, and the core's three parts to theirs — the two that take no `ShardProof` are the two a block runs once; the `SrsVerifier` layout, over three distinct points, round-trips field by field, and each of the three with one bit flipped is refused |
| `tests/cli.rs` | **`#[ignore]`d** (it proves the S16 statement first): S20's `the_cli_verifies_a_block_file` — the same statement proved as a block, the `block` verb exiting 0, and another identity, a statement that is not the block's, a flipped bit anywhere in the block, a shard file given to the block form and a block file given to the shard form each refused, with a usage error on a short `block` invocation; and acceptance 10's CLI half — the dumped key, statement and proofs verify; another identity is refused; a flipped bit in each proof, the statement and the key is refused; each proof alone, and each given twice, refused as not the statement's shards, and the two in reverse order accepted; a usage error exits 2 |
