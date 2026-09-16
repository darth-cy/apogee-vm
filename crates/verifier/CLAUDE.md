# `crates/verifier`

## What this crate owns
The one verification path, `verify_shard`, and the `verifier` CLI: the no_std core's
`reduce_shard`, then the shard's one batched Mercury opening through `pcs::batch_verify`,
which is where a base verification's pairings happen. `docs/spec/shard-proof.md` §6 and
§7.2 are normative. Nothing of the protocol lives here but step 12.

```rust
pub fn verify_shard(vk: &VerifyingKey, proof: &ShardProof, public: &PublicInputs)
    -> Result<(), VerifyError>;
pub fn load_verifying_key(bytes: &[u8]) -> Result<VerifyingKey, String>;
pub fn decode_srs_verifier(bytes: &[u8; 320]) -> Option<SrsVerifier>;
pub fn encode_srs_verifier(vsrs: &SrsVerifier) -> [u8; 320];
pub use verifier_core::{PublicInputs, ShardProof, VerifyError, VerifyingKey, OPENING_BYTES, SRS_VERIFIER_BYTES};
```

```
verifier <verifying-key> <identity-hex> <public-inputs> <proof>...
```
Exit 0 when the proofs are exactly the statement's shards, each once in any order, and
every one verifies; 1 naming the first file refused and why, or when the proofs are not
the statement's shards; 2 on a usage error. The identity is the program's 32 canonical
bytes, little-endian, as 64 lowercase hex digits, and it comes from the caller — a
verifier never takes identity from the key or the proof.

## Frozen invariants
- **One verification path.** The CLI, every test and `checker::TamperHarness` call
  `verify_shard`, and nothing else verifies a shard. Its signature is
  `(&VerifyingKey, &ShardProof, &PublicInputs)` and `tests/signature.rs` pins it at
  compile time.
- **Every curve point is decoded through its validating reader** — the `SrsVerifier`'s
  three through S05's `from_bytes`, every commitment through `G1Affine::from_bytes`, the
  Mercury proof through `MercuryProof::from_bytes` — and a point that is not one is
  `Opening`. The `SrsVerifier` is the only SRS material a verifier reads.
- **`load_verifying_key` is the key's load**: `VerifyingKey::from_bytes` (the core's
  §7.2), then every curve point the key carries. Run once per key; `verify_shard` does not
  load again.
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
| `src/lib.rs` (unit) | the core's opening width is `pcs::PROOF_BYTES` |
| `tests/signature.rs` | acceptance 12: `verify_shard` and `reduce_shard` pinned to `(&VerifyingKey, &ShardProof, &PublicInputs)` at compile time; the `SrsVerifier` layout round-trips and an off-curve point is refused |
| `tests/cli.rs` | **`#[ignore]`d** (it proves the S16 statement first): acceptance 10's CLI half — the dumped key, statement and proofs verify; another identity is refused; a flipped bit in each proof, the statement and the key is refused; each proof alone, and each given twice, refused as not the statement's shards, and the two in reverse order accepted; a usage error exits 2 |
