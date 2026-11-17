# Falcon-512 with Poseidon2's HashToPoint

Falcon-512 v1.2 (the NIST round-3 specification) with one change: HashToPoint, the map from (public
key, salt, message) to the point c, is a Poseidon2-A64-C5 sponge instead of SHAKE256(salt ‖ message).
Keys, encodings, the signer's sampler and the acceptance rule are v1.2's. It is **not interoperable
with standard Falcon-512**: a standard signature does not verify here, nor the reverse. The
construction is specified in `docs/spec/precompiles.md`, “HashToPoint” in the section “The Falcon-512 lattice check”.

Three implementations, each with its own suite. These packages live here temporarily and will move
to their own repositories.

| Directory | Implementation | Suite |
|---|---|---|
| `rust/` | crate `apogee-falcon512`: keys from a seed, signing, the verifier the guest SDK's is held to | `cargo test -p apogee-falcon512` |
| `js/` | one ES module, no dependencies, Node.js ≥ 20 and browsers | `node --test` in `js/` |
| `python/` | package `apogee_falcon512`, standard library only, Python ≥ 3.9 | `python3 -m unittest discover -s tests` in `python/` |

## `vectors.json`

Every suite reads all of it. Bytes are lowercase hex.

- `standard_kat`: `{pk, msg, sig}`, entries 0, 1, 49 and 99 of the official Falcon-512 KAT
  (`falcon512-KAT.rsp`), each signed message re-encoded as a padded 666-byte signature (header
  `0x39`). They are standard Falcon-512: each suite feeds its verify core the point the test computes,
  SHAKE256(salt ‖ msg) read as 16-bit big-endian t, kept when t < 61445, c_i = t mod q.
- `hash_to_point`: `{pk, salt, msg, c}`, c as 512 integers: messages of 0, 3, 64, 200 and 1000 bytes
  under a real key (`rust/`'s, seed `0x5a…`) and an 897-byte pattern that is not a key. The 200-byte
  case's squeeze rejects one lane (≥ T).
- `key_digest`: `{pk, digest}`, eight lanes as `0x…` hex: empty, 3 bytes, the 897-byte pattern and
  the real key.
- `signatures`: `{signer, pk, msg, sig}`, two per implementation (an empty and a 64-byte message),
  each signed under a key that implementation generated.
- `malformed`: `{case, pk, msg, sig}`, each one departure from the Python 64-byte signature, whose
  `s2` has a zero coefficient: `negative_zero` (that zero's sign bit set, the same `s2` to a lenient
  decoder), `padding_byte_bit` (a one in the first whole padding byte), `last_byte_bit` (a one after
  the last coefficient, inside its byte), `header_0x29`, `one_byte_short`, and
  `key_coefficient_16383` (the key's first coefficient set to 2^14 − 1 ≥ q). Every verifier refuses
  each.

All three implementations computed `hash_to_point` and `key_digest` and agreed; each verifies every
`signatures` entry and the KAT through its core, and refuses every `malformed` entry.
