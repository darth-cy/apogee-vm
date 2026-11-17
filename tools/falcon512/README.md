# Falcon-512 with Poseidon2's HashToPoint

Falcon-512 v1.2 (the NIST round-3 specification) with one change: HashToPoint, the map to the point
c, is a Poseidon2-A64-C5 sponge over the key digest K, the salt, the application's context (0 to 255
bytes) and the message instead of SHAKE256(salt ‖ message). Keys, encodings, the signer's sampler and
the acceptance rule are v1.2's. Each signer draws a fresh salt, and so a fresh c, for every attempt: after a
norm or a compression rejection it starts over, where v1.2's Algorithm 10 keeps its salt. It is **not interoperable with standard Falcon-512**: a standard
signature does not verify here, nor the reverse. K is a sponge over the key, and a key's address is
K's first 32 bytes, written `0x`, 64 hex digits and an 8-digit checksum. The construction is
specified in `docs/spec/precompiles.md`, “HashToPoint” in the section “The Falcon-512 lattice check”.

Three implementations, each with its own suite. These packages live here temporarily and will move
to their own repositories.

| Directory | Implementation | Suite |
|---|---|---|
| `rust/` | crate `apogee-falcon512`: keys from a seed, signing, the verifier the guest SDK's is held to | `cargo test -p apogee-falcon512` |
| `js/` | ES modules, no dependencies, Node.js ≥ 20 and browsers; also user addresses (below) | `node --test` in `js/` |
| `python/` | package `apogee_falcon512`, standard library only, Python ≥ 3.9 | `python3 -m unittest discover -s tests` in `python/` |

## User addresses (JavaScript only)

A user is known by a user address, and a user's address comes from a 24-word recovery phrase that
the app's frontend generates (BIP39 words for 256 random bits), never from a sentence the user
invents. The app's own frontend derives the keys from the phrase and signs with them, so an Apogee
app needs no separate signing app. The same phrase, passphrase and index recover the same user
address:

```
root_seed    = BIP39(phrase, passphrase)                      PBKDF2-HMAC-SHA512, 2048 rounds, 64 bytes
address_seed = HKDF-SHA512(root_seed, salt empty,
                           info = u8(32) ‖ "apogee/user-address/falcon512/v1" ‖ u32_be(index), 48 bytes)
(sk, pk)     = the Falcon round-3 reference keygen of address_seed (SHAKE256 of the seed as its RNG)
address      = K(pk)[0..32]
```

`deriveUserAddress(phrase, { passphrase, index })` in `js/recovery.js` computes these four lines
and returns the keys, the address and its text. The keygen is the reference implementation's, bit
for bit, so the same phrase, passphrase and index recover the same keys and address everywhere.
`js/README.md` has the API, and `js/test/fixtures/recovery.json` holds its vectors: the official
BIP39 vectors, address seeds, and keys from the compiled reference C. The Rust and Python packages
sign and verify, but derive no user addresses.

## `vectors.json`

Every suite reads all of it. Bytes are lowercase hex.

- `standard_kat`: `{pk, msg, sig}`, entries 0, 1, 49 and 99 of the official Falcon-512 KAT
  (`falcon512-KAT.rsp`), each signed message re-encoded as a padded 666-byte signature (header
  `0x39`). They are standard Falcon-512: each suite feeds its verify core the point the test computes,
  SHAKE256(salt ‖ msg) read as 16-bit big-endian t, kept when t < 61445, c_i = t mod q.
- `hash_to_point`: `{pk, salt, context, msg, c}`, c as 512 integers: messages of 0, 3, 92, 200 and
  1000 bytes under contexts of 0, 3, 255, 9 and 0 bytes, under a real key (`rust/`'s, seed `0x5a…`)
  and an 897-byte pattern that is not a key. The 1000-byte case's squeeze skips one lane (≥ T).
- `key_digest`: `{pk, key_digest, address, address_text}`, K's 64 bytes, the address and its text:
  empty, 3 bytes, the 897-byte pattern and the real key.
- `address_text`: `{case, text, address}`, departures from the real key's text, each refused
  (`address` null): `checksum_digit` and `address_digit` (one digit changed), `73_hex_digits`,
  `non_hex_digit` and `no_0x`; and `uppercase`, its digits in uppercase, which reads as the address.
- `signatures`: `{signer, pk, msg, context, sig}`, two per implementation, each signed under a key
  that implementation generated: an empty message under the empty context and a 92-byte message under
  a 20-byte context.
- `malformed`: `{case, pk, msg, context, sig}`, each one departure from the Python 92-byte signature,
  whose `s2` has a zero coefficient: `negative_zero` (that zero's sign bit set, the same `s2` to a
  lenient decoder), `padding_byte_bit` (a one in the first whole padding byte), `last_byte_bit` (a one
  after the last coefficient, inside its byte), `header_0x29`, `one_byte_short`,
  `key_coefficient_16383` (the key's first coefficient set to 2^14 − 1 ≥ q), `wrong_context` (the
  context's last bit flipped), and `context_256_bytes` (a signature under a 256-byte context, valid
  but for the context's length). Every verifier refuses each.

All three implementations computed `hash_to_point`, `key_digest` and the `address_text` verdicts and
agreed; each verifies every `signatures` entry and the KAT through its core, and refuses every
`malformed` entry.
