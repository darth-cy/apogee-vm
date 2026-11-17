# apogee-falcon512

Falcon-512 with Poseidon2's HashToPoint, as one zero-dependency ES module for Node.js (≥ 20) and
browsers.

This is Falcon-512 v1.2 (the NIST round-3 specification) with one change: HashToPoint maps the
key digest K, the salt, the application's context and the message to the point c with a
Poseidon2-A64-C5 sponge instead of SHAKE256(salt ‖ message). Keys, signatures, encodings, the
sampler and the acceptance rule are v1.2's. Because HashToPoint differs, it is **not interoperable
with standard Falcon-512**: a standard signature does not verify here, and a signature made here
does not verify elsewhere. The construction is specified in the apogee-vm repository's
`docs/spec/precompiles.md`, “HashToPoint” in the section “The Falcon-512 lattice check”.

## API

```js
export const PUBLIC_KEY_BYTES = 897, SECRET_KEY_BYTES = 1281, SIGNATURE_BYTES = 666, SALT_BYTES = 40;
generateKeyPair()                                 // { secretKey: Uint8Array(1281), publicKey: Uint8Array(897) }
sign(secretKey, message, context?)                // Uint8Array(666); throws on a malformed secret key or a long context
verify(publicKey, message, signature, context?)   // boolean; never throws, malformed input is false
hashToPoint(publicKey, salt, message, context?)   // Uint16Array(512), each coefficient below q = 12289
keyDigest(publicKey)                              // Uint8Array(64): K, eight lanes below p = 2^64 − 59 (any bytes)
address(publicKey)                                // Uint8Array(32): K's first 32 bytes
formatAddress(address)                            // string: "0x", 64 hex digits, 8 of checksum
parseAddress(text)                                // Uint8Array(32); throws unless text is an address
publicKeyFromSecretKey(secretKey)                 // Uint8Array(897)
```

Messages, keys, contexts and signatures are `Uint8Array`s; encode strings with `TextEncoder`.

**The context** is the application's context string, FIPS 204's and 206's convention: 0 to 255
bytes, empty by default. A signature verifies only under the context it was made under, so a key
that signs for several purposes keeps a signature for one from passing as another's. `sign` throws
on a longer context; `verify` returns false.

**The address** names an account: the first 32 bytes of K, the key digest, a sponge over the domain
`apogee/key/v1`, the scheme `falcon512-poseidon2/v1` and the 897-byte public key. Its text is `0x`,
the address in 64 lowercase hex digits, then 8 hex digits of a checksum (a sponge over the address),
74 characters. `parseAddress` reads hex digits of either case after exactly `0x`, and refuses any
other text or a checksum that does not match, so a mistyped address is caught.

## Node

```js
import { generateKeyPair, sign, verify, address, formatAddress } from 'apogee-falcon512';

const { secretKey, publicKey } = generateKeyPair();
const context = new TextEncoder().encode('example/payments/v1');
const message = new TextEncoder().encode('pay 10 to bob');
const signature = sign(secretKey, message, context);
console.log(verify(publicKey, message, signature, context)); // true
console.log(verify(publicKey, message, signature)); // false: signed under another context
console.log(formatAddress(address(publicKey))); // 0x… (74 characters)
```

## Browser

```html
<script type="module">
  import { generateKeyPair, sign, verify } from './falcon512.js';

  const { secretKey, publicKey } = generateKeyPair();
  const message = new TextEncoder().encode('pay 10 to bob');
  console.log(verify(publicKey, message, sign(secretKey, message))); // true
</script>
```

## Caveat

Signing (and key generation) uses floating point and is not constant time, so its timing can depend
on the secret key. A secret key belongs on its owner's device; do not sign with it where others can
time the signer. Verification uses only public data.

## Tests

`npm test` (`node --test`): the Poseidon2 known answer, round trips and tampering, and HashToPoint,
key digest and address properties; `test/vectors.test.js` reads the vectors shared with the Rust and
Python implementations, `../vectors.json`, the official Falcon-512 KAT among them (through the verify
core, with standard HashToPoint computed by the test).
