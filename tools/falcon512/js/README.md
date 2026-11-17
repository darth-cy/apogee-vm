# apogee-falcon512

Falcon-512 with Poseidon2's HashToPoint, as one zero-dependency ES module for Node.js (≥ 20) and
browsers.

This is Falcon-512 v1.2 (the NIST round-3 specification) with one change: HashToPoint maps (public
key, salt, message) to the point c with a Poseidon2-A64-C5 sponge instead of SHAKE256(salt ‖
message). Keys, signatures, encodings, the sampler and the acceptance rule are v1.2's. Because
HashToPoint differs, it is **not interoperable with standard Falcon-512**: a standard signature
does not verify here, and a signature made here does not verify elsewhere. The construction is
specified in the apogee-vm repository's `docs/spec/precompiles.md`, “HashToPoint” in the section “The Falcon-512
lattice check”.

## API

```js
export const PUBLIC_KEY_BYTES = 897, SECRET_KEY_BYTES = 1281, SIGNATURE_BYTES = 666, SALT_BYTES = 40;
generateKeyPair()                       // { secretKey: Uint8Array(1281), publicKey: Uint8Array(897) }
sign(secretKey, message)                // Uint8Array(666); throws on a malformed secret key
verify(publicKey, message, signature)   // boolean; never throws, malformed input is false
hashToPoint(publicKey, salt, message)   // Uint16Array(512), each coefficient below q = 12289
publicKeyDigest(publicKey)              // bigint[8], each below p = 2^64 − 59 (KeyDigest; any bytes)
publicKeyFromSecretKey(secretKey)       // Uint8Array(897)
```

Messages, keys and signatures are `Uint8Array`s; encode strings with `TextEncoder`.

## Node

```js
import { generateKeyPair, sign, verify } from 'apogee-falcon512';

const { secretKey, publicKey } = generateKeyPair();
const message = new TextEncoder().encode('pay 10 to bob');
const signature = sign(secretKey, message);
console.log(verify(publicKey, message, signature)); // true
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

`npm test` (`node --test`): the Poseidon2 known answer, round trips and tampering, and
HashToPoint/KeyDigest properties; `test/vectors.test.js` reads the vectors shared with the Rust and
Python implementations, `../vectors.json`, the official Falcon-512 KAT among them (through the verify
core, with standard HashToPoint computed by the test).
