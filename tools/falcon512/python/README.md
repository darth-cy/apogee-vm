# apogee-falcon512

Falcon-512 with Poseidon2's HashToPoint, in pure Python (standard library only, Python 3.9+).

This is Falcon-512 v1.2 (q = 12289, n = 512; its key, salt and signature encodings, key generation,
sampler and acceptance rule) with one change: HashToPoint maps the key digest K, the salt, the
application's context and the message to the point with a Poseidon2-A64-C5 sponge instead of
SHAKE256(salt ‖ message). It is therefore **not interoperable with standard Falcon-512**: a standard
signature does not verify here, nor the reverse. The construction is specified in the apogee-vm
repository's `docs/spec/precompiles.md`, “HashToPoint” in the section “The Falcon-512 lattice check”.

Install from this directory with `pip install .`; there are no dependencies.

## API

```python
PUBLIC_KEY_BYTES = 897; SECRET_KEY_BYTES = 1281; SIGNATURE_BYTES = 666; SALT_BYTES = 40

generate_keypair() -> tuple[bytes, bytes]                       # (secret_key, public_key)
sign(secret_key, message, context=b"") -> bytes                 # 666 bytes; ValueError on a malformed
                                                                #   secret key or a context over 255 bytes
verify(public_key, message, signature, context=b"") -> bool     # never raises on malformed input
hash_to_point(public_key, salt, message, context=b"") -> list[int]  # 512 coefficients in [0, 12289)
key_digest(public_key) -> bytes                                 # K: 64 bytes, 8 lanes below 2^64 - 59
address(public_key) -> bytes                                    # 32 bytes: K's first 32
format_address(address) -> str                                  # "0x", 64 hex digits, 8 of checksum
parse_address(text) -> bytes                                    # 32 bytes; ValueError unless an address
public_key_from_secret_key(secret_key) -> bytes                 # 897 bytes
```

Byte arguments accept any bytes-like object (`bytes`, `bytearray`, `memoryview`).

**The context** is the application's context string, FIPS 204's and 206's convention: 0 to 255
bytes, empty by default. A signature verifies only under the context it was made under, so a key
that signs for several purposes keeps a signature for one from passing as another's. `sign` raises
`ValueError` on a longer context; `verify` returns `False`.

**The address** names an account: the first 32 bytes of K, the key digest, a sponge over the domain
`apogee/key/v1`, the scheme `falcon512-poseidon2/v1` and the 897-byte public key (K is defined for
any bytes). Its text is `0x`, the address in 64 lowercase hex digits, then 8 hex digits of a checksum
(a sponge over the address), 74 characters. `parse_address` reads hex digits of either case after
exactly `0x`, and raises `ValueError` for any other text or a checksum that does not match, so a
mistyped address is caught. A verifier keeps the K of the last 256 keys it saw.

## Usage

```python
import apogee_falcon512 as falcon

secret_key, public_key = falcon.generate_keypair()
signature = falcon.sign(secret_key, b"pay 10 to alice", b"example/payments/v1")
assert falcon.verify(public_key, b"pay 10 to alice", signature, b"example/payments/v1")
assert not falcon.verify(public_key, b"pay 99 to alice", signature, b"example/payments/v1")
assert not falcon.verify(public_key, b"pay 10 to alice", signature)  # signed under another context
print(falcon.format_address(falcon.address(public_key)))  # 0x... (74 characters)
```

## Django

The package has no Django dependency. A view that verifies a signed request body against a stored
public key (here a `BinaryField`; `verify` accepts the `memoryview` some database backends return),
under the context the client signs it with:

```python
import base64

from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

import apogee_falcon512 as falcon

from .models import Account  # public_key = models.BinaryField(max_length=897)

CONTEXT = b"example.com/submit/v1"  # the client signs under the same context


@csrf_exempt
@require_POST
def submit(request, account_id):
    account = get_object_or_404(Account, pk=account_id)
    try:
        signature = base64.b64decode(request.headers["X-Signature"], validate=True)
    except (KeyError, ValueError):
        return HttpResponseForbidden("missing or malformed signature")
    if not falcon.verify(account.public_key, request.body, signature, CONTEXT):
        return HttpResponseForbidden("bad signature")
    return JsonResponse({"accepted": True})
```

A signature covers exactly the bytes signed and its context: put a nonce or timestamp in the body
if a replayed request must be refused. An account's address, `falcon.address(public_key)`, can key
the table; `falcon.parse_address` reads it from a URL or a form.

## Caveat

Signing uses floating point and is not constant time. A secret key belongs on its owner's device; a
server should only verify.

## Tests

```
python3 -m unittest discover -s tests
```

`tests/test_vectors.py` reads the vectors shared with the Rust and JS implementations,
`../vectors.json`, the official Falcon-512 KAT among them (through the verification core, with
standard HashToPoint computed by the test).
