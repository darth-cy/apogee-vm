# apogee-falcon512

Falcon-512 with Poseidon2's HashToPoint, in pure Python (standard library only, Python 3.9+).

This is Falcon-512 v1.2 (q = 12289, n = 512; its key, salt and signature encodings, key generation,
sampler and acceptance rule) with one change: HashToPoint maps (public key, salt, message) to the point
with a Poseidon2-A64-C5 sponge instead of SHAKE256(salt ‖ message). It is therefore **not interoperable
with standard Falcon-512**: a standard signature does not verify here, nor the reverse. The
construction is specified in the apogee-vm repository's `docs/spec/precompiles.md`, “HashToPoint” in the section
“The Falcon-512 lattice check”.

Install from this directory with `pip install .`; there are no dependencies.

## API

```python
PUBLIC_KEY_BYTES = 897; SECRET_KEY_BYTES = 1281; SIGNATURE_BYTES = 666; SALT_BYTES = 40

generate_keypair() -> tuple[bytes, bytes]                 # (secret_key, public_key)
sign(secret_key, message) -> bytes                        # 666 bytes; ValueError on a malformed secret key
verify(public_key, message, signature) -> bool            # never raises on malformed input
hash_to_point(public_key, salt, message) -> list[int]     # 512 coefficients in [0, 12289)
public_key_digest(public_key) -> list[int]                # 8 lanes in [0, 2^64 - 59), any bytes
public_key_from_secret_key(secret_key) -> bytes           # 897 bytes
```

Byte arguments accept any bytes-like object (`bytes`, `bytearray`, `memoryview`).

## Usage

```python
import apogee_falcon512 as falcon

secret_key, public_key = falcon.generate_keypair()
signature = falcon.sign(secret_key, b"pay 10 to alice")
assert falcon.verify(public_key, b"pay 10 to alice", signature)
assert not falcon.verify(public_key, b"pay 99 to alice", signature)
```

## Django

The package has no Django dependency. A view that verifies a signed request body against a stored
public key (here a `BinaryField`; `verify` accepts the `memoryview` some database backends return):

```python
import base64

from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

import apogee_falcon512 as falcon

from .models import Account  # public_key = models.BinaryField(max_length=897)


@csrf_exempt
@require_POST
def submit(request, account_id):
    account = get_object_or_404(Account, pk=account_id)
    try:
        signature = base64.b64decode(request.headers["X-Signature"], validate=True)
    except (KeyError, ValueError):
        return HttpResponseForbidden("missing or malformed signature")
    if not falcon.verify(account.public_key, request.body, signature):
        return HttpResponseForbidden("bad signature")
    return JsonResponse({"accepted": True})
```

A signature covers exactly the bytes signed: put a nonce or timestamp in the body if a replayed
request must be refused.

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
