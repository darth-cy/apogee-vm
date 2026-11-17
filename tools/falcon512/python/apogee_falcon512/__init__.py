"""Falcon-512 with Poseidon2's HashToPoint, in pure Python (standard library only).

Falcon-512 v1.2 (q = 12289, n = 512: its encodings, key generation, sampler and acceptance rule) with
one change: HashToPoint(public key, salt, message) is a Poseidon2-A64-C5 sponge instead of
SHAKE256(salt || message), so standard Falcon-512 signatures do not verify here, nor the reverse. The
construction is specified in the apogee-vm repository's docs/spec/precompiles.md, "HashToPoint" in the section
"The Falcon-512 lattice check".

Signing uses floating point and is not constant time: a secret key belongs on its owner's device.
"""

import bisect
import cmath
import functools
import math
import os

from ._constants import APPROX_EXP_C, INTERNAL_DIAG_M_1, RC_INITIAL, RC_PARTIAL, RC_TERMINAL, RCDT

__all__ = [
    "PUBLIC_KEY_BYTES", "SECRET_KEY_BYTES", "SIGNATURE_BYTES", "SALT_BYTES", "generate_keypair",
    "sign", "verify", "hash_to_point", "public_key_digest", "public_key_from_secret_key",
]
__version__ = "0.1.0"

PUBLIC_KEY_BYTES = 897
SECRET_KEY_BYTES = 1281
SIGNATURE_BYTES = 666
SALT_BYTES = 40

_N = 512
_Q = 12289
_PK_HEADER, _SK_HEADER, _SIG_HEADER = 0x09, 0x59, 0x39
_SIG_BITS = 8 * (SIGNATURE_BYTES - 1 - SALT_BYTES)  # 5000 bits of compressed s2
_BETA2 = 34034726                                   # floor(beta^2)
_SIGMA = 165.7366171829776
_SIGMA_MIN = 1.2778336969128337
_SIGMA_MAX = 1.8205
_SIGMA_FG = 1.43300980528773   # 8 samples of D_{Z, this} sum to D_{Z, 1.17 sqrt(q / 2n)} (v1.2 (3.29))
_GAMMA2 = 1.17 ** 2 * _Q       # NTRUGen's bound on the squared Gram-Schmidt norm
_SIGN_ATTEMPTS = 100           # a valid key fails one attempt with probability ~1e-6

# ---------------------------------------------------------------------------------------------------
# Poseidon2-A64-C5: width 16, x^3, 6 full + 42 partial + 6 full rounds over p = 2^64 - 59.
# ---------------------------------------------------------------------------------------------------

_P = 2 ** 64 - 59


def _external(s):
    """M_E = circ(2 M4, M4, M4, M4): block b becomes M4 s_b + sum_j M4 s_j."""
    ys = []
    for i in (0, 4, 8, 12):
        a, b, c, d = s[i:i + 4]
        t0, t1 = a + b, c + d
        t2, t3 = b + b + t1, d + d + t0
        t4, t5 = 4 * t1 + t3, 4 * t0 + t2
        ys.append((t3 + t5, t5, t2 + t4, t4))  # M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]
    tot = [sum(col) for col in zip(*ys)]
    return [(y + t) % _P for blk in ys for y, t in zip(blk, tot)]


def _permute(s):
    """The Poseidon2-A64-C5 permutation of 16 lanes in [0, p), as a new list."""
    s = _external(s)
    for rc in RC_INITIAL:
        s = _external([(x + c) ** 3 % _P for x, c in zip(s, rc)])
    for c in RC_PARTIAL:
        s[0] = (s[0] + c) ** 3 % _P
        t = sum(s)
        s = [(d * x + t) % _P for d, x in zip(INTERNAL_DIAG_M_1, s)]  # M_I = J + diag(mu - 1)
    for rc in RC_TERMINAL:
        s = _external([(x + c) ** 3 % _P for x, c in zip(s, rc)])
    return s


# ---------------------------------------------------------------------------------------------------
# The sponge: overwrite duplex, rate 8 (lanes 0..8), capacity 8, zero start, lazy permutation.
# ---------------------------------------------------------------------------------------------------

_CONTEXT = b"apogee/falcon512/hash-to-point/v1"
_T = 808 * _Q ** 4  # floor(p / q^4) q^4: lanes at or above it are rejected


def _bytes(x):
    """Any bytes-like object as bytes; TypeError for anything else."""
    return x if type(x) is bytes else memoryview(x).tobytes()


def _field(tag, data):
    """A message's lanes: its tag, its length in bytes, then its 7-byte little-endian chunks."""
    return [tag, len(data)] + [int.from_bytes(data[i:i + 7], "little") for i in range(0, len(data), 7)]


def _absorb(state, pos, lanes):
    """Overwrite the next rate lane for each of `lanes`, permuting first when the rate is full."""
    state = list(state)
    for x in lanes:
        if pos == 8:
            state, pos = _permute(state), 0
        state[pos] = x
        pos += 1
    return state, pos


def _prefix(pk):
    """(state, pos) after field(CONTEXT) and field(PUBLIC_KEY): 17 permutations for a 897-byte key."""
    state, pos = _absorb([0] * 16, 0, _field(1, _CONTEXT) + _field(2, pk))
    return tuple(state), pos


_cached_prefix = functools.lru_cache(maxsize=256)(_prefix)  # a verifier absorbs each key once


def _key_state(pk):
    return _cached_prefix(pk) if len(pk) == PUBLIC_KEY_BYTES else _prefix(pk)


def hash_to_point(public_key: bytes, salt: bytes, message: bytes) -> list[int]:
    """HashToPoint: c in [0, q)^512 from the sponge over (public key, salt, message)."""
    state, pos = _key_state(_bytes(public_key))
    state, _ = _absorb(state, pos, _field(3, _bytes(salt)) + _field(4, _bytes(message)))
    c = []
    while len(c) < _N:
        state = _permute(state)
        for x in state[:8]:
            if x < _T and len(c) < _N:
                for _ in range(4):  # base-q digits, least significant first
                    x, d = divmod(x, _Q)
                    c.append(d)
    return c


def public_key_digest(public_key: bytes) -> list[int]:
    """KeyDigest: 8 lanes in [0, p) fingerprinting any byte string (it need not decode as a key)."""
    state, pos = _key_state(_bytes(public_key))
    state, _ = _absorb(state, pos, [5, 0])  # an empty KEY_DIGEST frame
    return _permute(state)[:8]


# ---------------------------------------------------------------------------------------------------
# Polynomials in Z[x]/(x^n + 1): exact products by Kronecker substitution, and the float FFT.
# ---------------------------------------------------------------------------------------------------

def _kmul(a, b):
    """a * b in Z[x]/(x^n + 1), packing each operand into one integer and multiplying once."""
    n = len(a)
    ma, mb = max(map(abs, a)), max(map(abs, b))
    if not ma or not mb:
        return [0] * n
    w = (n * ma * mb).bit_length() // 8 + 1  # bytes per slot: every product coefficient < 2^(8w - 1)
    ones = int.from_bytes((b"\x01" + bytes(w - 1)) * n, "little")

    def pack(v, m):  # shift coefficients to [0, 2m], pack, shift back
        return int.from_bytes(b"".join((x + m).to_bytes(w, "little") for x in v), "little") - m * ones

    z = pack(a, ma) * pack(b, mb) + int.from_bytes((bytes(w - 1) + b"\x80") * (2 * n), "little")
    raw, half = z.to_bytes(2 * n * w, "little"), 1 << (8 * w - 1)
    c = [int.from_bytes(raw[i:i + w], "little") - half for i in range(0, 2 * n * w, w)]
    return [x - y for x, y in zip(c[:n], c[n:])]  # x^n = -1


def _conj(f):
    """f(-x)."""
    return [-x if i & 1 else x for i, x in enumerate(f)]


def _lift(f):
    """f(x^2), twice the degree."""
    out = [0] * (2 * len(f))
    out[0::2] = f
    return out


def _norm(f):
    """The field norm N(f), defined by N(f)(x^2) = f(x) f(-x)."""
    return _kmul(f, _conj(f))[0::2]


def _inv_mod_q(f):
    """1/f in Z_q[x]/(x^n + 1) as f(-x) / N(f)(x^2), or None when f is not invertible mod q."""
    if len(f) == 1:
        return [pow(f[0], -1, _Q)] if f[0] % _Q else None
    r = _inv_mod_q([x % _Q for x in _norm(f)])
    return None if r is None else [x % _Q for x in _kmul(_conj(f), _lift(r))]


def _root_exponents():
    """e[m]: the roots exp(i pi e / 512) of x^m + 1 in FFT order, (r_0..r_{m/2-1}, -r_0..-r_{m/2-1})
    with r_i^2 the i-th root of x^(m/2) + 1, so that FFT(f) = (f0 + r f1, f0 - r f1) for
    f(x) = f0(x^2) + x f1(x^2)."""
    e = {1: [512]}
    m = 1
    while m < _N:
        half = [x // 2 for x in e[m]]
        m *= 2
        e[m] = half + [x + 512 for x in half]
    return e


_W = {m: [cmath.exp(1j * math.pi * x / 512) for x in e[:m // 2]]
      for m, e in _root_exponents().items() if m > 1}
_WI = {m: [w.conjugate() / 2 for w in ws] for m, ws in _W.items()}


def _merge(a, b):
    """FFT(f) from FFT(f0), FFT(f1) (Algorithm 2, mergefft)."""
    t = [x * w for x, w in zip(b, _W[2 * len(a)])]
    return [x + y for x, y in zip(a, t)] + [x - y for x, y in zip(a, t)]


def _split(f):
    """(FFT(f0), FFT(f1)) from FFT(f) (Algorithm 1, splitfft)."""
    h = len(f) // 2
    a, b = f[:h], f[h:]
    return [(x + y) * 0.5 for x, y in zip(a, b)], [(x - y) * w for x, y, w in zip(a, b, _WI[len(f)])]


def _fft(f):
    return [complex(f[0])] if len(f) == 1 else _merge(_fft(f[0::2]), _fft(f[1::2]))


def _ifft(f):
    if len(f) == 1:
        return [f[0].real]
    a, b = _split(f)
    out = [0.0] * len(f)
    out[0::2], out[1::2] = _ifft(a), _ifft(b)
    return out


# ---------------------------------------------------------------------------------------------------
# Encodings: public key 897 B, secret key 1281 B, padded signature 666 B (Falcon v1.2 section 3.11).
# ---------------------------------------------------------------------------------------------------

def _pack(vals, bits):
    """Values in [0, 2^bits), concatenated most significant bit first."""
    s = "".join(format(v, "0%db" % bits) for v in vals)
    return int(s, 2).to_bytes(len(s) // 8, "big")


def _unpack(data, bits):
    s = format(int.from_bytes(data, "big"), "0%db" % (8 * len(data)))
    return [int(s[i:i + bits], 2) for i in range(0, len(s), bits)]


def _unpack_signed(data, bits):
    """Two's complement values; the minimum -2^(bits-1) is not an encoding."""
    top = 1 << (bits - 1)
    vals = _unpack(data, bits)
    if top in vals:
        raise ValueError("malformed secret key")
    return [v - 2 * top if v > top else v for v in vals]


def _encode_pk(h):
    return bytes([_PK_HEADER]) + _pack(h, 14)


def _decode_pk(pk):
    """h, or ValueError unless pk is exactly 0x09 and 512 coefficients below q, 14 bits each."""
    if len(pk) != PUBLIC_KEY_BYTES or pk[0] != _PK_HEADER:
        raise ValueError("malformed public key")
    h = _unpack(pk[1:], 14)
    if max(h) >= _Q:
        raise ValueError("malformed public key")
    return h


def _compress(s2):
    """Algorithm 17 into 625 bytes, or None when a coefficient exceeds 2047 or the bits overflow."""
    if max(map(abs, s2)) > 2047:
        return None
    bits = "".join(("1" if v < 0 else "0") + format(abs(v) & 127, "07b") + "0" * (abs(v) >> 7) + "1"
                   for v in s2)
    if len(bits) > _SIG_BITS:
        return None
    return int(bits.ljust(_SIG_BITS, "0"), 2).to_bytes(_SIG_BITS // 8, "big")


def _decode_sig(sig):
    """(salt, s2), or ValueError unless sig is exactly 0x39 || salt || compressed s2 || zero bits."""
    if len(sig) != SIGNATURE_BYTES or sig[0] != _SIG_HEADER:
        raise ValueError("malformed signature")
    bits = format(int.from_bytes(sig[1 + SALT_BYTES:], "big"), "0%db" % _SIG_BITS)
    s2, i = [], 0
    for _ in range(_N):
        if i + 8 > _SIG_BITS:
            raise ValueError("malformed signature")
        j = bits.find("1", i + 8, min(i + 24, _SIG_BITS))  # the high bits: at most 15 zeros, then a 1
        if j < 0:  # |s| > 2047, or past the end
            raise ValueError("malformed signature")
        v = int(bits[i + 1:i + 8], 2) + ((j - i - 8) << 7)
        if bits[i] == "1" and v == 0:  # -0
            raise ValueError("malformed signature")
        s2.append(-v if bits[i] == "1" else v)
        i = j + 1
    if "1" in bits[i:]:  # the rest of the last byte and the padding are zero
        raise ValueError("malformed signature")
    return sig[1:1 + SALT_BYTES], s2


def _expand(secret_key):
    """(f, g, F, G, h) of an encoded secret key, G = gF/f mod q centered, h = g/f mod q; ValueError
    unless the encoding is exact, f is invertible mod q and fG - gF = q."""
    sk = _bytes(secret_key)
    if len(sk) != SECRET_KEY_BYTES or sk[0] != _SK_HEADER:
        raise ValueError("malformed secret key")
    f, g, F = _unpack_signed(sk[1:385], 6), _unpack_signed(sk[385:769], 6), _unpack_signed(sk[769:], 8)
    fi = _inv_mod_q(f)
    if fi is None:
        raise ValueError("malformed secret key: f is not invertible mod q")
    h = [x % _Q for x in _kmul(g, fi)]
    G = [(x + _Q // 2) % _Q - _Q // 2 for x in _kmul(h, F)]
    if [x - y for x, y in zip(_kmul(f, G), _kmul(g, F))] != [_Q] + [0] * (_N - 1):
        raise ValueError("malformed secret key: f G - g F != q")
    return f, g, F, G, h


def public_key_from_secret_key(secret_key: bytes) -> bytes:
    """The 897-byte public key of a secret key; ValueError when the secret key is malformed."""
    return _encode_pk(_expand(secret_key)[4])


# ---------------------------------------------------------------------------------------------------
# Verification.
# ---------------------------------------------------------------------------------------------------

def _accepts(h, s2, c):
    """s1 = c - s2 h mod (q, x^n + 1) centered; accept iff ||s1||^2 + ||s2||^2 <= floor(beta^2)."""
    s1 = [(x - y) % _Q for x, y in zip(c, _kmul(s2, h))]
    return sum((x - _Q if x > _Q // 2 else x) ** 2 for x in s1) + sum(x * x for x in s2) <= _BETA2


def _verify_with_point(public_key, c, signature):
    """Verify against a given c (any HashToPoint); False for malformed input."""
    try:
        h, (_, s2) = _decode_pk(_bytes(public_key)), _decode_sig(_bytes(signature))
    except (TypeError, ValueError):
        return False
    return _accepts(h, s2, c)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff signature is a valid signature of message under public_key; never raises."""
    try:
        pk, msg = _bytes(public_key), _bytes(message)
        h, (salt, s2) = _decode_pk(pk), _decode_sig(_bytes(signature))
    except (TypeError, ValueError):
        return False
    return _accepts(h, s2, hash_to_point(pk, salt, msg))


# ---------------------------------------------------------------------------------------------------
# The sampler (Falcon v1.2 section 3.9.3): BaseSampler, ApproxExp, BerExp, SamplerZ.
# ---------------------------------------------------------------------------------------------------

class _Rng:
    """os.urandom, fetched 4 KiB at a time."""

    def __init__(self):
        self.buf, self.pos = b"", 0

    def take(self, k):
        if self.pos + k > len(self.buf):
            self.buf, self.pos = self.buf[self.pos:] + os.urandom(4096), 0
        self.pos += k
        return self.buf[self.pos - k:self.pos]


_RCDT_ASCENDING = sorted(RCDT)
_LN2 = math.log(2)
_INV_2SIGMA_MAX2 = 1 / (2 * _SIGMA_MAX ** 2)


def _approx_exp(x, ccs):
    """Algorithm 13: about 2^63 ccs exp(-x), for x in [0, ln 2] and ccs in [0, 1]."""
    z, y = int(x * 2 ** 63), APPROX_EXP_C[0]
    for c in APPROX_EXP_C[1:]:
        y = c - (z * y >> 63)
    return int(ccs * 2 ** 63) * y >> 63


def _ber_exp(x, ccs, rng):
    """Algorithm 14: True with probability about ccs exp(-x)."""
    s = int(x / _LN2)
    z = (2 * _approx_exp(x - s * _LN2, ccs) - 1) >> min(s, 63)
    for i in range(56, -8, -8):
        w = rng.take(1)[0] - ((z >> i) & 0xFF)
        if w:
            return w < 0
    return False


def _sampler_z(mu, sigma, rng):
    """Algorithm 15: z from D_{Z, sigma, mu}, for sigma in [sigma_min, sigma_max]."""
    s = math.floor(mu)
    r, dss, ccs = mu - s, 1 / (2 * sigma * sigma), _SIGMA_MIN / sigma
    while True:
        u = rng.take(10)  # 72 bits for BaseSampler (Algorithm 12), then one byte for the sign
        z0 = len(RCDT) - bisect.bisect_right(_RCDT_ASCENDING, int.from_bytes(u[:9], "big"))
        b = u[9] & 1
        z = b + (2 * b - 1) * z0
        if _ber_exp((z - r) ** 2 * dss - z0 * z0 * _INV_2SIGMA_MAX2, ccs, rng):
            return z + s


# ---------------------------------------------------------------------------------------------------
# Signing: the ffLDL tree, ffSampling and Algorithm 10.
# ---------------------------------------------------------------------------------------------------

def _ffldl(g00, g01, g11):
    """Algorithm 9 on the self-adjoint [[g00, g01], [g01*, g11]] (FFT form), leaves normalized to
    sigma / sqrt(leaf): a node is (L10, left, right), a leaf a float."""
    l10 = [b.conjugate() / a for a, b in zip(g00, g01)]
    d11 = [c - b * b.conjugate() / a for a, b, c in zip(g00, g01, g11)]
    if len(g00) == 2:
        return l10, _SIGMA / math.sqrt(g00[0].real), _SIGMA / math.sqrt(d11[0].real)
    a, b = _split(g00)
    c, d = _split(d11)
    return l10, _ffldl(a, b, a), _ffldl(c, d, c)


def _ffsampling(t0, t1, tree, rng):
    """Algorithm 11: integer z0, z1 (FFT form) near t0, t1."""
    if len(t0) == 1:
        return [_sampler_z(t0[0].real, tree, rng)], [_sampler_z(t1[0].real, tree, rng)]
    l10, left, right = tree
    z1 = _merge(*_ffsampling(*_split(t1), right, rng))
    t0 = [a + (b - c) * l for a, b, c, l in zip(t0, t1, z1, l10)]
    return _merge(*_ffsampling(*_split(t0), left, rng)), z1


def sign(secret_key: bytes, message: bytes) -> bytes:
    """A 666-byte signature of message; ValueError when the secret key is malformed."""
    f, g, F, G, h = _expand(secret_key)
    msg = _bytes(message)
    fa, ga, Fa, Ga = _fft(f), _fft(g), _fft(F), _fft(G)  # B = [[g, -f], [G, -F]]
    tree = _ffldl([x * x.conjugate() + y * y.conjugate() for x, y in zip(ga, fa)],
                  [x * u.conjugate() + y * v.conjugate() for x, y, u, v in zip(ga, fa, Ga, Fa)],
                  [u * u.conjugate() + v * v.conjugate() for u, v in zip(Ga, Fa)])
    salt = os.urandom(SALT_BYTES)
    c = hash_to_point(_encode_pk(h), salt, msg)
    ca = _fft(c)
    t0, t1 = [-x * y / _Q for x, y in zip(ca, Fa)], [x * y / _Q for x, y in zip(ca, fa)]
    rng = _Rng()
    for _ in range(_SIGN_ATTEMPTS):
        z0, z1 = _ffsampling(t0, t1, tree, rng)  # s = (c, 0) - z B
        v0 = _ifft([a * x + b * y for a, b, x, y in zip(z0, z1, ga, Ga)])  # z0 g + z1 G
        v1 = _ifft([a * x + b * y for a, b, x, y in zip(z0, z1, fa, Fa)])  # z0 f + z1 F
        s1, s2 = [x - round(y) for x, y in zip(c, v0)], [round(y) for y in v1]
        if sum(x * x for x in s1) + sum(x * x for x in s2) <= _BETA2:
            enc = _compress(s2)
            if enc is not None:
                return bytes([_SIG_HEADER]) + salt + enc
    raise ValueError("malformed secret key: no short signature found")


# ---------------------------------------------------------------------------------------------------
# Key generation: NTRUGen (Algorithm 5) with NTRUSolve (Algorithm 6) and Reduce (Algorithm 7).
# ---------------------------------------------------------------------------------------------------

def _bitsize(v):
    return max(map(abs, v)).bit_length()


def _reduce(f, g, F, G):
    """Algorithm 7 on the 53 leading bits of each polynomial: each round subtracts k (f, g) 2^shift
    with k the rounded quotient kept to 25 bits beyond 2^shift, until k = 0 at shift 0."""
    size = max(53, _bitsize(f), _bitsize(g))
    fa, ga = _fft([x >> (size - 53) for x in f]), _fft([x >> (size - 53) for x in g])
    den = [x.real ** 2 + x.imag ** 2 + y.real ** 2 + y.imag ** 2 for x, y in zip(fa, ga)]
    while True:
        big = max(53, _bitsize(F), _bitsize(G))
        if big < size:
            return F, G
        Fa, Ga = _fft([x >> (big - 53) for x in F]), _fft([x >> (big - 53) for x in G])
        shift = max(big - size - 25, 0)  # the quotient is about 2^(big - size) times this one
        scale = 2.0 ** (big - size - shift)
        k = [round(x * scale) for x in _ifft([(X * x.conjugate() + Y * y.conjugate()) / d
                                              for X, Y, x, y, d in zip(Fa, Ga, fa, ga, den)])]
        if not any(k):
            return F, G
        fk, gk = _kmul(f, k), _kmul(g, k)
        F = [x - (y << shift) for x, y in zip(F, fk)]
        G = [x - (y << shift) for x, y in zip(G, gk)]


def _ntru_solve(f, g):
    """(F, G) with f G - g F = q over Z[x]/(x^n + 1), reduced against (f, g), or None."""
    if len(f) == 1:
        try:
            u = pow(f[0], -1, g[0])  # u f + v g = 1
        except ValueError:
            return None
        v = (1 - u * f[0]) // g[0]
        return [-_Q * v], [_Q * u]
    sol = _ntru_solve(_norm(f), _norm(g))
    if sol is None:
        return None
    return _reduce(f, g, _kmul(_lift(sol[0]), _conj(g)), _kmul(_lift(sol[1]), _conj(f)))


def generate_keypair() -> tuple[bytes, bytes]:
    """(secret_key, public_key): 1281 and 897 bytes."""
    rng = _Rng()
    while True:
        f, g = ([sum(_sampler_z(0, _SIGMA_FG, rng) for _ in range(8)) for _ in range(_N)]
                for _ in range(2))
        if max(map(abs, f + g)) > 31:  # 6 bits each in the secret key, -32 excluded
            continue
        fa, ga = _fft(f), _fft(g)
        dual = _Q * _Q / _N * sum(1 / (x.real ** 2 + x.imag ** 2 + y.real ** 2 + y.imag ** 2)
                                  for x, y in zip(fa, ga))
        if sum(x * x for x in f + g) > _GAMMA2 or dual > _GAMMA2:  # ||B||_GS <= 1.17 sqrt(q)
            continue
        sol = _ntru_solve(f, g)
        if sol is None or max(map(abs, sol[0])) > 127:  # F: 8 bits each, -128 excluded
            continue
        sk = bytes([_SK_HEADER]) + b"".join(_pack([x & m for x in v], m.bit_length())
                                            for v, m in ((f, 63), (g, 63), (sol[0], 255)))
        try:
            return sk, public_key_from_secret_key(sk)  # ValueError: f is not invertible mod q
        except ValueError:
            continue
