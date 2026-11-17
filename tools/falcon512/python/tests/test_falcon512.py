"""apogee_falcon512 against independent answers: the Poseidon2 generator's known answer and round trips.
The shared vectors, the official Falcon-512 KAT among them, are test_vectors.py's."""

import os
import unittest

import apogee_falcon512 as falcon
from apogee_falcon512 import PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SIGNATURE_BYTES, SALT_BYTES

Q = 12289
P = 2 ** 64 - 59

# Poseidon2-A64-C5 at [0, 1, ..., 15], printed by HorizenLabs' generator (GENERATOR_KAT in the
# apogee-vm repository's crates/transcript/tests/permutation.rs).
GENERATOR_KAT = [
    0x59bb4dfebd9c36af, 0x04ef6d6db08fe0c3, 0x58712eed1ea7dab3, 0x6fdcdfd2cac82706,
    0xc28b6eb60e8cc108, 0x2dceea61d9b39cdc, 0x38a3f5e89590b70b, 0x8eaf1d087cb5fd81,
    0x461e234d53d95651, 0x3b06fe7980170f39, 0x3f92a9c75ed65822, 0x652f6a10605b537d,
    0x11f277067885fa72, 0x744edcd6a289fcb0, 0xde10fc99342e7e2b, 0x189b9d1e6db72de6,
]


def flip(data, bit):
    """data with one bit flipped, bit 0 being the most significant bit of byte 0."""
    out = bytearray(data)
    out[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(out)


class Poseidon2(unittest.TestCase):
    def test_generator_known_answer(self):
        self.assertEqual(falcon._permute(list(range(16))), GENERATOR_KAT)


class RoundTrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sk, cls.pk = falcon.generate_keypair()
        cls.msg, cls.ctx = bytes(range(92)), b"a context"
        cls.sig = falcon.sign(cls.sk, cls.msg, cls.ctx)

    def test_sizes_and_public_key(self):
        self.assertEqual((len(self.sk), len(self.pk)), (SECRET_KEY_BYTES, PUBLIC_KEY_BYTES))
        self.assertEqual(falcon.public_key_from_secret_key(self.sk), self.pk)

    def test_sign_and_verify(self):
        for n, ctx in ((0, b""), (92, os.urandom(255)), (200, b"a context")):
            msg = os.urandom(n)
            sig = falcon.sign(self.sk, msg, ctx)
            self.assertEqual(len(sig), SIGNATURE_BYTES)
            self.assertTrue(falcon.verify(self.pk, msg, sig, ctx))
            self.assertTrue(falcon.verify(bytearray(self.pk), memoryview(msg), bytearray(sig),
                                          bytearray(ctx)))

    def test_tampering_refuses(self):
        pk, msg, sig, ctx = self.pk, self.msg, self.sig, self.ctx
        self.assertTrue(falcon.verify(pk, msg, sig, ctx))
        self.assertFalse(falcon.verify(pk, flip(msg, 0), sig, ctx))
        self.assertFalse(falcon.verify(pk, msg + b"\x00", sig, ctx))
        self.assertFalse(falcon.verify(pk, msg, sig, flip(ctx, 8 * len(ctx) - 1)))  # context
        self.assertFalse(falcon.verify(pk, msg, sig))  # the context left out
        self.assertFalse(falcon.verify(pk, msg, flip(sig, 8 + 7), ctx))  # salt
        self.assertFalse(falcon.verify(pk, msg, flip(sig, 8 * (1 + SALT_BYTES) + 3), ctx))  # s2
        self.assertEqual(sig[-1], 0)
        self.assertFalse(falcon.verify(pk, msg, flip(sig, 8 * SIGNATURE_BYTES - 1), ctx))  # padding
        self.assertFalse(falcon.verify(pk, msg, flip(sig, 7), ctx))  # header 0x39 -> 0x38
        self.assertFalse(falcon.verify(pk, msg, sig[:-1], ctx))
        self.assertFalse(falcon.verify(pk, msg, sig + b"\x00", ctx))
        self.assertFalse(falcon.verify(flip(pk, 8 * 100), msg, sig, ctx))

    def test_key_coefficient_at_least_q_refuses(self):
        h = falcon._decode_pk(self.pk)
        i = next(i for i, x in enumerate(h) if x + Q < 2 ** 14)
        bad = falcon._encode_pk(h[:i] + [h[i] + Q] + h[i + 1:])  # the same h mod q, not canonical
        c = falcon.hash_to_point(self.pk, self.sig[1:41], self.msg, self.ctx)
        self.assertTrue(falcon._verify_with_point(self.pk, c, self.sig))
        self.assertFalse(falcon._verify_with_point(bad, c, self.sig))
        self.assertFalse(falcon.verify(bad, self.msg, self.sig, self.ctx))

    def test_two_signatures_differ(self):
        sign = lambda: falcon.sign(self.sk, self.msg, self.ctx)  # noqa: E731
        self.assertNotEqual(sign(), sign())

    def test_malformed_input(self):
        for args in ((self.pk, "text", self.sig), (None, self.msg, self.sig), (self.pk, self.msg, 666),
                     (self.pk[:-1], self.msg, self.sig), (b"", b"", b""),
                     (self.pk, self.msg, self.sig, "text")):
            self.assertFalse(falcon.verify(*args))
        self.assertRaises(ValueError, falcon.sign, self.sk, self.msg, bytes(256))  # over 255 bytes
        for sk in (self.sk[:-1], self.sk + b"\x00", flip(self.sk, 0), b"\x59" + bytes(1280),
                   self.sk[:1] + b"\x80" + self.sk[2:]):  # f[0] = -32, forbidden
            self.assertRaises(ValueError, falcon.sign, sk, self.msg)
        other_sk, _ = falcon.generate_keypair()
        mixed = self.sk[:769] + other_sk[769:]  # this key's f, g with another key's F
        self.assertRaises(ValueError, falcon.sign, mixed, self.msg)


class HashToPoint(unittest.TestCase):
    pk, salt = bytes(range(256)) * 3 + bytes(129), bytes(range(40))
    msg, ctx = b"a message to hash", b"ctx"

    def test_shape_and_determinism(self):
        c = falcon.hash_to_point(self.pk, self.salt, self.msg, self.ctx)
        self.assertEqual(len(c), 512)
        self.assertTrue(all(0 <= x < Q for x in c))
        self.assertEqual(c, falcon.hash_to_point(bytearray(self.pk), memoryview(self.salt), self.msg,
                                                 bytearray(self.ctx)))

    def test_any_flipped_bit_changes_it(self):
        c = falcon.hash_to_point(self.pk, self.salt, self.msg, self.ctx)
        for which in range(4):
            inputs = [self.pk, self.salt, self.msg, self.ctx]
            for bit in (0, 7, 8 * len(inputs[which]) // 2 + 3, 8 * len(inputs[which]) - 1):
                changed = list(inputs)
                changed[which] = flip(inputs[which], bit)
                self.assertNotEqual(falcon.hash_to_point(*changed), c, (which, bit))
        self.assertNotEqual(falcon.hash_to_point(self.pk, self.salt, self.msg + b"\x00", self.ctx), c)
        self.assertNotEqual(falcon.hash_to_point(self.pk, self.salt, self.msg, self.ctx + b"\x00"), c)
        self.assertNotEqual(falcon.hash_to_point(self.pk, self.salt, self.ctx, self.msg), c)  # swapped

    def test_key_digest_and_address(self):
        for data in (b"", self.pk, flip(self.pk, 0), b"\xff" * 2000):
            k = falcon.key_digest(data)
            self.assertEqual(len(k), 64)
            self.assertTrue(all(int.from_bytes(k[i:i + 8], "little") < P for i in range(0, 64, 8)))
            self.assertEqual(k, falcon.key_digest(bytearray(data)))
            self.assertEqual(falcon.address(data), k[:32])
        self.assertNotEqual(falcon.key_digest(self.pk), falcon.key_digest(flip(self.pk, 0)))

    def test_address_text(self):
        address = falcon.address(self.pk)
        text = falcon.format_address(address)
        self.assertEqual((len(text), text[:2], text[2:].lower()), (74, "0x", text[2:]))
        self.assertEqual(falcon.parse_address(text), address)
        self.assertEqual(falcon.parse_address("0x" + text[2:].upper()), address)
        for at in range(2, 74):
            changed = text[:at] + ("1" if text[at] == "0" else "0") + text[at + 1:]
            self.assertRaises(ValueError, falcon.parse_address, changed)
        for other in (text[2:], "0X" + text[2:], text + "0", text[:73], text[:40] + " " + text[41:],
                      text.encode()):
            self.assertRaises(ValueError, falcon.parse_address, other)
        self.assertRaises(ValueError, falcon.format_address, address[1:])


if __name__ == "__main__":
    unittest.main()
