"""The shared vectors, ../../vectors.json, which the Rust and JS suites read too: the official Falcon-512
KAT through the verification core (with standard Falcon's SHAKE256 HashToPoint), HashToPoint's points,
key digests, addresses and their texts, address texts to read or refuse, every implementation's
signatures, and malformed signatures, keys and contexts."""

import hashlib
import json
import os
import unittest

import apogee_falcon512 as falcon
from apogee_falcon512 import SIGNATURE_BYTES

Q = 12289
VECTORS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "vectors.json")

with open(VECTORS_PATH) as fh:
    VECTORS = json.load(fh)


def section(name):
    """The entries of one section, at least one."""
    entries = VECTORS[name]
    assert entries, name + " is empty"
    return entries


def unhex(v, *keys):
    """A vector's hex fields `keys`, as bytes."""
    return tuple(bytes.fromhex(v[k]) for k in keys)


def flip(data, bit):
    """data with one bit flipped, bit 0 being the most significant bit of byte 0."""
    out = bytearray(data)
    out[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(out)


def shake_point(salt, message):
    """Standard Falcon-512's HashToPoint: SHAKE256(salt || message) as 16-bit big-endian samples t,
    each t < 61445 kept as t mod q."""
    stream = hashlib.shake_256(salt + message).digest(4096)
    c = [t % Q for t in (int.from_bytes(stream[i:i + 2], "big") for i in range(0, 4096, 2)) if t < 5 * Q]
    assert len(c) >= 512
    return c[:512]


class StandardKat(unittest.TestCase):
    """Official Falcon-512 KAT vectors (padded signatures) through the verification core."""

    @classmethod
    def setUpClass(cls):
        cls.vectors = [unhex(v, "pk", "msg", "sig") for v in section("standard_kat")]

    def test_all_verify(self):
        for pk, msg, sig in self.vectors:
            self.assertTrue(falcon._verify_with_point(pk, shake_point(sig[1:41], msg), sig))
            self.assertFalse(falcon.verify(pk, msg, sig))  # a standard signature is not one here

    def test_flipped_bits_refuse(self):
        for pk, msg, sig in self.vectors:
            c = shake_point(sig[1:41], msg)
            self.assertFalse(falcon._verify_with_point(pk, shake_point(sig[1:41], flip(msg, 5)), sig))
            salted = flip(sig, 8 + 13)
            self.assertFalse(falcon._verify_with_point(pk, shake_point(salted[1:41], msg), salted))
            self.assertFalse(falcon._verify_with_point(pk, c, flip(sig, 8 * 41 + 2)))  # s2
            self.assertEqual(sig[-1], 0)
            self.assertFalse(falcon._verify_with_point(pk, c, flip(sig, 8 * SIGNATURE_BYTES - 1)))


class Vectors(unittest.TestCase):
    def test_hash_to_point(self):
        for v in section("hash_to_point"):
            self.assertEqual(falcon.hash_to_point(*unhex(v, "pk", "salt", "msg", "context")), v["c"])

    def test_key_digest_address_and_text(self):
        for v in section("key_digest"):
            pk, k, address = unhex(v, "pk", "key_digest", "address")
            self.assertEqual(falcon.key_digest(pk), k)
            self.assertEqual(falcon.address(pk), address)
            self.assertEqual(falcon.format_address(address), v["address_text"])
            self.assertEqual(falcon.parse_address(v["address_text"]), address)

    def test_address_text(self):
        for v in section("address_text"):
            with self.subTest(case=v["case"]):
                if v["address"] is None:
                    self.assertRaises(ValueError, falcon.parse_address, v["text"])
                else:
                    self.assertEqual(falcon.parse_address(v["text"]), bytes.fromhex(v["address"]))

    def test_signatures_verify(self):
        for v in section("signatures"):
            with self.subTest(signer=v["signer"]):
                self.assertTrue(falcon.verify(*unhex(v, "pk", "msg", "sig", "context")))

    def test_malformed_refuse(self):
        for v in section("malformed"):
            with self.subTest(case=v["case"]):
                self.assertFalse(falcon.verify(*unhex(v, "pk", "msg", "sig", "context")))


if __name__ == "__main__":
    unittest.main()
