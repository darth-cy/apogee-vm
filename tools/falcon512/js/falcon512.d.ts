// Falcon-512 with Poseidon2's HashToPoint. NOT interoperable with standard Falcon-512.

export declare const PUBLIC_KEY_BYTES: 897;
export declare const SECRET_KEY_BYTES: 1281;
export declare const SIGNATURE_BYTES: 666;
export declare const SALT_BYTES: 40;

export interface KeyPair {
  /** 1281 bytes: 0x59, f and g (6 bits each), F (8 bits each). */
  secretKey: Uint8Array;
  /** 897 bytes: 0x09, then h = g/f mod q, 14 bits a coefficient. */
  publicKey: Uint8Array;
}

/** A fresh key pair from `globalThis.crypto.getRandomValues`. */
export declare function generateKeyPair(): KeyPair;

/**
 * A 666-byte padded signature (0x39, 40-byte salt, compressed s2, zero padding) of `message` under the
 * application's `context` (default empty, at most 255 bytes). Throws on a malformed secret key or a longer
 * context.
 */
export declare function sign(secretKey: Uint8Array, message: Uint8Array, context?: Uint8Array): Uint8Array;

/**
 * True iff `signature` is valid for `message` under `publicKey` and `context` (default empty). Never throws:
 * malformed input, a context over 255 bytes among it, is false.
 */
export declare function verify(
  publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array, context?: Uint8Array): boolean;

/**
 * The Poseidon2-A64-C5 HashToPoint over (SIGNATURE_DOMAIN, K of `publicKey`, salt, context, message): 512
 * coefficients, each below q = 12289. Hashes the bytes as given.
 */
export declare function hashToPoint(
  publicKey: Uint8Array, salt: Uint8Array, message: Uint8Array, context?: Uint8Array): Uint16Array;

/** K, the 64-byte key digest: eight lanes below p = 2^64 − 59, each 8 bytes little-endian. Defined for any bytes. */
export declare function keyDigest(publicKey: Uint8Array): Uint8Array;

/** The 32-byte address: K's first 32 bytes. */
export declare function address(publicKey: Uint8Array): Uint8Array;

/** The address's text: "0x", the address and its 4-byte checksum in lowercase hex, 74 characters. */
export declare function formatAddress(address: Uint8Array): string;

/**
 * The 32-byte address of a text: exactly "0x", 72 hex digits of either case, the checksum matching.
 * Throws otherwise.
 */
export declare function parseAddress(text: string): Uint8Array;

/** The 897-byte public key of a secret key. Throws on a malformed secret key. */
export declare function publicKeyFromSecretKey(secretKey: Uint8Array): Uint8Array;

/** @internal Verify with a given point `c` (512 residues mod q) in place of HashToPoint. */
export declare function _verifyWithPoint(publicKey: Uint8Array, c: ArrayLike<number>, signature: Uint8Array): boolean;

/** @internal The Poseidon2-A64-C5 permutation of 16 lanes. */
export declare function _poseidon2(state: ArrayLike<bigint | number>): bigint[];
