// The Falcon round-3 reference implementation's Falcon-512 key generation, bit for bit.

import type { KeyPair } from './falcon512.js';

/** The seed's length in bytes. */
export declare const SEED_BYTES: 48;

/**
 * The reference keygen of a 48-byte seed: SHAKE256 of the seed as the RNG of the reference's keygen
 * at logn = 9, the keys encoded as its `crypto_sign_keypair` encodes them. The same seed gives the
 * same keys as the reference C, on every platform. Throws unless the seed is 48 bytes.
 */
export declare function keygen(seed: Uint8Array): KeyPair;
