// The Apogee wallet: 24 generated BIP39 words, an HKDF-SHA512 account seed, the reference keygen.

import type { KeyPair } from './falcon512.js';

/** HKDF's info names this scheme, then the account index. */
export declare const WALLET_SCHEME: 'apogee/wallet/falcon512/v1';

/** 24 new words: 256 bits from `crypto.getRandomValues` and BIP39's 8-bit checksum. */
export declare function generateMnemonic(): string;

/**
 * The canonical sentence of `text` (NFKD, lowercase, single spaces). Throws unless it is 24 words of the
 * BIP39 English list with a valid checksum.
 */
export declare function validateMnemonic(text: string): string;

/** BIP39's 64-byte seed: PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic" and the passphrase. */
export declare function mnemonicToSeed(mnemonic: string, passphrase?: string): Promise<Uint8Array>;

/** The account's 48-byte seed: HKDF-SHA512 of the root seed under WALLET_SCHEME and `index` (u32). */
export declare function accountSeed(rootSeed: Uint8Array, index: number): Promise<Uint8Array>;

export interface Account extends KeyPair {
  /** The 32-byte address: the key digest's first 32 bytes. */
  address: Uint8Array;
  /** The address as text: 0x, 64 hex digits, then an 8-digit checksum. */
  addressText: string;
}

/**
 * Account `index` (default 0) of a generated mnemonic and an optional passphrase. The same words,
 * passphrase and index always recover the same keys and address. Rejects words that fail
 * `validateMnemonic`.
 */
export declare function deriveAccount(
  mnemonic: string, options?: { passphrase?: string; index?: number }): Promise<Account>;
