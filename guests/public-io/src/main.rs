#![no_std]
#![no_main]
//! S-IO's guest: the whole public-values architecture in one small program.
//!
//! ```text
//! bulk data               -> ADVICE          prover-supplied, bound by nothing
//! a commitment to it      -> PUBLIC INPUT    the verifier's own bytes
//! the result              -> PUBLIC OUTPUT   what the proof publishes
//! ```
//!
//! It issues **no ecall but `EXIT`**: `public_input`, `advice` and `commit` are
//! ordinary loads and stores (`docs/spec/public-values.md`). That is what makes
//! it provable, and it is the contrast this guest exists to draw — every other
//! guest in this workspace that does I/O uses `read_stdin`/`write_stdout`, runs
//! under `qemu-riscv32`, and cannot be proven.
//!
//! # What it does, and why that shape
//!
//! The public input is eight bytes: a length `n` and a checksum `want`. The
//! advice is `n` bytes, which the guest reads and checksums. If the checksum
//! is not `want` the run fails; otherwise the guest commits the checksum and
//! the first eight bytes of the advice.
//!
//! That is the pattern `docs/spec/public-values.md` §6 states in miniature, and
//! the reason it is the pattern: **nothing binds the advice**, so the prover
//! chooses it, and a guest that published a function of it without checking it
//! would be publishing a value the prover chose. Here the check is against the
//! public input, which the proof does bind, so a prover who swaps the advice
//! either makes the run fail or has found a checksum collision.
//!
//! The checksum is deliberately position-dependent — `sum of advice[i]*(i+1)` —
//! so that a permutation of the advice is a different answer.
//!
//! # The exit status
//!
//! | status | what happened |
//! | --- | --- |
//! | 0 | the advice matched, and the journal holds the result |
//! | 60 | the public input is not eight bytes |
//! | 61 | the advice is not `n` bytes |
//! | 62 | the advice does not check against the public input |

guest_sdk::entry!(main);

/// The public input is not the eight bytes this guest reads.
const EXIT_BAD_INPUT: i32 = 60;
/// The advice is not the length the public input declared.
const EXIT_BAD_ADVICE_LENGTH: i32 = 61;
/// The advice does not check against the public input.
const EXIT_ADVICE_REFUSED: i32 = 62;

/// How many advice bytes the journal echoes, at most.
const ECHO: usize = 8;

fn word(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(word)
}

fn main() {
    let input = guest_sdk::public_input();
    if input.len() != 8 {
        guest_sdk::exit(EXIT_BAD_INPUT);
    }
    let (n, want) = (word(input, 0) as usize, word(input, 4));

    // Reading advice is a load, so there is no stream to run short: the slice
    // is as long as the host made it, and the guest says what it expected.
    let advice = guest_sdk::advice();
    if advice.len() != n {
        guest_sdk::exit(EXIT_BAD_ADVICE_LENGTH);
    }

    let mut sum = 0u32;
    for (i, byte) in advice.iter().enumerate() {
        sum = sum.wrapping_add((*byte as u32).wrapping_mul(i as u32 + 1));
    }
    if sum != want {
        guest_sdk::exit(EXIT_ADVICE_REFUSED);
    }

    // Two appends rather than one, so the journal's length word is seen to
    // move: what the proof binds is the byte string, not a fixed-size record.
    guest_sdk::commit(&sum.to_le_bytes());
    guest_sdk::commit(&advice[..ECHO.min(advice.len())]);
    guest_sdk::exit(0);
}
