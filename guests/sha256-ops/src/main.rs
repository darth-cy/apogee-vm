#![no_std]
#![no_main]
//! S26c's guest for the `SHA256_COMP` delegation: Ethereum's `0x02`
//! precompile's compression function, checked three ways in one binary.
//!
//! # The three halves, and why each
//!
//! **The ABI, called by name.** One raw [`guest_sdk::recursion::sha256_rounds`]
//! call — four rounds and four schedule words since S26e — and a whole
//! [`guest_sdk::recursion::sha256_comp`], its sixteen calls, over a frame this
//! guest writes itself, so the circuit is exercised at the frame level and not
//! only through a digest function. Every expectation is a **literal**: FIPS
//! 180-4's appendix prints the working variables after every round of the
//! `"abc"` block, so the first call's are a row of that table, and `"abc"` is
//! one padded block, so the initial state plus the sixteenth call's working
//! variables *is* the published digest.
//!
//! **The padding and the block loop, against published digests.**
//! [`guest_sdk::sha256`] is the patchable surface (`docs/spec/delegation.md`
//! §15), and what can go wrong in it is the Merkle-Damgård padding rather than
//! the compression: the length field, the `0x80`, and the boundary where a tail
//! stops fitting in one block. So the vectors here are chosen by **length** —
//! 0, 3, 55, 56, 63, 64, 65 — with 55 the last that pads into one block and 56
//! the first that needs two, and every digest a literal from a published table.
//!
//! **A foreign implementation, run rather than reserved.** §2 of
//! `docs/spec/delegation.md` requires a caller to have a software path, and
//! `guest_sdk::sha256`'s is in `guest-sdk` beside the delegated one — so a
//! comparison between them is a comparison between two functions in this
//! repository. `sha2` is not: it is an unpatched crates.io crate running its
//! own compression, and this guest runs it on **every** vector and compares.
//! That is what makes the literals above a check of two implementations rather
//! than of one, and it is the same shape `guests/mod-mul-ops` uses.
//!
//! **Nothing in this guest can observe whether the delegation is live**, and
//! that is by construction — a delegated compression and a software one agree
//! on the digest. What observes it is the *invocation count*, pinned host-side
//! in `crates/emulator/tests/guests.rs`.
//!
//! # Input, advice and the journal
//!
//! Unused. `EXIT` and `PRECOMPILE_SHA256_COMP` are this guest's only ecalls,
//! which is what keeps it provable.
//!
//! # The result
//!
//! The exit status, `a0`: one per check passed but the first, as every fixture
//! guest here reports it, or `200 + i` on the first that fails — which names
//! the check rather than leaving a count one short.

use guest_sdk::recursion::{sha256_comp, sha256_rounds, Sha256Frame, SHA256_IV};
use guest_sdk::{entry, exit, sha256};
use sha2::{Digest, Sha256};

entry!(main);

/// FIPS 180-4 §A.1's `"abc"`, padded into its one block: the message, the
/// `0x80` terminator, zeros, and the bit length 24 in the last word.
///
/// Spelled out rather than built by calling the padding this guest is
/// checking. A vector computed by the code under test checks nothing.
const ABC_BLOCK: [u32; 16] = [
    0x6162_6380,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x0000_0018,
];

/// The working variables after round 3 of [`ABC_BLOCK`] from the IV: FIPS
/// 180-4's appendix, the row for `t = 3`. One raw call runs rounds 0 to 3.
const ABC_ROUND3: [u32; 8] = [
    0xd550_f666,
    0xc8c3_47a7,
    0x5a6a_d9ad,
    0x5d6a_ebcd,
    0x24e0_0850,
    0xf929_39eb,
    0x78ce_7989,
    0xfa2a_4622,
];

/// `W_16..W_19` of [`ABC_BLOCK`]'s message schedule: the four words the first
/// call appends to the window as it moves it down four.
const ABC_W16: [u32; 4] = [0x6162_6380, 0x000f_0000, 0x7da8_6405, 0x6000_03c6];

/// `sha256("abc")` as its eight big-endian state words. Because `"abc"` is one
/// padded block, this is also the chaining state one compression of
/// [`ABC_BLOCK`] from the IV must leave.
const ABC_STATE: [u32; 8] = [
    0xba78_16bf,
    0x8f01_cfea,
    0x4141_40de,
    0x5dae_2223,
    0xb003_61a3,
    0x9617_7a9c,
    0xb410_ff61,
    0xf200_15ad,
];

/// The published digests of `"a" * n` for the seven lengths this guest checks,
/// as lowercase hex. The lengths are [`LENGTHS`], and the two that matter are
/// 55 and 56 — the last that pads into one block and the first that needs two.
const DIGESTS: [&str; 7] = [
    // n = 0, the empty message: one block, all of it padding.
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    // n = 3, which is `"aaa"` and not `"abc"`.
    "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
    "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
    "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
    "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
    "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
    "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
];

/// The message lengths [`DIGESTS`] covers, in the same order.
const LENGTHS: [usize; 7] = [0, 3, 55, 56, 63, 64, 65];

/// FIPS 180-4 §A.2's two-block vector, and its published digest.
const TWO_BLOCK: &str = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const TWO_BLOCK_DIGEST: &str = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

/// A digest against its published hex, and against `sha2`'s answer for the same
/// bytes.
///
/// Both comparisons, every time. The literal is what says the padding is the
/// published one; `sha2` is what says so for the lengths no table here covers,
/// and it is the only implementation in this check that is not this
/// repository's.
fn digest_is(message: &[u8], want: &str) -> bool {
    let ours = sha256(message);
    let theirs = Sha256::digest(message);
    hex_is(&ours, want) && ours[..] == theirs[..]
}

/// A byte string against its lowercase hex. Written out rather than decoded, so
/// the expectation in this file is the form a reader can check against any
/// published table.
fn hex_is(bytes: &[u8], want: &str) -> bool {
    if bytes.len() * 2 != want.len() {
        return false;
    }
    let digits = want.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        if digits[2 * i] != nibble(byte >> 4) || digits[2 * i + 1] != nibble(byte & 0xf) {
            return false;
        }
    }
    true
}

/// A nibble as its lowercase hex digit.
fn nibble(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

fn main() {
    let mut passed = 0i32;
    let mut i = 0i32;
    let mut check = |ok: bool| {
        if !ok {
            exit(200 + i);
        }
        i += 1;
        passed += 1;
    };

    // --- The ABI, called by name, against literals.

    // One raw call is rounds 0 to 3. `false` from the shim is exactly
    // `-ENOSYS` — an executor with no `SHA256_COMP` circuit, which is every
    // executor but this VM's — and then there is nothing for this check to
    // compare, so it passes on the software path having already been checked
    // below.
    let mut frame = Sha256Frame::of(&SHA256_IV, &ABC_BLOCK);
    let answered = sha256_rounds(&mut frame);
    check(!answered || frame.working() == ABC_ROUND3);

    // The window moved down four words and took on the four schedule words
    // those rounds unlock: the schedule crosses the frame, sixteen at a time.
    let mut window = [0u32; 16];
    window[..12].copy_from_slice(&ABC_BLOCK[4..]);
    window[12..].copy_from_slice(&ABC_W16);
    check(!answered || frame.0[9..25] == window);

    // A whole compression is sixteen calls, and the initial state plus the
    // working variables they leave is the published digest.
    let mut frame = Sha256Frame::of(&SHA256_IV, &ABC_BLOCK);
    let answered = sha256_comp(&mut frame);
    let mut state = SHA256_IV;
    for (h, v) in state.iter_mut().zip(frame.working()) {
        *h = h.wrapping_add(v);
    }
    check(!answered || state == ABC_STATE);

    // A second compression, chaining from the first, so the frame's state lane
    // is shown to be read and not only written. The block is all zeros, which
    // is not a padded anything — this checks the chaining, and `sha2` has no
    // say in it, so the expectation is that it differs from the IV round.
    let chained = {
        let mut f = Sha256Frame::of(&ABC_STATE, &[0u32; 16]);
        let answered = sha256_comp(&mut f);
        let mut next = ABC_STATE;
        for (h, v) in next.iter_mut().zip(f.working()) {
            *h = h.wrapping_add(v);
        }
        (answered, next)
    };
    check(!chained.0 || chained.1 != ABC_STATE);

    // --- The padding and the block loop, at every length that changes it.

    let mut message = [b'a'; 65];
    for (n, want) in LENGTHS.iter().zip(DIGESTS.iter()) {
        check(digest_is(&message[..*n], want));
    }

    // FIPS 180-4's own two-block vector, at 56 bytes: the same length as the
    // fourth case above and a different message, so a padding that happened to
    // be right for `"aaa..."` is not right by accident here.
    check(digest_is(TWO_BLOCK.as_bytes(), TWO_BLOCK_DIGEST));

    // A message long enough to be several blocks, against `sha2` alone. No
    // literal for it: what this check is for is the loop, and 1,000 bytes is
    // fifteen full blocks and a tail.
    let mut long = [0u8; 1000];
    for (k, byte) in long.iter_mut().enumerate() {
        *byte = (k % 251) as u8;
    }
    check(sha256(&long)[..] == Sha256::digest(long)[..]);

    // The one-byte difference a digest must see. `message` is still all `b'a'`.
    message[0] = b'b';
    check(sha256(&message[..65])[..] != Sha256::digest([b'a'; 65])[..]);

    exit(passed - 1);
}
