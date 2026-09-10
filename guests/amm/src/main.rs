#![no_std]
#![no_main]
//! A constant-product automated market maker: one two-asset pool, a batch of at
//! most 64 operations applied to it in order, and the pool it leaves behind.
//!
//! The arithmetic is Uniswap v2's — the `x*y` swap price, the pro-rata mint, the
//! pro-rata burn, `sqrt(x*y)` for the first shares — with one deliberate
//! deviation. The swap fee is taken *out* of the pool into a running total
//! rather than left in the reserves, so that the `fees_x` and `fees_y` words on
//! fd 1 are figures in their own right instead of something a reader has to
//! infer from a reserve delta. It also keeps the constant-product assertion
//! sharp: with the fee left in, the product grows for two unrelated reasons at
//! once and the assertion stops telling them apart.
//!
//! # What this is a fixture for
//!
//! **Wide integer arithmetic on a 32-bit machine.** RV32 multiplies 32 bits by
//! 32 bits and has nothing wider, so a `u128` here is four registers and every
//! operation on one is a sequence the backend writes out itself — rustc calls no
//! 128-bit builtin on this target, and `compiler_builtins` contributes only
//! `memcpy` and `memset` to the linked image. `crates/field` reaches for
//! `u128` as well, but only ever as the widening result of a 64-bit multiply;
//! this is the only guest whose *values* are 128 bits wide, and the only one
//! that needs the 256-bit intermediate an exact `mul_div` and a constant-product
//! check are built on.
//!
//! None of it is cheap. At opt-level 0 nothing knows that the `u64` halves
//! [`mul_u256`] multiplies have empty top halves, so each of its four partial
//! products compiles as a full 128-by-128 multiply — seventeen hardware
//! multiplies rather than the four a `u64 * u64` needs — and one 256-bit product
//! is sixty-eight of them. A single `mul_div` is that product and then 256
//! shift-and-subtract iterations of [`div_u256`], which is tens of thousands of
//! executed instructions with nothing in them but integer arithmetic; a swap is
//! two of those.
//!
//! It allocates nothing. Every buffer is a fixed array on the stack, because the
//! format bounds every one of them — the batch is read one 36-byte record at a
//! time and the journal is a single 104-byte write. `guests/echo` is where the
//! bump allocator is exercised.
//!
//! # The pool's rules
//!
//! An op is **applied** or **rejected**, and rejection is an ordinary outcome
//! rather than a fault: an op that would overflow, miss its limit, or empty the
//! pool leaves the pool exactly as it was and is counted. Both tallies reach
//! fd 1, so a batch that was refused in full is a different public statement
//! from one that was applied in full.
//!
//! Two things are *not* rejections. A malformed batch — a stream that ends
//! inside the header or inside a record, a fee outside `0..=1000`, more ops than
//! the format allows — is a statement with no batch in it, so it panics, which
//! fails the execution loudly and prints where on fd 2. And a constant product
//! that *fell* across a swap is a bug in this file rather than a property of the
//! input, so it panics too; see [`accept_swap`].
//!
//! The header may present reserves with no shares outstanding against them — an
//! unclaimed seed. Those shares are minted before the first op runs, as Uniswap
//! v2 mints its first liquidity: `sqrt(reserve_x * reserve_y)`, computed over
//! the full 256-bit product. A seed with either reserve empty mints nothing, and
//! a pool with no shares refuses every op, because every price in here is a
//! ratio against a reserve and every claim a ratio against the share count.
//! A pool cannot be conjured out of nothing: fd 0 seeds it or nothing does.
//!
//! # fd 0, the public input
//!
//! A 56-byte header, then `n_ops` records of 36 bytes. Every integer is
//! little-endian, and a record's `u128` fields are not 16-aligned — everything
//! goes through a byte copy, which has no alignment requirement of its own.
//!
//! ```text
//! header    0..16    reserve_x       u128
//!          16..32    reserve_y       u128
//!          32..48    total_shares    u128; zero means an unclaimed seed
//!          48..52    fee_bps         u32; basis points off every swap input,
//!                                    at most 1000
//!          52..56    n_ops           u32; at most 64
//!
//! record    0..4     kind            u32; 0..=4, see below
//!           4..20    amount          u128
//!          20..36    limit           u128
//! ```
//!
//! `kind` names the op and decides what `amount` and `limit` mean:
//!
//! ```text
//! 0  SwapXForY        amount of x in, at least `limit` of y out
//! 1  SwapYForX        the mirror
//! 2  AddLiquidity     amount of x deposited, y taken pro rata, at least
//!                     `limit` shares minted
//! 3  RemoveLiquidity  amount of shares burned, at least `limit` of x returned
//! 4  Quote            price the swap of `amount` x for y, at least `limit`,
//!                     without moving the pool
//! ```
//!
//! Anything else is an op this pool does not have and is rejected like any
//! other, rather than voiding the batch.
//!
//! # fd 1, the public output
//!
//! 104 bytes, written once at the end:
//!
//! ```text
//!           0..16    reserve_x       u128
//!          16..32    reserve_y       u128
//!          32..48    total_shares    u128
//!          48..64    fees_x          u128; cumulative x-side fees, in x units
//!          64..80    fees_y          u128; cumulative y-side fees, in y units
//!          80..96    last_quote      u128; the last accepted Quote, or zero
//!          96..100   applied         u32
//!         100..104   rejected        u32
//! ```
//!
//! # fd 3, and why it is empty
//!
//! Unused, and deliberately so. A hint is a shortcut to a value the guest then
//! checks against something fd 0 binds, and it earns its keep when the value is
//! expensive to derive and cheap to verify. Nothing here is either: every
//! quantity this guest commits is a short, total, deterministic function of the
//! header and the records — there is no search, no witness, and no root to
//! open — so advice could only ever restate work the guest has to do anyway in
//! order to check it.
//!
//! # One thing to expect in the artifact
//!
//! The dispatch in [`settle`] is exhaustive over five variants, and at
//! opt-level 0 LLVM lowers it to a jump table: an indexed load, a `jalr` through
//! it, and then a single `c.unimp` halfword padding the default block it proved
//! unreachable. `crates/loader` records that halfword as a not-code slot rather
//! than an instruction, because `c.unimp` is a defined-illegal encoding, and the
//! `.img.txt` report folds it into a one-halfword `---- not code ----` run in
//! the middle of the function — the only one in the image. It is expected, and
//! no pc reaches it.

guest_sdk::entry!(main);

// ---------------------------------------------------------------------------
// The format's bounds
// ---------------------------------------------------------------------------

/// The largest batch the format allows. It bounds the loop and nothing else:
/// records are read one at a time, so no buffer is sized by it.
const MAX_OPS: u32 = 64;

/// The largest fee the format allows, in basis points — ten per cent.
const MAX_FEE_BPS: u32 = 1_000;

/// Basis points in the whole: a fee is `amount * fee_bps / BPS_DENOM`.
const BPS_DENOM: u128 = 10_000;

/// `reserve_x`, `reserve_y`, `total_shares`, `fee_bps`, `n_ops`.
const HEADER_LEN: usize = 56;

/// `kind`, `amount`, `limit`.
const RECORD_LEN: usize = 36;

/// Six `u128` totals and two `u32` tallies.
const OUTPUT_LEN: usize = 104;

/// The iteration ceiling in [`sqrt_u256`], and the subject of its termination
/// argument.
const SQRT_STEPS: u32 = 200;

// ---------------------------------------------------------------------------
// 256-bit arithmetic
// ---------------------------------------------------------------------------

/// A 256-bit value, as a `(high, low)` pair of `u128` halves.
///
/// A tuple rather than a struct for one reason: Rust orders tuples
/// lexicographically, so `(hi_a, lo_a) < (hi_b, lo_b)` is already the numeric
/// comparison of the two 256-bit values, and the constant-product assertion in
/// [`accept_swap`] needs nothing further.
type U256 = (u128, u128);

/// The exact 256-bit product of two `u128`s.
///
/// Schoolbook over `u64` halves, which is the only shape that stays inside
/// `u128` at every step: each of the four partial products is at most
/// `(2^64 - 1)^2`, comfortably below `2^128`, whereas any attempt to multiply
/// the halves in a wider type would need the wider type this function exists to
/// build. What the compiler makes of it is in the module doc: four partial
/// products, sixty-eight hardware multiplies, and the carry chain below.
fn mul_u256(a: u128, b: u128) -> U256 {
    /// The low 64 bits of a `u128`.
    const LOW: u128 = u64::MAX as u128;

    let (a0, a1) = (a & LOW, a >> 64);
    let (b0, b1) = (b & LOW, b >> 64);

    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;

    // The two middle terms together can reach 2^129, so the carry out of their
    // sum is a real bit of the answer and is kept rather than checked away.
    let (mid, mid_carry) = p01.overflowing_add(p10);
    let (lo, lo_carry) = p00.overflowing_add((mid & LOW) << 64);

    // Every term below is a part of the true high word, which is under 2^128
    // because the product of two u128s is under 2^256; so each partial sum is
    // bounded by that word and none of these additions can overflow.
    let hi = p11 + (mid >> 64) + (u128::from(mid_carry) << 64) + u128::from(lo_carry);

    (hi, lo)
}

/// `floor((hi * 2^128 + lo) / d)`, or `None` when the divisor is zero or the
/// quotient will not fit in a `u128`.
///
/// Restoring long division, one bit of the dividend at a time. There is no
/// wider type to fall back on and no hardware divider on RV32 that would help
/// even if the operands were narrower, so a shift-and-subtract loop is both the
/// obvious implementation and the only one whose exactness is visible by
/// inspection. It is 256 iterations regardless of the operands, which is also
/// what makes its cost independent of the values a prover chose.
fn div_u256(hi: u128, lo: u128, d: u128) -> Option<u128> {
    if d == 0 {
        return None;
    }
    // The quotient is below 2^128 exactly when the high half is below the
    // divisor, so this single comparison is the whole overflow test and the
    // loop is spared having to notice.
    if hi >= d {
        return None;
    }

    let mut rem: u128 = 0;
    let mut quo: u128 = 0;
    for i in (0..256u32).rev() {
        // The dividend's bits, most significant first. The subtraction is
        // guarded by the branch it sits in, so the unsigned counter cannot
        // wrap under it.
        let bit = if i >= 128 {
            (hi >> (i - 128)) & 1
        } else {
            (lo >> i) & 1
        };

        // The running remainder is always below `d`, so doubling it can carry
        // out of the `u128`; that carry is the difference between "subtract"
        // and "do not" and is taken before the shift discards it.
        let carry = (rem >> 127) != 0;
        rem = (rem << 1) | bit;

        // The quotient bits arrive from position 255 downward, and the test
        // above proved the top 128 of them are zero, so this shift never pushes
        // a set bit off the end.
        quo <<= 1;

        // With the carry set the true remainder is `2^128 + rem`, which is
        // above `d` unconditionally. The subtraction is exact in either case:
        // the true value is under `2 * d`, so the difference is under `d` and
        // therefore under `2^128`, and the wrapping form computes it as the
        // borrow it is.
        if carry || rem >= d {
            rem = rem.wrapping_sub(d);
            quo |= 1;
        }
    }
    Some(quo)
}

/// `floor(a * b / d)`, exact even where `a * b` overflows a `u128`.
///
/// Uniswap's `FullMath.mulDiv`, and the heart of this guest: every price, every
/// mint and every burn below is one call to it. Both halves of the answer are
/// needed — the product must not be truncated before the division, or a swap
/// against a large pool prices at nothing — so the product is formed in 256 bits
/// and consumed there.
///
/// `None` is the honest answer for a zero divisor and for a quotient above
/// `u128::MAX`; both are rejections at the call site rather than saturations,
/// because a saturated price is a lie that the invariant assertion would then
/// have to catch.
fn mul_div(a: u128, b: u128, d: u128) -> Option<u128> {
    let (hi, lo) = mul_u256(a, b);
    div_u256(hi, lo, d)
}

/// `floor(sqrt(hi * 2^128 + lo))`, which always fits in a `u128`.
///
/// Newton's iteration on integers: from an over-estimate, `x` moves to
/// `floor((x + floor(N/x)) / 2)` and the first step that does not move down is
/// at `floor(sqrt(N))`. Two details make it safe in fixed width.
///
/// The average is computed as `q + (x - q) / 2` rather than `(x + q) / 2`,
/// because the latter overflows for `x` near `2^128` while the former is the
/// same integer and never leaves the range. And `floor(N/x)` is asked for as a
/// `u128`: it fits whenever `x` is at least `floor(sqrt(N))`, which the
/// iteration maintains, except at the very top of the range where the true
/// quotient can exceed `u128::MAX` by two. There it is capped, which stops the
/// iteration at once and returns `u128::MAX` — the correct answer, because a
/// quotient that large only arises for `N` above `(2^128 - 2)^2`.
///
/// The loop is bounded rather than open. Each step strictly decreases `x` while
/// it is running, and the worst start is `u128::MAX` against a small `N`, which
/// roughly halves each time: 128 halvings and then a handful of quadratic steps.
/// The ceiling is far past both, so reaching it means the reasoning above is
/// wrong, and a panic says so rather than the guest spinning.
fn sqrt_u256(hi: u128, lo: u128) -> u128 {
    if hi == 0 && lo == 0 {
        return 0;
    }

    // The first power of two at or above the square root: `2^ceil(bits/2)` is
    // above `sqrt(N)` for any `N` under `2^bits`. At the top of the range that
    // power is `2^128`, which is not representable and is replaced by
    // `u128::MAX` — still at or above the answer, because `floor(sqrt(N))` for
    // a 256-bit `N` never exceeds `u128::MAX`.
    let bits = if hi != 0 {
        256 - hi.leading_zeros()
    } else {
        128 - lo.leading_zeros()
    };
    let half = bits.div_ceil(2);
    let mut x = if half >= 128 {
        u128::MAX
    } else {
        1u128 << half
    };

    for _ in 0..SQRT_STEPS {
        let q = div_u256(hi, lo, x).unwrap_or(u128::MAX);
        if q >= x {
            return x;
        }
        x = q + (x - q) / 2;
    }
    panic!("amm: the square root did not converge");
}

// ---------------------------------------------------------------------------
// The pool
// ---------------------------------------------------------------------------

/// The whole of the mutable state: two reserves and the shares against them.
#[derive(Clone, Copy)]
struct Pool {
    x: u128,
    y: u128,
    shares: u128,
}

/// A pool with nothing in it: an empty reserve, or no shares outstanding.
///
/// It is asked at both ends of an op, and for one reason. An empty reserve
/// makes every price a division by zero and an empty share count makes every
/// claim one, so such a pool can neither be traded against nor be a state an op
/// is allowed to leave behind — an op that emptied it would quietly reject the
/// whole rest of the batch. Uniswap v2 reaches the same rule from the other
/// side, burning a minimum liquidity on the first mint so the state cannot be
/// arrived at.
fn is_empty(pool: Pool) -> bool {
    pool.x == 0 || pool.y == 0 || pool.shares == 0
}

/// The five ops, as fd 0 spells them.
#[derive(Clone, Copy)]
#[repr(u32)]
enum Kind {
    SwapXForY = 0,
    SwapYForX = 1,
    AddLiquidity = 2,
    RemoveLiquidity = 3,
    Quote = 4,
}

impl Kind {
    /// Decode a record's tag, or refuse it.
    ///
    /// The refusal is the dispatch's explicit default, and it is a rejection
    /// rather than a panic: fd 0 is public but not well formed by assumption,
    /// and an op this pool does not have is a request it declines, not a
    /// statement it cannot parse.
    fn decode(tag: u32) -> Option<Kind> {
        match tag {
            0 => Some(Kind::SwapXForY),
            1 => Some(Kind::SwapYForX),
            2 => Some(Kind::AddLiquidity),
            3 => Some(Kind::RemoveLiquidity),
            4 => Some(Kind::Quote),
            _ => None,
        }
    }
}

/// One record, decoded. `amount` and `limit` mean whatever `kind` says.
struct Op {
    kind: u32,
    amount: u128,
    limit: u128,
}

/// What an accepted op does. A rejection is the `None` of `Option<Effect>`, and
/// every path to it leaves the pool untouched.
enum Effect {
    /// The pool moves here, having booked this much fee on each side. Only one
    /// side is ever nonzero, but carrying both keeps the two swap directions
    /// one shape instead of two.
    Move {
        next: Pool,
        fee_x: u128,
        fee_y: u128,
    },
    /// A price, computed against the pool and then dropped.
    Priced(u128),
}

/// The swap arithmetic's answer, stated in terms of the input and output
/// reserves rather than of `x` and `y`.
struct Swap {
    /// The reserve that took the input, after the trade.
    reserve_in: u128,
    /// The reserve that paid the output, after the trade.
    reserve_out: u128,
    /// Withheld from the input, in input-side units.
    fee: u128,
    /// What the trader receives.
    out: u128,
}

/// Price and settle one swap against an ordered reserve pair.
///
/// Stated once and called twice. The caller says which of `x` and `y` is the
/// input side and reassembles the pool afterwards, so the two directions are
/// literally the same arithmetic rather than a transcription of it and its
/// mirror — a transposed reserve in one of two copies is exactly the bug that
/// survives review.
///
/// `None` is a rejection, and every arithmetic step that could produce one is
/// checked. Two of the refusals are Uniswap v2's rather than this format's: a
/// trade of nothing and a trade that returns nothing are both refused there,
/// the first because it moves no state while counting as an op and the second
/// because it is a donation to the pool wearing a swap's clothes.
fn swap_quote(
    reserve_in: u128,
    reserve_out: u128,
    fee_bps: u32,
    amount: u128,
    min_out: u128,
) -> Option<Swap> {
    if amount == 0 {
        return None;
    }

    // The fee leaves the pool, so it comes off the input before the reserves or
    // the price see any of it.
    let fee = mul_div(amount, u128::from(fee_bps), BPS_DENOM)?;
    let net = amount.checked_sub(fee)?;
    if net == 0 {
        return None;
    }

    let new_in = reserve_in.checked_add(net)?;
    // `new_in` is at least `net`, which is nonzero, so the divisor here is
    // never zero and `mul_div` can only refuse a quotient that will not fit.
    let out = mul_div(reserve_out, net, new_in)?;
    if out == 0 || out < min_out {
        return None;
    }
    let new_out = reserve_out.checked_sub(out)?;

    Some(Swap {
        reserve_in: new_in,
        reserve_out: new_out,
        fee,
        out,
    })
}

/// Book a swap: the emptiness rule, and then the invariant.
///
/// **The constant product is asserted, not rejected.** `x*y` not falling across
/// a swap is a property of the formula above, which floors the output and so can
/// only ever leave the product where it was or above it; it is not a property of
/// the input, and no record can make it false. If it is false then the price,
/// the fee split or the 256-bit arithmetic underneath them is wrong, and the
/// loud failure is the useful one — a rejection would hide a broken multiply
/// behind a plausible tally.
///
/// The comparison is over the full 256-bit products, because truncating them to
/// `u128` first would make the assertion pass on exactly the pools where the
/// arithmetic is hardest.
fn accept_swap(before: Pool, next: Pool, fee_x: u128, fee_y: u128) -> Option<Effect> {
    if is_empty(next) {
        return None;
    }
    assert!(
        mul_u256(next.x, next.y) >= mul_u256(before.x, before.y),
        "amm: the constant product fell across a swap"
    );
    Some(Effect::Move { next, fee_x, fee_y })
}

/// Settle one op against the pool, or refuse it.
///
/// The five arms below are the whole of the pool's behaviour. Each returns a
/// candidate state and never writes one: the caller applies it, so a rejection
/// discovered in the last line of an arm costs nothing to unwind.
fn settle(pool: Pool, fee_bps: u32, op: &Op) -> Option<Effect> {
    let kind = Kind::decode(op.kind)?;

    match kind {
        Kind::SwapXForY => {
            let s = swap_quote(pool.x, pool.y, fee_bps, op.amount, op.limit)?;
            let next = Pool {
                x: s.reserve_in,
                y: s.reserve_out,
                shares: pool.shares,
            };
            accept_swap(pool, next, s.fee, 0)
        }

        Kind::SwapYForX => {
            let s = swap_quote(pool.y, pool.x, fee_bps, op.amount, op.limit)?;
            let next = Pool {
                x: s.reserve_out,
                y: s.reserve_in,
                shares: pool.shares,
            };
            accept_swap(pool, next, 0, s.fee)
        }

        Kind::AddLiquidity => {
            // A pool with nothing in it has no ratio to deposit against and no
            // denominator to mint against.
            if is_empty(pool) || op.amount == 0 {
                return None;
            }
            let dx = op.amount;
            let dy = mul_div(dx, pool.y, pool.x)?;
            if dy == 0 {
                return None;
            }

            // Uniswap v2 mints the smaller of the two pro-rata claims. Here the
            // second is bounded by the first, because `dy` was floored out of
            // it, but taking the minimum states the rule instead of relying on
            // that — and the rule is what stops a lopsided deposit from minting
            // against the more generous side of itself.
            let by_x = mul_div(dx, pool.shares, pool.x)?;
            let by_y = mul_div(dy, pool.shares, pool.y)?;
            let minted = by_x.min(by_y);
            if minted == 0 || minted < op.limit {
                return None;
            }

            // Nothing to check for emptiness: all three components strictly
            // increase here.
            let next = Pool {
                x: pool.x.checked_add(dx)?,
                y: pool.y.checked_add(dy)?,
                shares: pool.shares.checked_add(minted)?,
            };
            Some(Effect::Move {
                next,
                fee_x: 0,
                fee_y: 0,
            })
        }

        Kind::RemoveLiquidity => {
            let burn = op.amount;
            if burn == 0 || burn > pool.shares {
                return None;
            }
            let dx = mul_div(burn, pool.x, pool.shares)?;
            let dy = mul_div(burn, pool.y, pool.shares)?;
            // Uniswap v2 refuses a burn that returns nothing on either side; so
            // does the format's `limit`, on the x side only.
            if dx == 0 || dy == 0 || dx < op.limit {
                return None;
            }

            let next = Pool {
                x: pool.x.checked_sub(dx)?,
                y: pool.y.checked_sub(dy)?,
                shares: pool.shares.checked_sub(burn)?,
            };
            // This is where the emptiness rule earns its place: burning the
            // last share takes the pool to exactly nothing.
            if is_empty(next) {
                return None;
            }
            Some(Effect::Move {
                next,
                fee_x: 0,
                fee_y: 0,
            })
        }

        Kind::Quote => {
            // A quote is the swap that would have happened, refused on every
            // ground the swap would be refused on, the emptiness rule
            // included, so that a price this guest commits is one the pool
            // would actually honour.
            let s = swap_quote(pool.x, pool.y, fee_bps, op.amount, op.limit)?;
            let next = Pool {
                x: s.reserve_in,
                y: s.reserve_out,
                shares: pool.shares,
            };
            if is_empty(next) {
                return None;
            }
            Some(Effect::Priced(s.out))
        }
    }
}

// ---------------------------------------------------------------------------
// The batch
// ---------------------------------------------------------------------------

fn main() {
    let mut header = [0u8; HEADER_LEN];
    assert_eq!(
        guest_sdk::read_input(&mut header),
        HEADER_LEN,
        "amm: fd 0 ended inside the header"
    );
    let (mut pool, fee_bps, n_ops) = decode_header(&header);
    assert!(
        fee_bps <= MAX_FEE_BPS,
        "amm: fee_bps is above the format's maximum"
    );
    assert!(n_ops <= MAX_OPS, "amm: n_ops is above the format's maximum");

    // The unclaimed seed is claimed here, before any op runs, because every op
    // below divides by the share count.
    if pool.shares == 0 {
        let (hi, lo) = mul_u256(pool.x, pool.y);
        pool.shares = sqrt_u256(hi, lo);
        guest_sdk::log(b"amm: minted sqrt(x*y) against the seed\n");
    }

    let mut fees_x: u128 = 0;
    let mut fees_y: u128 = 0;
    let mut last_quote: u128 = 0;
    let mut applied: u32 = 0;
    let mut rejected: u32 = 0;

    // One record at a time, in order. The batch is a sequence and not a set:
    // each op is priced against what the ops before it left behind.
    for _ in 0..n_ops {
        let mut record = [0u8; RECORD_LEN];
        assert_eq!(
            guest_sdk::read_input(&mut record),
            RECORD_LEN,
            "amm: fd 0 ended inside an op record"
        );
        let op = decode_op(&record);

        match settle(pool, fee_bps, &op) {
            Some(Effect::Move { next, fee_x, fee_y }) => {
                // The fee totals are committed state too, so an op whose fee
                // would overflow one of them is rejected exactly as an op whose
                // reserves would be: applying it against a saturated total would
                // commit a figure that is the sum of nothing.
                match (fees_x.checked_add(fee_x), fees_y.checked_add(fee_y)) {
                    (Some(fx), Some(fy)) => {
                        pool = next;
                        fees_x = fx;
                        fees_y = fy;
                        applied += 1;
                    }
                    _ => rejected += 1,
                }
            }
            Some(Effect::Priced(quote)) => {
                last_quote = quote;
                applied += 1;
            }
            None => rejected += 1,
        }
    }

    let mut out = [0u8; OUTPUT_LEN];
    let mut at = 0;
    put_u128(&mut out, &mut at, pool.x);
    put_u128(&mut out, &mut at, pool.y);
    put_u128(&mut out, &mut at, pool.shares);
    put_u128(&mut out, &mut at, fees_x);
    put_u128(&mut out, &mut at, fees_y);
    put_u128(&mut out, &mut at, last_quote);
    put_u32(&mut out, &mut at, applied);
    put_u32(&mut out, &mut at, rejected);
    assert_eq!(
        at, OUTPUT_LEN,
        "amm: the journal is not the declared length"
    );
    guest_sdk::commit(&out);
}

// ---------------------------------------------------------------------------
// fd 0 in, fd 1 out
// ---------------------------------------------------------------------------

/// The header, in its declared order.
fn decode_header(b: &[u8; HEADER_LEN]) -> (Pool, u32, u32) {
    let pool = Pool {
        x: get_u128(b, 0),
        y: get_u128(b, 16),
        shares: get_u128(b, 32),
    };
    (pool, get_u32(b, 48), get_u32(b, 52))
}

/// One record, in its declared order.
fn decode_op(b: &[u8; RECORD_LEN]) -> Op {
    Op {
        kind: get_u32(b, 0),
        amount: get_u128(b, 4),
        limit: get_u128(b, 20),
    }
}

/// Read a little-endian `u128` at a fixed offset.
///
/// The offsets are structural: they come from the format, not from the input,
/// and every caller hands in a buffer whose length was already checked against
/// the read count. A slice out of range here would be a bug in this file, and
/// the panic it takes is the right answer to one.
fn get_u128(b: &[u8], at: usize) -> u128 {
    let mut w = [0u8; 16];
    w.copy_from_slice(&b[at..at + 16]);
    u128::from_le_bytes(w)
}

/// Read a little-endian `u32` at a fixed offset. As [`get_u128`].
fn get_u32(b: &[u8], at: usize) -> u32 {
    let mut w = [0u8; 4];
    w.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(w)
}

/// Append a little-endian `u128` to the journal and advance the cursor.
///
/// The cursor is carried rather than the offsets being written out, because
/// fd 1's layout is six fields of one width followed by two of another and a
/// transposed pair of hand-written offsets is precisely the mistake a verifier
/// cannot see. `main` checks the cursor against the declared length at the end.
fn put_u128(b: &mut [u8], at: &mut usize, v: u128) {
    b[*at..*at + 16].copy_from_slice(&v.to_le_bytes());
    *at += 16;
}

/// Append a little-endian `u32` to the journal. As [`put_u128`].
fn put_u32(b: &mut [u8], at: &mut usize, v: u32) {
    b[*at..*at + 4].copy_from_slice(&v.to_le_bytes());
    *at += 4;
}
