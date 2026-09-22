//! The `ecrecover` group: the committed secp256k1 recovery corpus.
//!
//! `crates/program/tests/vectors/ecrecover.txt`. Every line is one call of the
//! EVM's `0x01` precompile — `(h, v, r, s)` in, a public key or a failure out
//! — and the answers come from **`libsecp256k1`**, a dev-dependency reference
//! implementation, never from `program::secp256k1` (master rule 10).
//!
//! The corpus is the stage prompt's acceptance 3 list, case by case:
//!
//! | case | what it pins |
//! | --- | --- |
//! | `sign_*` | RFC 6979 signatures under five distinct keys, both `v` values |
//! | `high_s_*` | `s > n/2`, **accepted**: the low-s rule is EIP-2's, a transaction-signature rule, and the precompile passes `homestead = false` |
//! | `r_one`, `s_one`, `s_n_minus_1` | `r` and `s` at the ends of their range |
//! | `hash_ge_n` | a hash at or above `n`, which is reduced and not an error |
//! | `fail_*` | `v` out of range, `r` or `s` out of range, and an `r` whose `x` is on no curve point |
//!
//! **`r = n - 1` is a failure, not a pass.** The prompt lists `r` at `n-1`
//! among the accepted inputs; `(n-1)^3 + 7` is a quadratic non-residue mod `p`,
//! so no curve point has that `x` and the precompile returns empty. It is in
//! the failing set below and `docs/handoff/S22-ecrecover.md` records why.
//!
//! **A high-s line is checked twice.** Its key is the oracle's, like every
//! other line's, *and* it is asserted equal to its low-s twin's by the
//! malleability identity: if `(r, s, v)` recovers `Q` then so does
//! `(r, n - s, v ^ 1)`, because `R' = -R` and `(-s)(-R) = sR`. So the corpus
//! pins both that the oracle accepts `s > n/2` -- it does; the low-s rule is
//! EIP-2's and this precompile does not carry it -- and that it accepts it
//! with the answer the algebra says.

use constants::secp256k1 as k;
use program::secp256k1 as s2;
use test_support::to_hex;

use crate::write_vectors;

/// keccak256, from the `tiny-keccak` oracle: the address is
/// `keccak256(x || y)[12..]`, and the guest shim derives it through
/// `guest_sdk::keccak256`, so the corpus carries what the EVM would return.
fn keccak256(input: &[u8]) -> [u8; 32] {
    use tiny_keccak::Hasher;
    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(input);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// One corpus line.
struct Case {
    name: String,
    hash: [u8; 32],
    v: u32,
    r: [u8; 32],
    s: [u8; 32],
    /// The uncompressed public key's coordinates, or `None` for a failure.
    key: Option<([u8; 32], [u8; 32])>,
}

/// The oracle's recovery, or `None` where it refuses.
fn oracle(hash: &[u8; 32], v: u32, r: &[u8; 32], s: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    if !(27..=28).contains(&v) {
        return None;
    }
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(r);
    sig[32..].copy_from_slice(s);
    let signature = libsecp256k1::Signature::parse_standard(&sig).ok()?;
    let message = libsecp256k1::Message::parse(hash);
    let recovery = libsecp256k1::RecoveryId::parse((v - 27) as u8).ok()?;
    let key = libsecp256k1::recover(&message, &signature, &recovery).ok()?;
    // 65 bytes: the 0x04 tag, then x and y. The EVM's address is
    // keccak256 of the 64 bytes after the tag, which is the shim's job.
    let bytes = key.serialize();
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..65]);
    Some((x, y))
}

/// A deterministic 32-byte value from a label, so the corpus is reproducible
/// without a random source.
fn seeded(label: &str) -> [u8; 32] {
    test_support::sha256(label.as_bytes())
}

/// A signature under a seeded key, and the key it recovers to.
///
/// The signature is *built* here rather than asked of the oracle: signing
/// needs RFC 6979, which needs `libsecp256k1`'s `hmac` feature and with it
/// `sha2`, `hmac-drbg` and `typenum` in the workspace graph. It buys nothing —
/// the oracle's job is the **recovery**, which is what this stage builds — and
/// the cross-check is as strong either way: the key the oracle recovers is
/// compared with the oracle's *own* `PublicKey::from_secret_key`, so a wrong
/// scalar multiplication here produces a signature that recovers to the wrong
/// key and the assertion fires.
fn signed(label: &str) -> Case {
    let secret_bytes = seeded(&format!("apogee/s22/key/{label}"));
    let secret = libsecp256k1::SecretKey::parse(&secret_bytes).expect("a valid secret key");
    let hash = seeded(&format!("apogee/s22/msg/{label}"));
    let d = s2::from_be_bytes(&secret_bytes);
    let e = s2::rem(&s2::from_be_bytes(&hash), &k::N);

    // A nonce, rejected until the signature is canonical and low-s: a high-s
    // one is covered by `malleable` below, deliberately and by construction.
    let mut attempt = 0u32;
    let (r, s, v) = loop {
        let nonce_bytes = seeded(&format!("apogee/s22/nonce/{label}/{attempt}"));
        attempt += 1;
        let nonce = s2::rem(&s2::from_be_bytes(&nonce_bytes), &k::N);
        if s2::is_zero(&nonce) {
            continue;
        }
        let point = s2::joint_mul(&nonce, &s2::ZERO, &s2::generator());
        assert!(
            !point.infinity,
            "a nonzero scalar times G is not the identity"
        );
        // r = R.x mod n. R.x is below p, which exceeds n, so the reduction is
        // real and a signature whose r wrapped is one recovery cannot undo.
        let r = s2::rem(&point.x, &k::N);
        if s2::is_zero(&r) || !s2::less(&point.x, &k::N) {
            continue;
        }
        let k_inv = s2::invmod(&nonce, &k::N).expect("a nonzero nonce");
        let s = s2::mulmod(
            &k_inv,
            &s2::addmod(&e, &s2::mulmod(&r, &d, &k::N), &k::N),
            &k::N,
        );
        if s2::is_zero(&s) || !s2::less(&s, &half_n()) {
            continue;
        }
        break (r, s, 27 + (point.y[0] & 1) as u32);
    };

    let r = s2::to_be_bytes(&r);
    let s = s2::to_be_bytes(&s);
    let key = oracle(&hash, v, &r, &s).expect("a canonical low-s signature recovers");
    // And it recovers the signer's own key, which is what makes this a
    // signature and not a pair of numbers -- and is the cross-check that the
    // scalar multiplication above was right.
    let public = libsecp256k1::PublicKey::from_secret_key(&secret).serialize();
    assert_eq!(key.0, public[1..33], "{label}: the recovered x");
    assert_eq!(key.1, public[33..65], "{label}: the recovered y");
    Case {
        name: format!("sign_{label}"),
        hash,
        v,
        r,
        s,
        key: Some(key),
    }
}

/// `(r, n - s, v ^ 1)`, the high-s half of the corpus, which recovers the same
/// key as `(r, s, v)`. The oracle answers it and the answer is asserted equal
/// to the twin's, so the line pins both the acceptance and the algebra.
fn malleable(base: &Case) -> Case {
    let s = s2::from_be_bytes(&base.s);
    let flipped = s2::submod(&s2::ZERO, &s, &k::N);
    assert!(!s2::is_zero(&flipped), "s is not 0");
    let half = half_n();
    assert!(!s2::less(&flipped, &half), "the twin's s is above n/2");
    assert!(s2::less(&s, &half), "the base's s is below n/2");
    let v = if base.v == 27 { 28 } else { 27 };
    let s_bytes = s2::to_be_bytes(&flipped);
    let key = oracle(&base.hash, v, &base.r, &s_bytes);
    assert_eq!(
        key, base.key,
        "{}: a high-s signature recovers its twin's key",
        base.name
    );
    assert!(key.is_some(), "{}: the oracle accepts s > n/2", base.name);
    Case {
        name: format!("high_s_{}", base.name.trim_start_matches("sign_")),
        hash: base.hash,
        v,
        r: base.r,
        s: s_bytes,
        key,
    }
}

/// `n / 2`, rounded down.
fn half_n() -> s2::U256 {
    let mut out = s2::ZERO;
    for (i, limb) in out.iter_mut().enumerate() {
        *limb = k::N[i] >> 1;
        if i + 1 < k::LIMBS {
            *limb |= k::N[i + 1] << 63;
        }
    }
    out
}

/// A case whose `(h, v, r, s)` are given and whose answer is the oracle's,
/// whatever it is.
fn probe(name: &str, hash: s2::U256, v: u32, r: s2::U256, s: s2::U256) -> Case {
    let hash = s2::to_be_bytes(&hash);
    let r = s2::to_be_bytes(&r);
    let s = s2::to_be_bytes(&s);
    Case {
        name: name.to_string(),
        hash,
        v,
        r,
        s,
        key: oracle(&hash, v, &r, &s),
    }
}

fn u256(v: u64) -> s2::U256 {
    [v, 0, 0, 0]
}

/// The whole corpus, in file order.
fn corpus() -> Vec<Case> {
    let mut cases = Vec::new();
    let signed: Vec<Case> = ["alpha", "beta", "gamma", "delta", "epsilon"]
        .iter()
        .map(|label| signed(label))
        .collect();
    // Both recovery ids must appear among the signatures, or the corpus does
    // not cover `v = 27` and `v = 28` as the prompt requires.
    assert!(
        signed.iter().any(|c| c.v == 27),
        "some signature has v = 27"
    );
    assert!(
        signed.iter().any(|c| c.v == 28),
        "some signature has v = 28"
    );
    for case in &signed {
        cases.push(malleable(case));
    }
    cases.splice(0..0, signed);

    let n_minus_1 = s2::sub(&k::N, &s2::ONE).0;
    // `r` and `s` at the ends of their range. `x = 1` is on the curve
    // (`1 + 7 = 8` is a residue mod p), so these recover rather than fail.
    cases.push(probe("r_one", seeded_u256("r_one"), 27, s2::ONE, s2::ONE));
    cases.push(probe(
        "r_one_v28",
        seeded_u256("r_one"),
        28,
        s2::ONE,
        s2::ONE,
    ));
    cases.push(probe(
        "s_n_minus_1",
        seeded_u256("s_end"),
        27,
        s2::ONE,
        n_minus_1,
    ));
    // A hash at or above n is reduced, not refused.
    cases.push(probe("hash_ge_n", k::N, 27, s2::ONE, s2::ONE));
    cases.push(probe(
        "hash_p_minus_1",
        s2::sub(&k::P, &s2::ONE).0,
        28,
        s2::ONE,
        s2::ONE,
    ));

    // The three failures the prompt names, plus the ones beside them.
    cases.push(probe(
        "fail_r_zero",
        seeded_u256("f1"),
        27,
        s2::ZERO,
        s2::ONE,
    ));
    cases.push(probe(
        "fail_s_zero",
        seeded_u256("f2"),
        27,
        s2::ONE,
        s2::ZERO,
    ));
    cases.push(probe("fail_r_eq_n", seeded_u256("f3"), 27, k::N, s2::ONE));
    cases.push(probe("fail_s_eq_n", seeded_u256("f4"), 27, s2::ONE, k::N));
    // `x = 5`: `5^3 + 7 = 132`, a quadratic non-residue mod p, so no curve
    // point has it.
    cases.push(probe(
        "fail_no_curve_point",
        seeded_u256("f5"),
        27,
        u256(5),
        s2::ONE,
    ));
    // And `r = n - 1`, which the prompt lists among the *passing* inputs and
    // is not one: `(n-1)^3 + 7` is a non-residue too.
    cases.push(probe(
        "fail_r_n_minus_1",
        seeded_u256("f6"),
        27,
        n_minus_1,
        s2::ONE,
    ));
    // A wrong recovery id for an otherwise-valid signature. The prompt says
    // this "fails or gives a wrong address per the reference; match the
    // oracle" — so the corpus records whichever the oracle says, and
    // `probe` does not care which it is.
    let (h0, v0, r0, s0) = (
        s2::from_be_bytes(&cases[0].hash),
        cases[0].v,
        s2::from_be_bytes(&cases[0].r),
        s2::from_be_bytes(&cases[0].s),
    );
    let wrong_id = if v0 == 27 { 28 } else { 27 };
    cases.push(probe("wrong_recovery_id", h0, wrong_id, r0, s0));
    // `v` outside {27, 28} at all.
    for v in [0u32, 1, 26, 29, 31] {
        cases.push(probe(&format!("fail_v_{v}"), h0, v, r0, s0));
    }
    cases
}

fn seeded_u256(label: &str) -> s2::U256 {
    // Reduced below n so the value is a legal scalar wherever one is wanted.
    s2::rem(&s2::from_be_bytes(&seeded(label)), &k::N)
}

/// The fixture's one relative path and its contents.
fn fixture() -> (&'static str, String) {
    let mut text = String::new();
    text.push_str(
        "# the secp256k1 ecrecover corpus, from the `libsecp256k1` dev-dependency oracle\n\
         # docs/spec/ecrecover.md \u{00a7}1 is normative for the semantics\n\
         # name v hash r s outcome pubkey_x pubkey_y address\n\
         # every 256-bit field is 64 hex digits, big-endian, the EVM's encoding\n\
         # outcome is `ok` with a key and the 20-byte address keccak256(x || y)[12..],\n\
         # or `fail` with three `-`\n",
    );
    for case in corpus() {
        let (outcome, x, y, address) = match case.key {
            Some((x, y)) => {
                let mut serialized = [0u8; 64];
                serialized[..32].copy_from_slice(&x);
                serialized[32..].copy_from_slice(&y);
                let digest = keccak256(&serialized);
                ("ok", to_hex(&x), to_hex(&y), to_hex(&digest[12..]))
            }
            None => ("fail", "-".to_string(), "-".to_string(), "-".to_string()),
        };
        text.push_str(&format!(
            "{} {} {} {} {} {} {} {} {}\n",
            case.name,
            case.v,
            to_hex(&case.hash),
            to_hex(&case.r),
            to_hex(&case.s),
            outcome,
            x,
            y,
            address
        ));
    }
    ("crates/program/tests/vectors/ecrecover.txt", text)
}

/// The schedule's virtual columns as committed Rust source.
///
/// `constraints::ecrecover::tables::derive` is the definition; this writes it
/// out so that `gkr_verify::virtual_at_row` can read a table entry without
/// rebuilding the 3,779-step program, which it would otherwise do once per row
/// per column. The file is source rather than a `tests/vectors` fixture
/// because the engine links it, and the recursion guest links the engine
/// (`docs/spec/ecrecover.md` §6.2).
///
/// It is **generated and diffed** like every other fixture: `kat-gen --
/// ecrecover` rewrites it, CI regenerates and diffs, and
/// `crates/constraints/tests/tables.rs` holds it equal to `derive`'s output
/// inside `cargo test --workspace`, so a schedule edited without regenerating
/// fails fast rather than silently building a circuit against stale constants.
fn schedule_data() -> (&'static str, String) {
    use constraints::ecrecover::tables::{derive, id, MODAL};
    let sparse = derive();
    let total: usize = sparse.iter().map(|t| t.len()).sum();

    let mut out = String::new();
    for line in [
        r#"//! The step schedule's virtual columns, generated."#,
        r#"//!"#,
        r#"//! Written by `cargo run -p kat-gen -- ecrecover` from"#,
        r#"//! `constraints::ecrecover::tables::derive`, which is the definition."#,
        r#"//! Do not edit by hand: `crates/constraints/tests/tables.rs` holds this"#,
        r#"//! equal to `derive`'s output, so a hand edit fails the workspace run."#,
        r#"//!"#,
        r#"//! Each table is stored as the `(step, value - MODAL[k])` pairs where"#,
        r#"//! that difference is not zero, ascending by step. A zero entry costs"#,
        r#"//! nothing in the extension's sum, which is what keeps the schedule"#,
        r#"//! affordable in a `no_std` crate the recursion guest links."#,
        r#""#,
    ] {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(&format!(
        "/// Every schedule table, sparse: {total} pairs against {} dense.\n",
        id::COUNT * constants::ecrecover::ROWS_PER_INVOCATION
    ));
    // `rustfmt::skip`, because `cargo fmt --all` would otherwise rewrap this
    // array and the file would no longer be what the generator writes --
    // which is the equality the test below and CI's regenerate-and-diff both
    // rest on.
    out.push_str("#[rustfmt::skip]\n");
    out.push_str(&format!(
        "pub const SPARSE: [&[(u16, i128)]; {}] = [\n",
        id::COUNT
    ));
    for (k, table) in sparse.iter().enumerate() {
        out.push_str(&format!(
            "    // table {k}, modal {}, {} pairs\n    &[",
            MODAL[k],
            table.len()
        ));
        for (i, (step, value)) in table.iter().enumerate() {
            if i % 8 == 0 {
                out.push_str("\n        ");
            }
            out.push_str(&format!("({step}, {value}), "));
        }
        if !table.is_empty() {
            out.push('\n');
            out.push_str("    ");
        }
        out.push_str("],\n");
    }
    out.push_str("];\n");
    ("crates/constraints/src/ecrecover/schedule_data.rs", out)
}

pub fn generate() {
    let (path, text) = fixture();
    write_vectors(path, &text);
    let (path, text) = schedule_data();
    write_vectors(path, &text);
}

#[cfg(test)]
mod tests {
    /// The corpus the generator writes is the corpus the file holds: a
    /// fixture whose generator has drifted is a fixture that proves nothing.
    #[test]
    fn the_fixture_is_what_the_generator_writes() {
        let (path, text) = super::fixture();
        let full = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        let on_disk = std::fs::read_to_string(full).expect("the committed file");
        assert_eq!(
            on_disk, text,
            "{path} is stale: rerun `kat-gen -- ecrecover`"
        );
    }

    /// The generated schedule columns are what the generator writes, for the
    /// same reason -- and this one is **source the engine links**, so a stale
    /// copy is a circuit built against constants the program no longer has.
    #[test]
    fn the_schedule_columns_are_what_the_generator_writes() {
        let (path, text) = super::schedule_data();
        let full = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        let on_disk = std::fs::read_to_string(full).expect("the committed file");
        assert_eq!(
            on_disk, text,
            "{path} is stale: rerun `kat-gen -- ecrecover`"
        );
    }
}
