//! The benchmark harness. One routine per thing worth measuring, each runnable
//! on its own.
//!
//!     cargo run --release -p bench                        # every routine
//!     cargo run --release -p bench -- zerocheck-verify    # just this one
//!     cargo run --release -p bench -- --list
//!
//! Routines are independent: each builds its own data from its own stream off
//! the one seed, prints its own table, and shares nothing but the timing
//! helpers. Running one alone gives the same number as running it with the
//! others. That matters because the setup costs are not small — the zerocheck
//! routines each spend seconds digesting a 2^20-row witness before they measure
//! anything — and there is no reason to pay for a routine you did not ask for.
//!
//! Numbers are internal only. Machine-dependent; make no public claims.

mod fr_arith;
mod mercury;
mod msm;
mod poly_bind;
mod square;
mod timing;
mod zerocheck_prove;
mod zerocheck_verify;

/// Every routine: selector, one line of what it measures, and the entry point.
/// The order here is the order a bare `cargo run` runs them in.
const ROUTINES: [(&str, &str, fn()); 6] = [
    (
        "fr-arith",
        "S01: Fr mul, square, inverse and batch inverse against ark-bn254",
        fr_arith::run,
    ),
    (
        "poly-bind",
        "S03: lift plus the full bind chain of a u32 column at 2^20",
        poly_bind::run,
    ),
    (
        "msm",
        "S07 acceptance 9 and 10: MSM at 2^22 over ceremony bases, against ark-bn254",
        msm::run,
    ),
    (
        "mercury",
        "S08 acceptance 11: Mercury commit, open and verify at 2^22 over ceremony bases",
        mercury::run,
    ),
    (
        "zerocheck-prove",
        "S04: prove wall-clock and peak polynomial memory at 2^20",
        zerocheck_prove::run,
    ),
    (
        "zerocheck-verify",
        "S04: sumcheck verification against naive verification at 2^20",
        zerocheck_verify::run,
    ),
];

fn usage() {
    println!("usage: cargo run --release -p bench [-- <routine>...]");
    println!("With no routine, every routine runs in the order listed.\n");
    let width = ROUTINES.iter().map(|r| r.0.len()).max().unwrap_or(0);
    for (name, what, _) in ROUTINES {
        println!("  {name:width$}  {what}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args
        .iter()
        .any(|a| a == "--list" || a == "--help" || a == "-h")
    {
        usage();
        return;
    }

    let selected: Vec<(&str, &str, fn())> = if args.is_empty() {
        ROUTINES.to_vec()
    } else {
        let mut v = Vec::new();
        for name in &args {
            match ROUTINES.iter().find(|r| r.0 == name) {
                Some(r) => v.push(*r),
                None => {
                    eprintln!("bench: no routine named `{name}`\n");
                    usage();
                    std::process::exit(2);
                }
            }
        }
        v
    };

    for (i, (name, _, run)) in selected.into_iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("=== {name} ===");
        run();
    }

    println!("\nMachine-dependent; internal use only.");
}
