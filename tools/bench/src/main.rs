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

mod block;
mod fr_arith;
mod gkr_prove;
mod mercury;
mod mercury_batch;
mod msm;
mod poly_bind;
mod recurse;
mod report;
mod square;
mod timing;
mod zerocheck_prove;
mod zerocheck_verify;

/// Every routine: selector, one line of what it measures, and the entry point.
/// The order here is the order a bare `cargo run` runs them in.
const ROUTINES: [(&str, &str, fn()); 8] = [
    (
        "fr-arith",
        "Fr mul, square, inverse and batch inverse against ark-bn254",
        fr_arith::run,
    ),
    (
        "poly-bind",
        "lift plus the full bind chain of a u32 column at 2^20",
        poly_bind::run,
    ),
    (
        "msm",
        "MSM at 2^22 over ceremony bases, against ark-bn254",
        msm::run,
    ),
    (
        "mercury",
        "Mercury commit, open and verify at 2^22 over ceremony bases",
        mercury::run,
    ),
    (
        "mercury-batch",
        "16 x 2^20 columns as one batch, then as 16 single openings",
        mercury_batch::run,
    ),
    (
        "zerocheck-prove",
        "zerocheck prove wall-clock and peak polynomial memory at 2^20",
        zerocheck_prove::run,
    ),
    (
        "zerocheck-verify",
        "sumcheck verification against naive verification at 2^22",
        zerocheck_verify::run,
    ),
    (
        "gkr-prove",
        "GKR forward, self_check, prove and verify over a 339-gate circuit at 2^18",
        gkr_prove::run,
    ),
];

fn usage() {
    println!("usage: cargo run --release -p bench [-- <routine>...]");
    println!("With no routine, every routine runs in the order listed.\n");
    let width = ROUTINES.iter().map(|r| r.0.len()).max().unwrap_or(0);
    for (name, what, _) in ROUTINES {
        println!("  {name:width$}  {what}");
    }
    println!("\nAnd verbs, which take arguments of their own:\n");
    println!("{}", block::usage());
    println!("{}", recurse::usage());
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // One verb, and it takes arguments: a proving job has to be told which
    // block and what the hardware costs, which the routine table's `fn()` has
    // nowhere to put. It is matched before the table rather than added to it,
    // so the eight routines keep their signature.
    // Four more: a recursion tree, one node of it, its decider's key and its
    // root's decision (`recurse.rs`).
    let recursion = match args.first().map(String::as_str) {
        Some("recurse") => Some(recurse::run(&args[1..])),
        Some("recurse-node") => Some(recurse::node(&args[1..])),
        Some("ceremony") => Some(recurse::ceremony(&args[1..])),
        Some("decide") => Some(recurse::decide(&args[1..])),
        _ => None,
    };
    if let Some(result) = recursion {
        if let Err(why) = result {
            eprintln!("bench: {why}\n\n{}", recurse::usage());
            std::process::exit(1);
        }
        return;
    }

    if args.first().map(String::as_str) == Some("prove") {
        match block::parse(&args[1..]) {
            Ok(options) => {
                if let Err(why) = block::run(&options) {
                    eprintln!("prove: {why}");
                    std::process::exit(1);
                }
            }
            Err(why) => {
                eprintln!("bench: {why}\n");
                usage();
                std::process::exit(2);
            }
        }
        println!("\nMachine-dependent; internal use only.");
        return;
    }

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
