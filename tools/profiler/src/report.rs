//! The profile as a report: one flat `serde` struct for a machine, and a plain
//! table for a reader.
//!
//! The conventions are `tools/bench`': a flat struct, `serde_json`'s pretty
//! printer, and a hand-written table of `name  value` rows. Every number is a
//! count of cycles on one execution of one image; nothing here is a threshold
//! and nothing is asserted.

use serde::{Deserialize, Serialize};

use crate::categories::Category;
use crate::Profile;

/// One workload's share.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CategoryRow {
    pub category: String,
    pub cycles: u64,
    /// Percent of the execution's cycles.
    pub share: f64,
    /// Calls into the functions of this category, entry-count summed.
    pub calls: u64,
}

/// One function's share.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct FuncRow {
    pub path: String,
    pub category: String,
    pub cycles: u64,
    pub share: f64,
    pub calls: u64,
    /// `cycles / calls`, or 0 where the entry never ran — which happens when
    /// control only ever enters the function past its first instruction.
    pub cycles_per_call: f64,
}

/// One execution's profile, flat.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProfileReport {
    /// What was profiled: a label the caller chose.
    pub label: String,
    /// The guest binary's name.
    pub guest: String,

    pub guest_cycles: u64,
    pub exit_code: i32,
    pub journal_bytes: usize,

    /// Cycles per family, by name, in family order.
    pub families: Vec<(String, u64)>,
    /// Cycles per workload, descending.
    pub categories: Vec<CategoryRow>,
    /// The functions with the most cycles, descending.
    pub top_functions: Vec<FuncRow>,
    /// Cycles per instruction mnemonic, descending.
    pub mnemonics: Vec<(String, u64)>,
    /// Cycles at a pc no function symbol claims, and its share.
    pub unattributed_cycles: u64,
    pub unattributed_share: f64,
    /// How many function symbols the ELF carried, and what fraction of `.text`
    /// they covered: the honesty check on every number above.
    pub function_symbols: usize,
}

fn share(part: u64, whole: u64) -> f64 {
    match whole {
        0 => 0.0,
        _ => 100.0 * part as f64 / whole as f64,
    }
}

impl ProfileReport {
    /// The report of `profile`, with `top` functions listed.
    pub fn of(label: &str, guest: &str, profile: &Profile, top: usize) -> ProfileReport {
        let total = profile.cycles;
        let categories: Vec<CategoryRow> = {
            let mut rows: Vec<CategoryRow> = profile
                .by_category()
                .into_iter()
                .map(|(c, cycles, calls)| CategoryRow {
                    category: c.name().to_string(),
                    cycles,
                    share: share(cycles, total),
                    calls,
                })
                .collect();
            rows.sort_by_key(|r| std::cmp::Reverse(r.cycles));
            rows
        };
        let top_functions: Vec<FuncRow> = profile
            .funcs
            .iter()
            .filter(|f| f.cycles > 0)
            .take(top)
            .map(|f| FuncRow {
                path: f.path.clone(),
                category: f.category.name().to_string(),
                cycles: f.cycles,
                share: share(f.cycles, total),
                calls: f.calls,
                cycles_per_call: match f.calls {
                    0 => 0.0,
                    n => f.cycles as f64 / n as f64,
                },
            })
            .collect();
        ProfileReport {
            label: label.to_string(),
            guest: guest.to_string(),
            guest_cycles: total,
            exit_code: profile.execution.exit_code,
            journal_bytes: profile.execution.io.output.len(),
            families: profile
                .profile
                .counts
                .iter()
                .map(|(f, n)| (program::family_name(*f).to_string(), *n))
                .collect(),
            categories,
            top_functions,
            mnemonics: profile.mnemonics.clone(),
            unattributed_cycles: profile.unclaimed,
            unattributed_share: share(profile.unclaimed, total),
            function_symbols: profile.funcs.len(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a flat report serializes") + "\n"
    }

    /// The human half.
    pub fn to_table(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let row = |out: &mut String, name: &str, value: String| {
            let _ = writeln!(out, "  {name:<28} {value}");
        };
        let cyc = |n: u64, s: f64| format!("{n:>14}  {s:>6.2}%");

        let _ = writeln!(out, "workload");
        row(&mut out, "label", self.label.clone());
        row(&mut out, "guest", self.guest.clone());
        row(&mut out, "guest cycles", self.guest_cycles.to_string());
        row(
            &mut out,
            "exit status",
            match self.exit_code {
                0 => "0".to_string(),
                // The guest SDK's own statuses, named: an execution that ran and
                // could not *publish* is a complete profile, and reading `70` as
                // a failed execution would be wrong.
                70 => "70  the journal does not fit its window; every cycle below \
                       was run"
                    .to_string(),
                71 => "71  the guest's heap is exhausted".to_string(),
                101 => "101 the guest panicked".to_string(),
                other => other.to_string(),
            },
        );
        row(&mut out, "journal bytes", self.journal_bytes.to_string());
        row(
            &mut out,
            "function symbols",
            self.function_symbols.to_string(),
        );

        let _ = writeln!(out, "\ncycles by workload");
        for c in &self.categories {
            if c.cycles == 0 {
                continue;
            }
            row(&mut out, &c.category, cyc(c.cycles, c.share));
        }

        let _ = writeln!(out, "\ncycles by family");
        for (family, n) in &self.families {
            if *n == 0 {
                continue;
            }
            row(&mut out, family, n.to_string());
        }

        let _ = writeln!(out, "\ntop functions");
        for f in &self.top_functions {
            let _ = writeln!(
                out,
                "  {:>12}  {:>6.2}%  {:>9} calls  {:>10.1} c/call  {}  [{}]",
                f.cycles, f.share, f.calls, f.cycles_per_call, f.path, f.category
            );
        }

        let _ = writeln!(out, "\ncycles by mnemonic");
        for (name, n) in self.mnemonics.iter().take(24) {
            row(&mut out, name, cyc(*n, share(*n, self.guest_cycles)));
        }

        let _ = writeln!(
            out,
            "\nMachine-independent: every number is a count of executed cycles on one \
             image.\nA function's cycles include everything the compiler inlined into it \
             (docs/tools.md §2.2)."
        );
        out
    }
}

/// Every category a report lists, for a test that wants the set.
pub fn category_names() -> Vec<&'static str> {
    Category::ALL.iter().map(|c| c.name()).collect()
}
