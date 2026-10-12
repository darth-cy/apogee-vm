//! The prover's debug log, behind the `debug-info` cargo feature.
//!
//! **This is the workspace's one cargo feature**: off by default, enabling no
//! dependency, changing no proof byte. It exists for one job: when a proving
//! run fails — or is killed, or hangs — say *where*. `docs/tools.md` §3 is the
//! reading guide.
//!
//! # Why a feature and not an unconditional runtime switch
//!
//! Because the cost is real and unconditional. The log's interesting lines are
//! the **invariant scans**: `self_check` before the backward pass, the forward
//! pass's layer shapes, every multiplicity total. That is work proportional to
//! the shard, and a switch would leave it compiled into every proving run
//! behind a branch. The feature deletes it instead.
//!
//! # Why the level is an environment variable and not a parameter
//!
//! Because the log has no state to thread. Every line is emitted where its
//! subject is already in scope — `family` and `index` inside `gkr_part` — so
//! there is nothing for a `&mut Recorder`
//! equivalent to carry, and adding one would put a parameter on twenty
//! signatures to pass a `u8`. [`config`] reads `APOGEE_DEBUG` on each call and
//! caches nothing: at the granularity these lines sit at — a phase, a shard, a
//! layer — an environment lookup is not measurable against a shard's forward
//! pass. No log site sits inside a trace-sized loop; the scans below are how a
//! per-row fact gets reported without one.
//!
//! # The interface
//!
//! ```text
//! APOGEE_DEBUG=phase    the skeleton: one line per stage of a block
//! APOGEE_DEBUG=detail   and per shard, per family, per channel; runs self_check
//! APOGEE_DEBUG=deep     and per layer
//! APOGEE_DEBUG=off      nothing
//! APOGEE_DEBUG=deep:MUL_DIV,ATOMICS    deep for those families, detail for the rest
//! ```
//!
//! Unset, in a build that has the feature, is [`Level::Phase`]: a reader who
//! compiled the feature in asked for output. An unparsable value complains
//! once on the same stream and falls back to [`Level::Phase`], because a
//! debugging tool that answers a typo with silence is worse than one that
//! answers it with noise.
//!
//! # Why the raw stderr handle and not `eprintln!`
//!
//! `eprintln!` routes through `std::io::set_output_capture`, which is how
//! libtest captures a test's output and prints it **only when that test
//! fails**. The failures this log is for are the ones where no test ever
//! fails: an OOM kill on a 38 GB block, a hang, a `SIGINT` on a run that was
//! going nowhere. Captured output is lost in every one of them. A direct
//! `io::stderr()` write consults no capture, so the last line printed is the
//! last thing that happened — which is the whole design: **a `begin` line
//! with no matching `done` line names the shard that died.**
//!
//! It also makes the stream consistent. Capture is a thread-local, so lines
//! from rayon's workers already bypassed it while the main thread's were held
//! back; a log whose ordering depended on which thread wrote it would be
//! unreadable exactly where it matters, in the parallel shard region.

use std::io::Write;
use std::time::Instant;

use constants::{family, lookup_channel};
use constraints::FamilyCircuit;
use field::Fr;
use program::FamilyId;

/// How much the log says. Ordered: a line at level `L` is emitted when the
/// configured level is at least `L`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Nothing at all.
    Off = 0,
    /// The skeleton: setup, the statement, the commit phase, each shard's
    /// begin and end, each block phase. Tens of lines for a block.
    Phase = 1,
    /// Per shard, per family, per channel — and the invariant scans, which is
    /// where the information is. Also runs [`gkr::self_check`] before the
    /// backward pass, which is the difference between a named relation and a
    /// layer number.
    Detail = 2,
    /// Per GKR layer. Hundreds of lines a shard.
    Deep = 3,
}

impl Level {
    /// The word this level is spelled with.
    fn word(self) -> &'static str {
        match self {
            Level::Off => "off",
            Level::Phase => "phase",
            Level::Detail => "detail",
            Level::Deep => "deep",
        }
    }
}

/// `APOGEE_DEBUG`, parsed: a level, and the families the top level applies to.
///
/// An empty `families` means every family, which is the common case; naming
/// some raises *those* to the parsed level and leaves the rest one step below
/// it, so `deep:MUL_DIV` is the one thing a reader usually wants — everything
/// at `detail`, and the family under suspicion at `deep`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub level: Level,
    pub families: Vec<FamilyId>,
}

impl Config {
    /// The level that applies to `family`: the configured one where no filter
    /// names any family or this one is named, and one step below it otherwise.
    ///
    /// This is the filter's whole meaning, as one pure function, so the tests
    /// exercise the decision itself rather than a copy of it.
    pub fn level_for(&self, family: FamilyId) -> Level {
        if self.families.is_empty() || self.families.contains(&family) {
            return self.level;
        }
        match self.level {
            Level::Deep => Level::Detail,
            Level::Detail => Level::Phase,
            other => other,
        }
    }
}

/// The environment variable. `APOGEE_` as every other switch in this
/// repository spells it (`APOGEE_GUEST_PROFILE`).
pub const VAR: &str = "APOGEE_DEBUG";

/// Parse `APOGEE_DEBUG`'s value. `None` is unset.
///
/// Returns the config and, when the value did not parse, the complaint to
/// print beside it. Split that way so it is a pure function and the test can
/// be a table.
pub fn parse(value: Option<&str>) -> (Config, Option<String>) {
    let every = Config {
        level: Level::Phase,
        families: Vec::new(),
    };
    let text = match value {
        None => return (every, None),
        Some(t) => t.trim(),
    };
    if text.is_empty() {
        return (every, None);
    }
    let (level_word, family_list) = match text.split_once(':') {
        Some((l, f)) => (l.trim(), f),
        None => (text, ""),
    };
    let level = match level_word.to_ascii_lowercase().as_str() {
        "off" | "0" | "none" => Level::Off,
        "phase" | "1" => Level::Phase,
        "detail" | "2" => Level::Detail,
        "deep" | "3" => Level::Deep,
        other => {
            return (
                every,
                Some(format!(
                    "{VAR}: {other:?} is not a level; \
                     expected off | phase | detail | deep, optionally \
                     followed by `:FAMILY,FAMILY`. Using phase"
                )),
            )
        }
    };
    let mut families = Vec::new();
    let mut unknown = Vec::new();
    for name in family_list
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        match family_id(name) {
            Some(f) => families.push(f),
            None => unknown.push(name.to_string()),
        }
    }
    let complaint = if unknown.is_empty() {
        None
    } else {
        Some(format!(
            "{VAR}: {} names no family; the names are the ones this log prints, \
             e.g. MUL_DIV, ATOMICS, ADD_SUB_LUI_AUIPC",
            unknown.join(", ")
        ))
    };
    (Config { level, families }, complaint)
}

/// `APOGEE_DEBUG` as it stands now, and **silently**: reads the environment on
/// every call, caches nothing (see the module docs) and prints no complaint.
///
/// The complaint belongs to [`banner`] and to nowhere else. `enabled` is called
/// once per layer at `deep`, so a complaint here would print a thousand copies
/// of itself and bury the log it was warning about.
pub fn config() -> Config {
    let (config, _) = parse(std::env::var(VAR).ok().as_deref());
    config
}

/// Is a line at `want` emitted, for a line that belongs to no one family?
///
/// The skeleton and the global phases are these: a family filter lowers the
/// *other families*, never the block's own spine, so a reader who asks for
/// `deep:MUL_DIV` still gets every phase line.
pub fn enabled(want: Level) -> bool {
    config().level >= want
}

/// Is a line at `want` emitted for `family`? [`Config::level_for`] is the rule.
pub fn enabled_for(want: Level, family: FamilyId) -> bool {
    config().level_for(family) >= want
}

/// The one header line of a run, and the one place an unparsable
/// `APOGEE_DEBUG` is complained about.
///
/// Called at the top of each entry point that proves a whole execution, so a
/// log pasted into an issue says what it was configured to print and a typo is
/// named once.
pub fn banner(what: &str) {
    let raw = std::env::var(VAR).ok();
    let (config, complaint) = parse(raw.as_deref());
    if let Some(text) = complaint {
        line(&format!("apogee ERROR    {text}"));
    }
    if config.level == Level::Off {
        return;
    }
    let filter = if config.families.is_empty() {
        String::new()
    } else {
        let names: Vec<String> = config.families.iter().map(|f| family_name(*f)).collect();
        format!(" deep-for={}", names.join(","))
    };
    line(&format!(
        "apogee ---------- {what}: {VAR}={}{filter}",
        config.level.word()
    ));
}

/// One line, to the real stderr, with no capture in the way. See the module
/// docs for why this is not `eprintln!`.
pub fn line(text: &str) {
    let mut err = std::io::stderr().lock();
    // A single `write_all` of the line and its newline, so two threads writing
    // at once interleave whole lines rather than halves. The lock makes that
    // true of the handle; building the byte string first makes it true of the
    // write.
    let mut bytes = Vec::with_capacity(text.len() + 1);
    bytes.extend_from_slice(text.as_bytes());
    bytes.push(b'\n');
    let _ = err.write_all(&bytes);
    let _ = err.flush();
}

/// A wall clock for the `ms=` fields: four lines, and the only clock the prover
/// reads. It is not a timing harness — `tools/bench`'s `prove` verb is that,
/// off the prover's `StreamingReport` — and these fields say which shard is
/// slow while it is still running, not what a block cost.
#[derive(Clone, Copy, Debug)]
pub struct Clock(Instant);

impl Clock {
    pub fn start() -> Clock {
        Clock(Instant::now())
    }

    /// Milliseconds since [`Clock::start`], to one decimal.
    pub fn ms(&self) -> String {
        format!("{:.1}", self.0.elapsed().as_secs_f64() * 1000.0)
    }
}

// ---------------------------------------------------------------------------
// Names and short forms: what makes a line readable
// ---------------------------------------------------------------------------

/// A family's name, as `constants::family` spells it.
///
/// A statement's wire forms carry the number; a log a human reads under time
/// pressure prints the name. Appending a family to `constants::family` without
/// appending it here gives `family(<n>)`, which is wrong but not misleading.
pub fn family_name(f: FamilyId) -> String {
    match f {
        family::ADD_SUB_LUI_AUIPC => "ADD_SUB_LUI_AUIPC".to_string(),
        family::JUMP_BRANCH_SLT => "JUMP_BRANCH_SLT".to_string(),
        family::SHIFT_BITWISE => "SHIFT_BITWISE".to_string(),
        family::MUL_DIV => "MUL_DIV".to_string(),
        family::MEM_WORD => "MEM_WORD".to_string(),
        family::MEM_SUBWORD => "MEM_SUBWORD".to_string(),
        family::ATOMICS => "ATOMICS".to_string(),
        family::INIT_TEARDOWN => "INIT_TEARDOWN".to_string(),
        family::ZERO_WINDOWS => "ZERO_WINDOWS".to_string(),
        family::PUBLIC_INPUT => "PUBLIC_INPUT".to_string(),
        family::PUBLIC_OUTPUT => "PUBLIC_OUTPUT".to_string(),
        family::ADVICE_WINDOWS => "ADVICE_WINDOWS".to_string(),
        other => format!("family({other})"),
    }
}

/// [`family_name`] backwards, for the `:FAMILY` filter. Case-insensitive, and
/// a bare number works too.
fn family_id(name: &str) -> Option<FamilyId> {
    let upper = name.to_ascii_uppercase();
    if let Ok(n) = upper.parse::<u32>() {
        return (n < family::COUNT).then_some(n);
    }
    (0..family::COUNT).find(|f| family_name(*f) == upper)
}

/// `FAMILY#index`: the identity every per-shard line carries.
///
/// Every line below `phase` level names its shard this way, without exception.
/// Shards are proved in parallel, so lines from different shards interleave
/// and a line that does not say whose it is says nothing.
pub fn shard(family: FamilyId, index: u32) -> String {
    format!("{}#{index}", family_name(family))
}

/// An `Fr` short enough to read and long enough to compare: the first six and
/// last four digits of [`fr_full`].
///
/// Truncated because the interesting question about a challenge is never its
/// value, it is whether two runs produced the same one.
pub fn fr(x: &Fr) -> String {
    let hex = fr_full(x);
    format!("{}..{}", &hex[..6], &hex[60..])
}

/// A list of `Fr` as [`fr`] does each, at most `max` of them.
pub fn frs(xs: &[Fr], max: usize) -> String {
    let shown: Vec<String> = xs.iter().take(max).map(fr).collect();
    if xs.len() > max {
        format!("[{}, +{}]", shown.join(" "), xs.len() - max)
    } else {
        format!("[{}]", shown.join(" "))
    }
}

/// A height as `2^n`, which is how every spec in this repository writes one.
pub fn height(h: u32) -> String {
    if h.is_power_of_two() {
        format!("2^{}", h.trailing_zeros())
    } else {
        format!("{h}")
    }
}

// ---------------------------------------------------------------------------
// The report builders: one line's worth of a subject, computed where the
// subject is
// ---------------------------------------------------------------------------

/// A registered family's circuit, by the numbers.
///
/// Printed once per family at setup, and it is the reference every later line
/// is read against: a `layer=9` in a failure means nothing until you know the
/// circuit has 41 of them, and a shard whose `live` count is 0 means nothing
/// until you know its height. `checker dump` prints the circuit *readably* and
/// offline; this is the one line that puts it beside the run.
pub fn circuit(c: &FamilyCircuit, h: u32) -> String {
    let a = &c.artifact;
    let channels: Vec<String> = c
        .channels
        .iter()
        .map(|spec| {
            let name = lookup_channel::NAMES
                .get(spec.channel as usize)
                .copied()
                .unwrap_or("?");
            if lookup_channel::IS_RANGE
                .get(spec.channel as usize)
                .copied()
                .unwrap_or(false)
            {
                format!("{name}({})", lookup_channel::BITS[spec.channel as usize])
            } else {
                format!("{name}(table:{})", spec.table.len())
            }
        })
        .collect();
    let gates: usize = a.layers.iter().map(|l| l.producing.len()).sum();
    let enforcing: usize = a.layers.iter().map(|l| l.enforcing.len()).sum();
    format!(
        "h={} vars={} M={} W={} S={} V={} committed={} layers={} gates={}p/{}e \
         rel={} lookups={} chan=[{}] generic={} outputs={}",
        height(h),
        a.trace_vars,
        a.memory.len(),
        a.witness.len(),
        a.setup.len(),
        a.virtuals.len(),
        a.committed().len(),
        a.depth(),
        gates,
        enforcing,
        a.relations.len(),
        a.lookups.len(),
        channels.join(","),
        c.reads_generic_table(),
        a.outputs.len(),
    )
}

/// An `Fr` in full: its 32 canonical bytes as 64 hex digits, **in `to_bytes`
/// order**.
///
/// # Which order, and why it matters
///
/// Bare hex in this log is always a field element's canonical little-endian
/// bytes, which is what the `verifier` CLI takes as its `<identity-hex>`
/// argument and what every wire form in this repository carries
/// (`docs/spec/primitives.md` §1). So a value this log prints can be pasted
/// into the CLI, or grepped against a pinned fixture, without reversing
/// anything.
///
/// In full, not truncated, for the identity, which a reader compares against
/// a **pinned constant** rather than against another run — a run that prints
/// it, every time, shows a stale pin in one line — and for the global digest,
/// where two runs that should agree diverge first.
pub fn fr_full(x: &Fr) -> String {
    x.to_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// A shard-count vector against the families it counts.
pub fn counts(families: &[(FamilyId, u32)], counts: &[u32]) -> String {
    let parts: Vec<String> = families
        .iter()
        .zip(counts)
        .map(|((f, _), n)| format!("{}:{n}", family_name(*f)))
        .collect();
    format!("[{}]", parts.join(" "))
}

/// A `u64` timestamp window as the specs write one.
pub fn ts_window(window: [u64; 2]) -> String {
    format!("[{},{})", window[0], window[1])
}

/// Is every row of a column zero?
///
/// The fingerprint of a fill that wrote nothing — a frame narrower than its
/// family, a selector whose code matched no arm, a value read from the wrong
/// frame word. It is invisible in a proof, which is what makes it worth a line.
/// `O(rows)`, so `Deep` only.
pub fn all_zero(column: &poly::MultilinearPoly) -> bool {
    (0..column.len()).all(|i| column.get(i) == Fr::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_levels_parse_by_word_and_by_number() {
        for (text, want) in [
            ("off", Level::Off),
            ("none", Level::Off),
            ("0", Level::Off),
            ("phase", Level::Phase),
            ("1", Level::Phase),
            ("detail", Level::Detail),
            ("DETAIL", Level::Detail),
            (" deep ", Level::Deep),
            ("3", Level::Deep),
        ] {
            let (c, complaint) = parse(Some(text));
            assert_eq!(c.level, want, "{text}");
            assert!(c.families.is_empty(), "{text}");
            assert!(complaint.is_none(), "{text}: {complaint:?}");
        }
    }

    #[test]
    fn unset_and_empty_are_phase_and_silent() {
        for value in [None, Some(""), Some("   ")] {
            let (c, complaint) = parse(value);
            assert_eq!(c.level, Level::Phase, "{value:?}");
            assert!(complaint.is_none(), "{value:?}");
        }
    }

    /// A typo answers with a complaint and the skeleton, never with silence:
    /// the module docs' rule.
    #[test]
    fn an_unparsable_level_complains_and_falls_back_to_phase() {
        let (c, complaint) = parse(Some("verbose"));
        assert_eq!(c.level, Level::Phase);
        let text = complaint.expect("a complaint");
        assert!(text.contains("verbose"), "{text}");
        assert!(text.contains("detail"), "names the valid words: {text}");
    }

    #[test]
    fn a_family_filter_parses_by_name_and_by_number() {
        let (c, complaint) = parse(Some("deep:mul_div, ATOMICS ,3"));
        assert!(complaint.is_none(), "{complaint:?}");
        assert_eq!(c.level, Level::Deep);
        assert_eq!(
            c.families,
            vec![family::MUL_DIV, family::ATOMICS, family::MUL_DIV]
        );
    }

    #[test]
    fn an_unknown_family_complains_and_keeps_the_level() {
        let (c, complaint) = parse(Some("deep:MUL_DIVV"));
        assert_eq!(c.level, Level::Deep);
        assert!(c.families.is_empty());
        let text = complaint.expect("a complaint");
        assert!(text.contains("MUL_DIVV"), "{text}");
    }

    /// The filter's whole point: the named family is at the configured level
    /// and every other family is one step below it. `level_for` is the rule,
    /// so this test calls it rather than restating it.
    #[test]
    fn a_named_family_is_one_level_deeper_than_the_rest() {
        let (c, _) = parse(Some("deep:ATOMICS"));
        assert_eq!(c.level_for(family::ATOMICS), Level::Deep);
        assert_eq!(c.level_for(family::MUL_DIV), Level::Detail);

        let (c, _) = parse(Some("detail:MUL_DIV"));
        assert_eq!(c.level_for(family::MUL_DIV), Level::Detail);
        assert_eq!(c.level_for(family::ATOMICS), Level::Phase);

        // No filter: every family is at the configured level.
        let (c, _) = parse(Some("deep"));
        assert_eq!(c.level_for(family::ATOMICS), Level::Deep);
        assert_eq!(c.level_for(family::ADD_SUB_LUI_AUIPC), Level::Deep);

        // `off` stays off for every family, named or not: a filter raises
        // nothing above the configured level.
        let (c, _) = parse(Some("off:ATOMICS"));
        assert_eq!(c.level_for(family::ATOMICS), Level::Off);
        assert_eq!(c.level_for(family::MUL_DIV), Level::Off);
    }

    #[test]
    fn every_registered_family_has_a_name_and_round_trips() {
        for f in 0..family::COUNT {
            let name = family_name(f);
            assert!(
                !name.starts_with("family("),
                "family {f} has no name in the debug log"
            );
            assert_eq!(family_id(&name), Some(f), "{name} does not round-trip");
            assert_eq!(family_id(&name.to_ascii_lowercase()), Some(f));
        }
        assert_eq!(family_id("nonsense"), None);
        assert_eq!(family_id(&family::COUNT.to_string()), None);
    }

    #[test]
    fn a_full_fr_is_every_digit_and_a_short_one_is_not() {
        assert_eq!(fr_full(&Fr::ONE).len(), 64);
        assert!(fr(&Fr::ONE).len() < 20);
    }

    /// The order is `to_bytes`', so a printed value pastes into the `verifier`
    /// CLI and greps against a pinned fixture. `fr_full` is the full canonical
    /// encoding of the same bytes, and this holds the two equal by
    /// construction.
    #[test]
    fn a_field_element_prints_in_to_bytes_order() {
        for x in [Fr::ZERO, Fr::ONE, Fr::MINUS_ONE, Fr::from_u64(1 << 40)] {
            let want: String = x.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(fr_full(&x), want);
        }
        // `Fr::ONE` is 1, whose canonical little-endian bytes begin 01.
        assert!(fr_full(&Fr::ONE).starts_with("01"), "{}", fr_full(&Fr::ONE));
        assert_eq!(fr(&Fr::ZERO), "000000..0000");
        // Distinct values stay distinguishable in the short form, which is the
        // only property the log needs of it.
        assert_ne!(fr(&Fr::from_u64(1)), fr(&Fr::from_u64(2)));
    }

    #[test]
    fn a_height_reads_as_a_power_of_two() {
        assert_eq!(height(1 << 20), "2^20");
        assert_eq!(height(1 << 8), "2^8");
        assert_eq!(height(3), "3");
    }
}
