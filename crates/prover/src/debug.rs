//! The prover's debug log, behind the `debug-info` cargo feature.
//!
//! **This is the workspace's second cargo feature**, and the second and last
//! exception to master anti-goal 1 (owner's decision, this stage). It exists
//! for one job: when a deferred prover suite fails — or is killed, or hangs —
//! say *where*. `docs/tools.md` §3 is the reading guide.
//!
//! # Why a feature and not an unconditional runtime switch
//!
//! Because the cost is real and unconditional. The log's interesting lines are
//! the **invariant scans**: every live row of a delegation shard checked against
//! its modulus, every anchor's three zeroings, every multiplicity total. That
//! is work proportional to the shard, and a switch would leave it compiled
//! into every proving run behind a branch. The feature deletes it instead.
//!
//! # Why the level is an environment variable and not a parameter
//!
//! Because the log has no state to thread. Every line is emitted where its
//! subject is already in scope — `family` and `index` inside `gkr_part`, the
//! frame words inside `mod_mul` — so there is nothing for a `&mut Recorder`
//! equivalent to carry, and adding one would put a parameter on twenty
//! signatures to pass a `u8`. [`level`] reads `APOGEE_DEBUG` on each call and
//! caches nothing: master anti-goal 7 bans the `OnceLock` that would, and at
//! the granularity these lines sit at — a phase, a shard, a layer — an
//! environment lookup is not measurable against a shard's forward pass. No
//! log site may sit inside a trace-sized loop; §3 of the spec is the rule and
//! the scans below are how a per-row fact gets reported without one.
//!
//! # The interface
//!
//! ```text
//! APOGEE_DEBUG=phase    the skeleton: one line per stage of a block
//! APOGEE_DEBUG=detail   and per shard, per family, per channel; runs self_check
//! APOGEE_DEBUG=deep     and per layer, per invocation sample
//! APOGEE_DEBUG=off      nothing
//! APOGEE_DEBUG=deep:EC_ADD,MOD_MUL    deep for those families, detail for the rest
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
    /// Per GKR layer, per sampled invocation. Hundreds of lines a shard.
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
/// it, so `deep:EC_ADD` is the one thing a reader usually wants — everything
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
             e.g. EC_ADD, MOD_MUL, ADD_SUB_LUI_AUIPC",
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
/// `deep:EC_ADD` still gets every phase line.
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
/// off the `TraceArchive`'s own phase sections — and these fields say which
/// shard is slow while it is still running, not what a block cost.
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
        family::KECCAK_F => "KECCAK_F".to_string(),
        family::POSEIDON2 => "POSEIDON2".to_string(),
        family::FR_ARITH => "FR_ARITH".to_string(),
        family::PUBLIC_INPUT => "PUBLIC_INPUT".to_string(),
        family::PUBLIC_OUTPUT => "PUBLIC_OUTPUT".to_string(),
        family::ADVICE_WINDOWS => "ADVICE_WINDOWS".to_string(),
        family::MOD_MUL => "MOD_MUL".to_string(),
        family::SHA256_COMP => "SHA256_COMP".to_string(),
        family::EC_ADD => "EC_ADD".to_string(),
        family::FIELD_WINDOWS => "FIELD_WINDOWS".to_string(),
        family::FR_OP => "FR_OP".to_string(),
        family::P2_FIELD => "P2_FIELD".to_string(),
        family::FIELD_IO => "FIELD_IO".to_string(),
        family::FQ_OP => "FQ_OP".to_string(),
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
/// The shard region is a `par_iter`, so lines from different shards interleave
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

/// Eight 32-bit limbs as one **big-endian** hex integer, `0x`-marked: how a
/// modulus or a coordinate reads in every reference this repository cites, and
/// the one place this log is not in `to_bytes` order ([`fr_full`] says why).
/// Limb 0 is the low one.
pub fn limbs(words: &[u32]) -> String {
    let hex: String = words
        .iter()
        .rev()
        .map(|w| format!("{w:08x}"))
        .collect::<Vec<_>>()
        .join("");
    format!("0x{hex}")
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
/// argument and what every wire form in this repository carries (the root
/// `CLAUDE.md`'s "One encoding"). So a value this log prints can be pasted into
/// the CLI, or grepped against a pinned fixture, without reversing anything. The one exception is [`limbs`], which prints an
/// integer a reader compares against the literature — a modulus, a coordinate —
/// and marks it `0x` and big-endian for that reason.
///
/// In full, not truncated, for the two values a reader compares against a
/// **pinned constant** rather than against another run: identity and the SRS
/// digest. Five pins went stale in S26c and each was found by a test failing
/// somewhere else; a run that prints both, every time, is how the sixth gets
/// found by reading one line.
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

/// A canonicity scan's verdict: how many of `live` rows carry a last borrow of
/// 1, and the first row that does not.
///
/// **The delegation log's single most valuable line.** Every delegation frame
/// value owes an eight-limb borrow chain whose last borrow is 1 exactly when
/// the value is below the modulus (`docs/spec/delegation-circuits.md` §1), and a row
/// that breaks it is provable nowhere: the circuit's gated conclusion fails,
/// the shard's GKR self-check fails at whatever layer that conclusion sits on,
/// and the reader gets a layer number. This says which value, on which
/// invocation, and what it was.
///
/// `bad` is the offending rows in order; only the first is printed, because the
/// cause is one guest bug and the rest are its copies.
pub fn canonical(label: &str, live: usize, bad: &[(usize, String, String)]) -> String {
    if bad.is_empty() {
        return format!("canon {label}: {live}/{live} below the modulus");
    }
    let (row, value, modulus) = &bad[0];
    format!(
        "canon {label}: {}/{live} below the modulus -- NOT CANONICAL on {} rows, \
         first invocation {row}: value={value} modulus={modulus}",
        live - bad.len(),
        bad.len(),
    )
}

/// A one-hot selector column's histogram, by the name of what each code selects.
///
/// `MOD_MUL` multiplies in one of four fixed fields and `EC_ADD` over one of
/// two curves; the selector is a frame word, so a caller that writes the wrong
/// code does not fail a shape check — it proves a multiplication in the wrong
/// field, or fails a bound it would have passed. A histogram is how that reads
/// at a glance: a family whose every invocation should be `secp256k1_p` and
/// whose histogram shows two in `bn254_r` has found its bug.
pub fn histogram(label: &str, names: &[&str], tally: &[usize]) -> String {
    let parts: Vec<String> = names
        .iter()
        .zip(tally)
        .map(|(n, c)| format!("{n}:{c}"))
        .collect();
    format!("{label}=[{}]", parts.join(" "))
}

/// The extremes of a `u64` column, for a gap or a timestamp: the range the
/// frame's bit decomposition or its `RANGE16` chunks have to hold.
///
/// A gap that does not fit its representation is the failure the decomposition
/// silently truncates: `delegation_frame` writes `(gap >> bit) & 1` for 38 bits
/// and drops anything above, so a gap of `2^38` becomes a gap of 0 and a
/// timestamp chain that cannot balance. Printing `max` beside `bits` is how a
/// reader sees it before the multiset does.
pub fn range(label: &str, values: &[u64], bits: u32) -> String {
    // A slice and not an `impl Iterator`: master anti-goal 2 bans `impl Trait`
    // in a public signature, and the caller's slice is one `u64` per live row
    // per frame word — 30 kB on an `EC_ADD` shard, which is not worth a
    // generic.
    let (mut lo, mut hi) = (u64::MAX, 0u64);
    for v in values {
        lo = lo.min(*v);
        hi = hi.max(*v);
    }
    if values.is_empty() {
        return format!("{label}: no rows");
    }
    let ceiling = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let verdict = if hi > ceiling {
        format!(" -- OVER the {bits}-bit ceiling {ceiling}")
    } else {
        String::new()
    };
    format!("{label}=[{lo}..{hi}] over {bits} bits{verdict}")
}

/// A delegation shard's frame, scanned once, as the lines to print.
///
/// Every delegation family shares this much: `docs/spec/delegation.md` §4's
/// frame, an invocation a row, a cycle and a base a row, and a timestamp gap a
/// word. What it reports is the four things a reader needs before any
/// family-specific gate can be read:
///
/// - **how many invocations this shard actually holds**, against its height. A
///   zero here is the "(a) declared but never invoked" case: the family is in
///   the `VmConfig` because the linked binary declared it, its shard is proved
///   because the statement counts it, and every row of it is padding. That is
///   legal and it is also the first thing to check when a delegation is
///   suspected of doing nothing.
/// - **the cycle range**, which is the shard's cut of the execution and what
///   its ts window has to contain.
/// - **the base range**, which every frame's two decompositions bound.
/// - **the timestamp gap's range against the 38-bit clock.** The
///   bit-decomposition frame writes exactly `memory::TS_BITS` bits and drops
///   anything above, so a gap of `2^38` is committed as a gap of 0 and the
///   memory argument stops balancing for a reason no gate names. `range` says
///   so in words.
///
/// `O(live rows × frame words)` and nothing worse, over the live rows alone —
/// so on a `2^16` shard holding 1,893 invocations it reads 1,893 rows and not
/// 65,536.
pub fn frame_scan(frames: &trace::FrameSlice, height: usize) -> Vec<String> {
    let live = frames.len();
    let words = frames.width();
    if live == 0 {
        return vec![format!(
            "invocations=0/{height} frame_words={words} \
             -- DECLARED BUT NEVER INVOKED, every row of this shard is padding"
        )];
    }
    let cycles = frames.cycles();
    let bases = frames.bases();
    let mut out = vec![format!(
        "invocations={live}/{height} frame_words={words} cycles=[{}..{}] base=[{:#x}..{:#x}]",
        cycles.iter().min().copied().unwrap_or(0),
        cycles.iter().max().copied().unwrap_or(0),
        bases.iter().min().copied().unwrap_or(0),
        bases.iter().max().copied().unwrap_or(0),
    )];
    // `gap = 4·cycle + Δ − read_ts − 1`, the value both frame shapes decompose.
    let gaps: Vec<u64> = (0..words)
        .flat_map(|j| {
            let w = frames.word(j);
            (0..live).map(move |r| {
                let ts =
                    constants::memory::TS_STEP * cycles[r] + constants::delegation::FRAME_DELTA;
                ts.saturating_sub(w.read_ts[r]).saturating_sub(1)
            })
        })
        .collect();
    out.push(range("ts-gap", &gaps, constants::memory::TS_BITS));
    out
}

// ---------------------------------------------------------------------------
// The delegation families' own vocabulary
// ---------------------------------------------------------------------------

/// What each of `constants::mod_mul::CODES` selects, in that order.
///
/// The log's own vocabulary, not the constants': `constants` carries the code
/// and the limbs and no name, because nothing in the protocol needs one. A
/// histogram over "1, 2, 3, 4" would say nothing;
/// `secp256k1_p:1893 bn254_r:2` says which caller is wrong.
pub const MOD_MUL_SELECTORS: [&str; 4] = ["secp256k1_p", "secp256k1_n", "bn254_p", "bn254_r"];

/// What each of `constants::ec_add::CODES` selects, in that order: two curves
/// times three groups, one group being one third of a point addition.
pub const EC_ADD_SELECTORS: [&str; 6] = [
    "secp256k1_g1",
    "secp256k1_g2",
    "secp256k1_g3",
    "bn254_g1",
    "bn254_g2",
    "bn254_g3",
];

/// `constants::ec_add`'s twelve frame values, by name and in `VALUES` order.
///
/// A **mirror** of `constraints::ec_add::VALUES`, which is private to that
/// module: the six point coordinates are read by groups 0 and 1, the six
/// intermediates by group 2 alone, and `ec_add_reads` is that rule. It is
/// mirrored rather than shared because the circuit's table carries a word
/// offset and a gate's operand terms beside the name, none of which a log line
/// wants, and because making it public would put a log's vocabulary in the
/// circuit's API. **If `VALUES` gains a value or moves one between groups, this
/// mirror and `ec_add_reads` move with it** — `a_group_reads_its_own_six`
/// pins the shape, and nothing can pin the contents from outside that module.
pub const EC_ADD_VALUES: [&str; 12] = [
    "x1", "y1", "z1", "x2", "y2", "z2", "xx", "yy", "zz", "m4", "m5", "m6",
];

/// Does a row of group `group` read frame value `v`?
///
/// **This is what keeps the canonicity verdict from lying.** A value's `< m`
/// chain is computed on every row, but its *conclusion* is gated to the groups
/// that read it, so on a group-0 row the six intermediate words hold whatever
/// the guest's scratch held and need not be below `m` at all
/// (`crates/constraints/src/ec_add.rs`, `VALUES`). A scan that called those
/// rows non-canonical would report the honest prover as broken on every block.
pub fn ec_add_reads(group: usize, v: usize) -> bool {
    if v < 6 {
        group == 0 || group == 1
    } else {
        group == 2
    }
}

/// `EC_ADD`'s one free invariant, checked: **each curve's three groups must
/// have the same number of invocations.**
///
/// A row of this family is one third of a complete point addition
/// (`docs/spec/delegation-circuits.md` §6), so a guest that performed `n` additions on
/// a curve invoked each of that curve's three groups exactly `n` times. Three
/// counts that differ mean an addition whose thirds did not all reach the
/// executor — a dropped invocation, a guest that returned early between two
/// thirds, or a shard cut that split an addition across a boundary the frame
/// cannot express.
///
/// It costs a tally the log already has, and nothing else in the repository
/// checks it: the global multiset catches a dropped invocation eventually, as a
/// root product that does not reconcile over a whole block, which names no
/// family and no row.
pub fn ec_add_groups(tally: &[usize]) -> String {
    let mut out = Vec::new();
    for (curve, name) in ["secp256k1", "bn254"].iter().enumerate() {
        let groups: Vec<usize> = (0..constants::ec_add::CODES.len())
            .filter(|c| constants::ec_add::CODE_CURVE[*c] == curve)
            .map(|c| tally.get(c).copied().unwrap_or(0))
            .collect();
        if groups.iter().all(|n| *n == 0) {
            continue;
        }
        let balanced = groups.windows(2).all(|w| w[0] == w[1]);
        out.push(format!(
            "{name} thirds={groups:?}{}",
            if balanced {
                ""
            } else {
                " -- UNBALANCED, a point addition is missing a third"
            }
        ));
    }
    if out.is_empty() {
        return "no invocations on either curve".to_string();
    }
    out.join("  ")
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
        let (c, complaint) = parse(Some("deep:ec_add, MOD_MUL ,17"));
        assert!(complaint.is_none(), "{complaint:?}");
        assert_eq!(c.level, Level::Deep);
        assert_eq!(
            c.families,
            vec![family::EC_ADD, family::MOD_MUL, family::EC_ADD]
        );
    }

    #[test]
    fn an_unknown_family_complains_and_keeps_the_level() {
        let (c, complaint) = parse(Some("deep:EC_ADDD"));
        assert_eq!(c.level, Level::Deep);
        assert!(c.families.is_empty());
        let text = complaint.expect("a complaint");
        assert!(text.contains("EC_ADDD"), "{text}");
    }

    /// The filter's whole point: the named family is at the configured level
    /// and every other family is one step below it. `level_for` is the rule,
    /// so this test calls it rather than restating it.
    #[test]
    fn a_named_family_is_one_level_deeper_than_the_rest() {
        let (c, _) = parse(Some("deep:EC_ADD"));
        assert_eq!(c.level_for(family::EC_ADD), Level::Deep);
        assert_eq!(c.level_for(family::MOD_MUL), Level::Detail);

        let (c, _) = parse(Some("detail:MOD_MUL"));
        assert_eq!(c.level_for(family::MOD_MUL), Level::Detail);
        assert_eq!(c.level_for(family::EC_ADD), Level::Phase);

        // No filter: every family is at the configured level.
        let (c, _) = parse(Some("deep"));
        assert_eq!(c.level_for(family::EC_ADD), Level::Deep);
        assert_eq!(c.level_for(family::ADD_SUB_LUI_AUIPC), Level::Deep);

        // `off` stays off for every family, named or not: a filter raises
        // nothing above the configured level.
        let (c, _) = parse(Some("off:EC_ADD"));
        assert_eq!(c.level_for(family::EC_ADD), Level::Off);
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

    /// The selector names are the log's own, so nothing but a test holds them
    /// to the constants they name. A code appended to either family without a
    /// name here would print a histogram one column short.
    #[test]
    fn every_selector_code_has_a_name() {
        assert_eq!(MOD_MUL_SELECTORS.len(), constants::mod_mul::CODES.len());
        assert_eq!(EC_ADD_SELECTORS.len(), constants::ec_add::CODES.len());
        // The `ec_add` names claim a curve and a group; `CODE_CURVE` and
        // `CODE_GROUP` are what actually decide, so hold the two to agreeing.
        for (c, name) in EC_ADD_SELECTORS.iter().enumerate() {
            let curve = ["secp256k1", "bn254"][constants::ec_add::CODE_CURVE[c]];
            let group = constants::ec_add::CODE_GROUP[c] + 1;
            assert_eq!(*name, format!("{curve}_g{group}"), "code {c}");
        }
    }

    /// The mirror's shape, which is all a test outside `constraints::ec_add`
    /// can pin: twelve values, three groups, and every group reading exactly
    /// six of them — six coordinates for groups 0 and 1, six intermediates for
    /// group 2.
    #[test]
    fn a_group_reads_its_own_six() {
        assert_eq!(EC_ADD_VALUES.len(), 12);
        for group in 0..constants::ec_add::GROUPS {
            let read: Vec<usize> = (0..12).filter(|v| ec_add_reads(group, *v)).collect();
            assert_eq!(read.len(), 6, "group {group} reads {read:?}");
        }
        assert!(ec_add_reads(0, 0) && ec_add_reads(1, 5));
        assert!(!ec_add_reads(0, 6) && !ec_add_reads(1, 11));
        assert!(ec_add_reads(2, 6) && !ec_add_reads(2, 0));
    }

    #[test]
    fn unbalanced_ec_add_thirds_are_named() {
        // `CODES` is secp g1,g2,g3 then bn254 g1,g2,g3.
        let balanced = ec_add_groups(&[7, 7, 7, 0, 0, 0]);
        assert!(
            balanced.contains("secp256k1 thirds=[7, 7, 7]"),
            "{balanced}"
        );
        assert!(!balanced.contains("UNBALANCED"), "{balanced}");
        // A curve with no invocations is not mentioned at all.
        assert!(!balanced.contains("bn254"), "{balanced}");

        let short = ec_add_groups(&[7, 7, 6, 0, 0, 0]);
        assert!(short.contains("UNBALANCED"), "{short}");

        assert!(ec_add_groups(&[0; 6]).contains("no invocations"));
    }

    #[test]
    fn a_canonicity_verdict_names_the_first_bad_invocation() {
        let clean = canonical("a", 1893, &[]);
        assert!(clean.contains("1893/1893"), "{clean}");
        assert!(!clean.contains("NOT CANONICAL"), "{clean}");

        let bad = canonical(
            "y2",
            1893,
            &[
                (41, "0xdead".to_string(), "0xbeef".to_string()),
                (42, "0x1".to_string(), "0xbeef".to_string()),
            ],
        );
        assert!(bad.contains("NOT CANONICAL on 2 rows"), "{bad}");
        assert!(bad.contains("first invocation 41"), "{bad}");
        assert!(bad.contains("0xdead"), "{bad}");
        // The count is the rows that DID pass, not the rows that failed.
        assert!(bad.contains("1891/1893"), "{bad}");
    }

    /// A gap above its decomposition's ceiling is the silent truncation the
    /// scan exists to catch, so the line has to say so in words.
    #[test]
    fn a_range_over_its_ceiling_says_so() {
        let ok = range("gap", &[0u64, 5, 700], 38);
        assert!(ok.contains("[0..700]"), "{ok}");
        assert!(!ok.contains("OVER"), "{ok}");

        let over = range("gap", &[1u64 << 38], 38);
        assert!(over.contains("OVER the 38-bit ceiling"), "{over}");

        assert!(range("gap", &[], 38).contains("no rows"));
    }

    #[test]
    fn a_histogram_pairs_every_code_with_its_name() {
        let h = histogram(
            "sel",
            &["secp_p", "secp_n", "bn_q", "bn_r"],
            &[1893, 0, 2, 0],
        );
        assert_eq!(h, "sel=[secp_p:1893 secp_n:0 bn_q:2 bn_r:0]");
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
    fn limbs_read_big_endian_with_limb_zero_low() {
        assert_eq!(limbs(&[1, 0]), "0x0000000000000001");
        assert_eq!(limbs(&[0, 1]), "0x0000000100000000");
    }

    #[test]
    fn a_height_reads_as_a_power_of_two() {
        assert_eq!(height(1 << 20), "2^20");
        assert_eq!(height(1 << 8), "2^8");
        assert_eq!(height(3), "3");
    }
}
