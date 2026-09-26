//! The per-family trace buffers: one row per executed cycle, column-major,
//! holding every value the cycle's memory queries carried, in small types.
//!
//! Rows are live rows only. There is no padding here and no polynomial: what
//! a padding row holds, and how a column becomes a multilinear, belong to the
//! constraint system that has not been built yet, and a buffer that guessed
//! would be a buffer someone has to un-guess.

use program::FamilyId;

use crate::log::AddressSpace;

/// What a query does in its cycle. A role fixes the query's address space and
/// its in-cycle slot, and the frozen order of [`ROLES`] fixes its place among
/// the cycle's events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Slot 1, a register read: `rs1`. On an ecall row, `a7`.
    Rs1,
    /// Slot 2, a register read: `rs2`. On an ecall row, `a0`, the first argument.
    Rs2,
    /// Slot 2, a register read. On an ecall row, `a1`; nothing else uses it.
    Arg1,
    /// Slot 2, a register read. On an ecall row, `a2`; nothing else uses it.
    Arg2,
    /// Slot 2, a RAM read: a load's word.
    Load,
    /// Slot 3, a RAM query: a store's, an atomic's or an ecall transfer's word.
    Ram,
    /// Slot 3, a register write: `rd`. On an ecall row, `a0`, the result.
    Rd,
    /// Slot 3, a **delegation** request's mirror query (S21). Its address is
    /// the frame base pointer the request handed over in `a0`, in the
    /// delegation family's own address space; its read is the invocation's
    /// answer tuple, stamped 0 (`docs/spec/delegation.md` §5). Only an ecall
    /// row whose number is a delegation call has one.
    Delegate,
}

/// Every role, in frozen order. A cycle's events are its pc query, then one
/// query per role it has, in this order.
///
/// Eight is the ceiling: `Row::present` is a `u8` with one bit per role, so a
/// ninth role widens it, and that is a schema change
/// (`docs/spec/execution-trace.md` §7). [`Role::Delegate`] took the last bit.
pub const ROLES: [Role; 8] = [
    Role::Rs1,
    Role::Rs2,
    Role::Arg1,
    Role::Arg2,
    Role::Load,
    Role::Ram,
    Role::Rd,
    Role::Delegate,
];

impl Role {
    /// The in-cycle slot.
    pub fn delta(self) -> u64 {
        match self {
            Role::Rs1 => 1,
            Role::Rs2 | Role::Arg1 | Role::Arg2 | Role::Load => 2,
            Role::Ram | Role::Rd | Role::Delegate => 3,
        }
    }

    /// The address space.
    ///
    /// [`Role::Delegate`]'s is **the row's**, not the role's: a delegation
    /// family's anchor space *is* its type (`constants::address_space`), and
    /// with more than one registered type the role alone no longer says which.
    /// `delegation` is the requested family's space, which the row knows
    /// because the invocation riding its cycle names the family; every other
    /// role ignores it, and passing `None` on a row that has this role is a
    /// programmer error rather than a default.
    pub fn space(self, delegation: Option<AddressSpace>) -> AddressSpace {
        match self {
            Role::Load | Role::Ram => AddressSpace::Ram,
            Role::Delegate => {
                delegation.expect("a delegation request's row knows which family it is requesting")
            }
            _ => AddressSpace::Reg,
        }
    }
}

/// One query as a row holds it. Its write timestamp is not stored: it is
/// `4 * cycle + role.delta()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Query {
    pub addr: u32,
    pub read_ts: u64,
    pub read_value: u32,
    pub write_value: u32,
}

impl Query {
    /// What a row holds for a role it does not have.
    pub const ABSENT: Query = Query {
        addr: 0,
        read_ts: 0,
        read_value: 0,
        write_value: 0,
    };
}

/// One executed cycle.
///
/// The pc query is `pc` read and `next_pc` written, at slot 0; its read
/// timestamp is not stored because it is always the previous cycle's, `4 *
/// (cycle - 1)`. Bit `r` of `present` is set exactly when the cycle has a
/// query in role `ROLES[r]`; every other entry of `queries` is
/// [`Query::ABSENT`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub cycle: u64,
    pub pc: u32,
    pub next_pc: u32,
    pub present: u8,
    pub queries: [Query; 8],
}

impl Row {
    /// The query in `role`, if the cycle has one.
    pub fn query(&self, role: Role) -> Option<Query> {
        (self.present & (1 << role as u8) != 0).then(|| self.queries[role as usize])
    }

    /// The **delegation anchor space** this row's mirror query names, or `None`
    /// on a row that requests no delegation.
    ///
    /// [`Role::Delegate`]'s address space is the row's and not the role's: one
    /// role serves every delegation type, and the type is the space
    /// (`docs/spec/delegation.md` §5.1). What says which type is the ecall
    /// number, which a delegation row reads into `a7` at slot 1 — that is
    /// [`Role::Rs1`] on an ecall row (`docs/spec/execution-trace.md` §6) — so
    /// the row answers this on its own, without the invocation beside it. That
    /// is what lets a shard's columns be built from the shard's rows alone.
    ///
    /// Panics naming the number if a row claims the mirror query for an ecall
    /// number no delegation family has, which is a buffer the emulator cannot
    /// produce.
    pub fn delegation_space(&self) -> Option<AddressSpace> {
        self.query(Role::Delegate)?;
        let number = self
            .query(Role::Rs1)
            .expect("a delegation request's row reads a7 at slot 1")
            .read_value;
        let family = program::delegation_family(number).unwrap_or_else(|| {
            panic!(
                "cycle {}: a delegation request whose ecall number {number:#x} names no family",
                self.cycle
            )
        });
        program::delegation_space(family).and_then(AddressSpace::from_tag)
    }
}

/// One shard's rows of one cycle-owning family: a borrowed window into a trace
/// buffer, `[index·height, min((index+1)·height, len))`
/// (`docs/spec/block-proof.md` §5.1).
///
/// A fill reads its shard through this and never indexes the whole buffer, so
/// one fill serves a slice of an archived execution and a streaming executor's
/// freshly filled chunk alike — the two differ only in who owns the rows.
#[derive(Clone, Copy, Debug)]
pub struct RowSlice<'a> {
    trace: &'a FamilyTrace,
    start: usize,
    len: usize,
}

impl<'a> RowSlice<'a> {
    /// Shard `index`'s rows of `trace` at `height`. A shard past the buffer's
    /// end is empty rather than an error: a plan cuts no such shard, and a
    /// family that never ran has no rows at all.
    pub fn shard(trace: &'a FamilyTrace, index: u32, height: usize) -> RowSlice<'a> {
        let start = (index as usize * height).min(trace.len());
        let len = (start + height).min(trace.len()) - start;
        RowSlice { trace, start, len }
    }

    /// How many live rows this shard holds; at most the height.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The family whose rows these are.
    pub fn family(&self) -> FamilyId {
        self.trace.family
    }

    /// Row `i` of the shard.
    pub fn row(&self, i: usize) -> Row {
        assert!(i < self.len, "row {i} of a {}-row shard", self.len);
        self.trace.row(self.start + i)
    }

    /// The shard's cycle column: one cycle number per live row, ascending.
    pub fn cycles(&self) -> &'a [u64] {
        &self.trace.cycle[self.start..self.start + self.len]
    }
}

/// One shard's invocations of one delegation family: a borrowed window into a
/// [`DelegationTrace`], the same cut [`RowSlice`] takes over a `FamilyTrace`.
#[derive(Clone, Copy, Debug)]
pub struct FrameSlice<'a> {
    trace: &'a DelegationTrace,
    start: usize,
    len: usize,
}

impl<'a> FrameSlice<'a> {
    /// Shard `index`'s invocations of `trace` at `height`.
    pub fn shard(trace: &'a DelegationTrace, index: u32, height: usize) -> FrameSlice<'a> {
        let start = (index as usize * height).min(trace.len());
        let len = (start + height).min(trace.len()) - start;
        FrameSlice { trace, start, len }
    }

    /// How many invocations this shard holds; at most the height.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The family whose invocations these are.
    pub fn family(&self) -> FamilyId {
        self.trace.family
    }

    /// The frame's width in words.
    pub fn width(&self) -> usize {
        self.trace.words.len()
    }

    /// The requesting cycle of each invocation this shard holds.
    pub fn cycles(&self) -> &'a [u64] {
        &self.trace.cycle[self.start..self.start + self.len]
    }

    /// The frame base pointer of each.
    pub fn bases(&self) -> &'a [u32] {
        &self.trace.base[self.start..self.start + self.len]
    }

    /// Frame word `j`'s four columns over this shard's invocations.
    pub fn word(&self, j: usize) -> WordSlice<'a> {
        let c = &self.trace.words[j];
        let (a, b) = (self.start, self.start + self.len);
        WordSlice {
            addr: &c.addr[a..b],
            read_ts: &c.read_ts[a..b],
            read_value: &c.read_value[a..b],
            write_value: &c.write_value[a..b],
        }
    }
}

/// One frame word's four columns over one shard's invocations.
#[derive(Clone, Copy, Debug)]
pub struct WordSlice<'a> {
    pub addr: &'a [u32],
    pub read_ts: &'a [u64],
    pub read_value: &'a [u32],
    pub write_value: &'a [u32],
}

/// One role's four columns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryColumns {
    pub addr: Vec<u32>,
    pub read_ts: Vec<u64>,
    pub read_value: Vec<u32>,
    pub write_value: Vec<u32>,
}

/// One family's rows, column-major: every column has one entry per row, and
/// the row count is the family's occupancy.
///
/// The frozen column names are `cycle`, `pc`, `next_pc`, `present`, and for
/// each role `r` in [`ROLES`] order `r.addr`, `r.read_ts`, `r.read_value`
/// and `r.write_value` — `rs1.addr` through `rd.write_value`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyTrace {
    pub family: FamilyId,
    /// The family's `VmConfig` height, so the buffer says how it will be
    /// sharded without the config beside it.
    pub height: u32,
    pub cycle: Vec<u64>,
    pub pc: Vec<u32>,
    pub next_pc: Vec<u32>,
    pub present: Vec<u8>,
    /// Indexed by `role as usize`.
    pub queries: [QueryColumns; 8],
}

impl FamilyTrace {
    pub fn new(family: FamilyId, height: u32) -> FamilyTrace {
        FamilyTrace {
            family,
            height,
            cycle: Vec::new(),
            pc: Vec::new(),
            next_pc: Vec::new(),
            present: Vec::new(),
            queries: Default::default(),
        }
    }

    /// The occupancy: how many rows the family has.
    pub fn len(&self) -> usize {
        self.cycle.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cycle.is_empty()
    }

    pub fn push(&mut self, row: &Row) {
        self.cycle.push(row.cycle);
        self.pc.push(row.pc);
        self.next_pc.push(row.next_pc);
        self.present.push(row.present);
        for (columns, q) in self.queries.iter_mut().zip(&row.queries) {
            columns.addr.push(q.addr);
            columns.read_ts.push(q.read_ts);
            columns.read_value.push(q.read_value);
            columns.write_value.push(q.write_value);
        }
    }

    /// Row `i`, gathered back out of the columns.
    pub fn row(&self, i: usize) -> Row {
        let mut queries = [Query::ABSENT; 8];
        for (q, columns) in queries.iter_mut().zip(&self.queries) {
            *q = Query {
                addr: columns.addr[i],
                read_ts: columns.read_ts[i],
                read_value: columns.read_value[i],
                write_value: columns.write_value[i],
            };
        }
        Row {
            cycle: self.cycle[i],
            pc: self.pc[i],
            next_pc: self.next_pc[i],
            present: self.present[i],
            queries,
        }
    }
}

/// One **delegation** family's rows: one per invocation, column-major.
///
/// A delegation family is invoked, never decoded, so a row is not a cycle: it
/// is one call of the precompile, stamped with the cycle that requested it. Its
/// memory queries are the frame's fixed-offset words — 50 of them for
/// keccak-f[1600] — which do not fit [`Row`]'s eight roles and are not roles at
/// all, so they live here rather than in a [`FamilyTrace`].
///
/// `words[j]` is frame word `j`, at byte offset `4 * j` from `base`
/// (`docs/spec/delegation.md` §4); every word's write timestamp is
/// `4 * cycle + constants::delegation::FRAME_DELTA`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationTrace {
    pub family: FamilyId,
    /// The family's `VmConfig` height.
    pub height: u32,
    /// The requesting cycle, one per invocation.
    pub cycle: Vec<u64>,
    /// The frame base pointer the request handed over, one per invocation.
    pub base: Vec<u32>,
    /// The frame's word queries, in frame order; every entry has one value per
    /// invocation.
    pub words: Vec<QueryColumns>,
}

impl DelegationTrace {
    /// An empty buffer for `family` at `height`, with `width` frame words.
    pub fn new(family: FamilyId, height: u32, width: usize) -> DelegationTrace {
        DelegationTrace {
            family,
            height,
            cycle: Vec::new(),
            base: Vec::new(),
            words: vec![QueryColumns::default(); width],
        }
    }

    /// How many invocations the family made.
    pub fn len(&self) -> usize {
        self.cycle.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cycle.is_empty()
    }

    /// Append one invocation. `words` is one query per frame word, in frame
    /// order, and must be the buffer's width.
    pub fn push(&mut self, cycle: u64, base: u32, words: &[Query]) {
        assert_eq!(
            words.len(),
            self.words.len(),
            "delegation buffer: an invocation of {} frame words in a {}-word frame",
            words.len(),
            self.words.len()
        );
        self.cycle.push(cycle);
        self.base.push(base);
        for (columns, q) in self.words.iter_mut().zip(words) {
            columns.addr.push(q.addr);
            columns.read_ts.push(q.read_ts);
            columns.read_value.push(q.read_value);
            columns.write_value.push(q.write_value);
        }
    }

    /// Invocation `i`'s frame, gathered back out of the columns.
    pub fn frame(&self, i: usize) -> Vec<Query> {
        self.words
            .iter()
            .map(|columns| Query {
                addr: columns.addr[i],
                read_ts: columns.read_ts[i],
                read_value: columns.read_value[i],
                write_value: columns.write_value[i],
            })
            .collect()
    }
}

/// Every family's buffer, one per family of the `VmConfig`, in its order —
/// including those this execution never reached, which are empty.
///
/// A delegation family's buffer is a [`DelegationTrace`] and lives in
/// `delegations`; every other family's is a [`FamilyTrace`] in `families`.
/// Both are ascending by family id, and the two id sets are disjoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyTraces {
    pub families: Vec<FamilyTrace>,
    pub delegations: Vec<DelegationTrace>,
}

impl FamilyTraces {
    /// The buffer of `family`, or `None` if the config has no such family or
    /// the family is a delegation one.
    pub fn family(&self, family: FamilyId) -> Option<&FamilyTrace> {
        self.families.iter().find(|t| t.family == family)
    }

    /// The delegation buffer of `family`, or `None`.
    pub fn delegation(&self, family: FamilyId) -> Option<&DelegationTrace> {
        self.delegations.iter().find(|t| t.family == family)
    }

    /// Every buffer's row count, ascending by family id: the shape a
    /// `CycleProfile` has.
    pub fn row_counts(&self) -> Vec<(FamilyId, u64)> {
        let mut out: Vec<(FamilyId, u64)> = self
            .families
            .iter()
            .map(|t| (t.family, t.len() as u64))
            .chain(self.delegations.iter().map(|t| (t.family, t.len() as u64)))
            .collect();
        out.sort_by_key(|(f, _)| *f);
        out
    }
}
