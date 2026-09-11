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
}

/// Every role, in frozen order. A cycle's events are its pc query, then one
/// query per role it has, in this order.
pub const ROLES: [Role; 7] = [
    Role::Rs1,
    Role::Rs2,
    Role::Arg1,
    Role::Arg2,
    Role::Load,
    Role::Ram,
    Role::Rd,
];

impl Role {
    /// The in-cycle slot.
    pub fn delta(self) -> u64 {
        match self {
            Role::Rs1 => 1,
            Role::Rs2 | Role::Arg1 | Role::Arg2 | Role::Load => 2,
            Role::Ram | Role::Rd => 3,
        }
    }

    /// The address space.
    pub fn space(self) -> AddressSpace {
        match self {
            Role::Load | Role::Ram => AddressSpace::Ram,
            _ => AddressSpace::Reg,
        }
    }

    /// The column-name prefix.
    pub fn name(self) -> &'static str {
        match self {
            Role::Rs1 => "rs1",
            Role::Rs2 => "rs2",
            Role::Arg1 => "arg1",
            Role::Arg2 => "arg2",
            Role::Load => "load",
            Role::Ram => "ram",
            Role::Rd => "rd",
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
    pub queries: [Query; 7],
}

impl Row {
    /// The query in `role`, if the cycle has one.
    pub fn query(&self, role: Role) -> Option<Query> {
        (self.present & (1 << role as u8) != 0).then(|| self.queries[role as usize])
    }
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
    pub queries: [QueryColumns; 7],
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
        let mut queries = [Query::ABSENT; 7];
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

/// Every family's buffer, one per family of the `VmConfig`, in its order —
/// including those this execution never reached, which are empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyTraces {
    pub families: Vec<FamilyTrace>,
}

impl FamilyTraces {
    /// The buffer of `family`, or `None` if the config has no such family.
    pub fn family(&self, family: FamilyId) -> Option<&FamilyTrace> {
        self.families.iter().find(|t| t.family == family)
    }
}
