//! The step schedule as **virtual** columns: `docs/spec/ecrecover.md` §6.2.
//!
//! A row's behaviour must be a function of its step and of nothing a prover
//! chooses, so every per-step constant is a column of its own. These columns
//! are never committed, never opened and never sent -- their closed form is
//! their kind, and `family_circuit` is what binds them, the same check that
//! already holds every verifying key's circuit equal to the protocol's.
//!
//! ```text
//! V[sched_k](y) = Σ_{i < ROWS_PER_INVOCATION} eq(y_0..y_11, i) · c_k[i]
//! ```
//!
//! Three things keep that affordable, each measured against the real program
//! rather than assumed:
//!
//! - **Zero entries cost nothing.** A term with `c_k[i] = 0` drops out of the
//!   sum, so a table's price is its *nonzero* count against one shared `eq`
//!   vector. Most of these are mostly idle: each window-table column is live
//!   on 172 of 4,096 steps and the frame columns on seven.
//! - **Each table is stored offset by its modal value**, [`MODAL`], so the
//!   common case is the zero that drops out and the mode is a gate literal.
//!   `out_coeff` is `−1` on nearly every step: 3,779 nonzero becomes 830.
//! - **A write address is not a table at all.** A step owns the bus block
//!   `[step·FAN_OUT, (step + 1)·FAN_OUT)`, so its `j`th copy is at
//!   `FAN_OUT·step + j` -- a closed form of the row index, read off `V[row]`.
//!   Packed densely the base would be a running total, which is 3,515
//!   constants the recursion guest would have to link.
//!
//! Together those take the schedule from 131,072 constants dense to about
//! 25,000. `crates/constraints/tests/tables.rs` is what holds the generated
//! data equal to [`derive`]'s, so the two cannot drift.

use alloc::vec::Vec;

use constants::ecrecover::ROWS_PER_INVOCATION;

use super::schedule::{Digit, Frame, Modulus, Output, Step};
use super::FAN_OUT;

/// Every schedule table, by index. The order is the wire order and the order
/// of [`MODAL`] and of the generated data, so it is append-only.
pub mod id {
    /// 1 where the step's product reads its `A` operand from the bus.
    pub const HAS_A: usize = 0;
    /// `A`'s bus address.
    pub const A_ADDR: usize = 1;
    /// The written `A`'s own linear coefficient, for the one shape that reads
    /// its output linearly as well as in the product.
    pub const A_COEFF: usize = 2;
    /// 1 where the step's product reads its `B` operand from the bus.
    pub const HAS_B: usize = 3;
    /// `B`'s bus address.
    pub const B_ADDR: usize = 4;
    /// The `C` linear slot's coefficient and address.
    pub const C_COEFF: usize = 5;
    pub const C_ADDR: usize = 6;
    /// The `E` linear slot's coefficient and address.
    pub const E_COEFF: usize = 7;
    pub const E_ADDR: usize = 8;
    /// The step's added constant, limb by limb.
    pub const LITERAL: [usize; 4] = [9, 10, 11, 12];
    /// 0 none, 1 emit, 2 check -- what the row does with its selectors.
    pub const DIGIT_MODE: usize = 13;
    /// The bus address the digit is checked against, on a checking row.
    pub const DIGIT_ADDR: usize = 14;
    /// How many table entries the row selects among; 0 where it selects none.
    pub const TABLE_COUNT: usize = 15;
    /// The eight windowed-table entries' bus addresses.
    pub const TABLE_ADDR: [usize; 8] = [16, 17, 18, 19, 20, 21, 22, 23];
    /// 0 for the field modulus `p`, 1 for the group order `n`.
    pub const MODULUS: usize = 24;
    /// 0 none, 1 `A`, 2 `Sqrt`, 3 `D` -- which slot the step writes.
    pub const OUTPUT: usize = 25;
    /// The written slot's coefficient in the congruence.
    pub const OUT_COEFF: usize = 26;
    /// 1 where the output reaches the bus at all.
    pub const BUSED: usize = 27;
    /// How many copies the output is written to, which is how many steps read
    /// it. The addresses themselves are `FAN_OUT·step + j`.
    pub const WRITES_COUNT: usize = 28;
    /// 1 where the row's is-zero test is enabled.
    pub const IS_ZERO: usize = 29;
    /// 1 where the quotient is held to zero, making the congruence an
    /// equation over the integers.
    pub const EXACT: usize = 30;
    /// 0 none, 1 read, 2 write -- which way the row moves frame words.
    pub const FRAME_MODE: usize = 31;
    /// The eight frame words the row moves, low word first.
    pub const FRAME_WORD: [usize; 8] = [32, 33, 34, 35, 36, 37, 38, 39];
    /// How many tables there are, which is one past the last index.
    pub const COUNT: usize = 40;
}

/// Each table's **modal** value: the one its entries are stored relative to,
/// so that the common case is zero and drops out of the extension's sum. A
/// gate reading table `k` adds `MODAL[k]` as a literal.
///
/// These are measured, not chosen: `crates/constraints/tests/tables.rs`
/// rebuilds them from the program and refuses any that is not the most common
/// value of its column.
pub const MODAL: [i128; id::COUNT] = {
    let mut m = [0i128; id::COUNT];
    m[id::OUTPUT] = 3;
    m[id::OUT_COEFF] = -1;
    m[id::BUSED] = 1;
    m[id::WRITES_COUNT] = 1;
    m
};

/// One table as the raw value at each step of the block, before the modal
/// offset: `raw(k)[i]` is what step `i` says, and 0 past the program's end,
/// every idle step of the block being idle in every table.
pub fn raw(steps: &[Step], table: usize) -> Vec<i128> {
    let read = |s: &Step| -> i128 {
        match table {
            id::HAS_A => s.a.is_some() as i128,
            id::A_ADDR => s.a.unwrap_or(0) as i128,
            id::A_COEFF => s.a_coeff as i128,
            id::HAS_B => s.b.is_some() as i128,
            id::B_ADDR => s.b.unwrap_or(0) as i128,
            id::C_COEFF => s.c.map_or(0, |(c, _)| c as i128),
            id::C_ADDR => s.c.map_or(0, |(_, a)| a as i128),
            id::E_COEFF => s.e.map_or(0, |(c, _)| c as i128),
            id::E_ADDR => s.e.map_or(0, |(_, a)| a as i128),
            id::DIGIT_MODE => match s.digit {
                Digit::None => 0,
                Digit::Emit => 1,
                Digit::Check(_) => 2,
            },
            id::DIGIT_ADDR => match s.digit {
                Digit::Check(at) => at as i128,
                _ => 0,
            },
            id::TABLE_COUNT => s.table.len() as i128,
            id::MODULUS => matches!(s.modulus, Modulus::Order) as i128,
            id::OUTPUT => match s.output {
                Output::None => 0,
                Output::A => 1,
                Output::Sqrt => 2,
                Output::D => 3,
            },
            id::OUT_COEFF => s.out_coeff as i128,
            id::BUSED => s.bused as i128,
            id::WRITES_COUNT => s.writes.len() as i128,
            id::IS_ZERO => s.is_zero as i128,
            id::EXACT => s.exact as i128,
            id::FRAME_MODE => match s.frame {
                Frame::None => 0,
                Frame::Read(_) => 1,
                Frame::Write(_) => 2,
            },
            _ => {
                if let Some(j) = id::LITERAL.iter().position(|x| *x == table) {
                    s.literal[j] as i128
                } else if let Some(j) = id::TABLE_ADDR.iter().position(|x| *x == table) {
                    s.table.get(j).map_or(0, |v| *v as i128)
                } else if let Some(j) = id::FRAME_WORD.iter().position(|x| *x == table) {
                    match s.frame {
                        Frame::Read(w) | Frame::Write(w) => w[j] as i128,
                        Frame::None => 0,
                    }
                } else {
                    panic!(
                        "schedule table {table} is not one of the {} there are",
                        id::COUNT
                    )
                }
            }
        }
    };
    (0..ROWS_PER_INVOCATION)
        .map(|i| steps.get(i).map_or(0, read))
        .collect()
}

/// Every table, offset by its mode and kept sparse: `derive()[k]` is the
/// `(step, value − MODAL[k])` pairs of table `k` where that difference is not
/// zero, ascending by step.
///
/// This is the definition the generated data is checked against, and the one
/// `kat-gen` writes from. Nothing calls it at proving time.
pub fn derive() -> Vec<Vec<(u16, i128)>> {
    let program = super::schedule();
    (0..id::COUNT)
        .map(|k| {
            raw(&program.steps, k)
                .into_iter()
                .enumerate()
                .filter(|(_, v)| *v != MODAL[k])
                .map(|(i, v)| (i as u16, v - MODAL[k]))
                .collect()
        })
        .collect()
}

/// The bus address of the `j`th copy of the value step `i` writes.
///
/// A closed form and not a table: a step owns the block
/// `[i·FAN_OUT, (i + 1)·FAN_OUT)`, so the circuit reads this off `V[row]` and
/// the schedule carries nothing for it.
pub fn write_address(step: usize, copy: usize) -> usize {
    debug_assert!(copy < FAN_OUT, "a step writes at most FAN_OUT copies");
    FAN_OUT * step + copy
}

/// The tables, dense, in step order -- the shape `virtual_at_row` reads and
/// the shape the generated data decodes to. Allocates; the engine holds one
/// of these per circuit rather than calling it per row.
pub fn dense() -> Vec<Vec<i128>> {
    let program = super::schedule();
    (0..id::COUNT).map(|k| raw(&program.steps, k)).collect()
}

/// A table's value at one step, from its sparse pairs.
pub fn at(sparse: &[(u16, i128)], modal: i128, step: usize) -> i128 {
    match sparse.binary_search_by_key(&(step as u16), |(i, _)| *i) {
        Ok(j) => modal + sparse[j].1,
        Err(_) => modal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The modal value of each table really is its most common entry, so the
    /// offset is the one that makes the table sparsest.
    #[test]
    fn each_tables_offset_is_its_most_common_entry() {
        let program = crate::ecrecover::schedule();
        for (k, modal) in MODAL.iter().enumerate() {
            let col = raw(&program.steps, k);
            let mut best = (0i128, 0usize);
            for v in &col {
                let n = col.iter().filter(|x| *x == v).count();
                if n > best.1 {
                    best = (*v, n);
                }
            }
            assert_eq!(
                *modal,
                best.0,
                "table {k}'s mode is {} on {} of {} steps, and MODAL says {modal}",
                best.0,
                best.1,
                col.len()
            );
        }
    }

    /// Sparse and dense agree at every step of the block, which is what lets
    /// the verifier evaluate one and the prover read the other.
    #[test]
    fn the_sparse_tables_are_the_dense_ones() {
        let sparse = derive();
        let dense = dense();
        for (k, column) in dense.iter().enumerate() {
            for (i, want) in column.iter().enumerate() {
                assert_eq!(at(&sparse[k], MODAL[k], i), *want, "table {k} step {i}");
            }
        }
    }

    /// The whole point, measured: the sparse form is a small fraction of the
    /// dense one. A regression here means a table stopped being idle and the
    /// recursion guest's image grew.
    #[test]
    fn the_schedule_is_smaller_sparse_than_dense() {
        let sparse = derive();
        let total: usize = sparse.iter().map(|t| t.len()).sum();
        let dense = id::COUNT * ROWS_PER_INVOCATION;
        assert!(
            total * 4 < dense,
            "the sparse schedule is {total} pairs against {dense} dense, which is not the \
             fourfold saving §6.2 rests on"
        );
        assert!(total < 30_000, "the sparse schedule grew to {total} pairs");
    }

    /// A write address is the block's, so it is a closed form of the step.
    #[test]
    fn a_write_address_is_its_steps_block() {
        let program = crate::ecrecover::schedule();
        for (i, step) in program.steps.iter().enumerate() {
            for (j, at) in step.writes.iter().enumerate() {
                assert_eq!(*at as usize, write_address(i, j), "step {i} copy {j}");
            }
        }
    }
}
