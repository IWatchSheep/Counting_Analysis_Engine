//! # Source-Level Counting Harness
//!
//! Provides explicit accounting of high-level algorithmic operations executed
//! in source code.
//!
//! IMPORTANT: These counts represent source-language semantic operations (loop passes,
//! variable increments, logical operators), NOT assembly instructions or CPU cycles.
//! Assembly and hardware measurements are introduced in later checkpoints (CAE-1B, CAE-1C).

/// Explicit record of high-level source operations performed by an algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SourceOperationCounts {
    /// Number of times a loop body was entered and executed.
    pub loop_iterations: u64,
    /// Number of explicit increment operations applied to the counter variable.
    pub counter_updates: u64,
    /// Number of bitwise AND (`&`) operations evaluated.
    pub bitwise_ands: u64,
    /// Number of bitwise right-shift (`>>`) operations executed.
    pub bit_shifts: u64,
    /// Number of arithmetic subtraction (`- 1`) operations executed.
    pub arithmetic_subtractions: u64,
    /// Number of loop/branch condition evaluations performed.
    pub condition_evaluations: u64,
}

impl SourceOperationCounts {
    /// Total count of all tracked discrete source-level operations.
    pub fn total_operations(&self) -> u64 {
        self.loop_iterations
            + self.counter_updates
            + self.bitwise_ands
            + self.bit_shifts
            + self.arithmetic_subtractions
            + self.condition_evaluations
    }
}

/// Instrumented execution of the naive bit-counting algorithm.
///
/// Mirrors the logic of [`crate::algorithms::popcount_naive`], while recording
/// every source-level operation in [`SourceOperationCounts`].
pub fn popcount_naive_instrumented(mut n: u64) -> (u32, SourceOperationCounts) {
    let mut ops = SourceOperationCounts::default();
    let mut count = 0;

    for _ in 0..64 {
        ops.loop_iterations += 1;
        ops.condition_evaluations += 1; // Loop range bound check

        ops.bitwise_ands += 1;
        ops.condition_evaluations += 1; // if (n & 1) != 0 check
        if (n & 1) != 0 {
            count += 1;
            ops.counter_updates += 1;
        }

        n >>= 1;
        ops.bit_shifts += 1;
    }

    // Final termination check of the for-loop range (0..64)
    ops.condition_evaluations += 1;

    (count, ops)
}

/// Instrumented execution of Brian Kernighan's bit-clearing algorithm.
///
/// Mirrors the logic of [`crate::algorithms::popcount_kernighan`], while recording
/// every source-level operation in [`SourceOperationCounts`].
pub fn popcount_kernighan_instrumented(mut n: u64) -> (u32, SourceOperationCounts) {
    let mut ops = SourceOperationCounts::default();
    let mut count = 0;

    // First while-loop condition evaluation: `n != 0`
    ops.condition_evaluations += 1;
    while n != 0 {
        ops.loop_iterations += 1;

        n &= n - 1;
        ops.arithmetic_subtractions += 1;
        ops.bitwise_ands += 1;

        count += 1;
        ops.counter_updates += 1;

        // Subsequent while-loop condition evaluations
        ops.condition_evaluations += 1;
    }

    (count, ops)
}

/// Instrumented execution of the optimized reference implementation (`count_ones()`).
///
/// From the perspective of source-level evaluation, this is an opaque closed-form
/// operation with no source loop iterations.
pub fn popcount_reference_instrumented(n: u64) -> (u32, SourceOperationCounts) {
    let count = n.count_ones();
    let ops = SourceOperationCounts {
        loop_iterations: 0,
        counter_updates: 1, // Single direct assignment of the computed count
        bitwise_ands: 0,
        bit_shifts: 0,
        arithmetic_subtractions: 0,
        condition_evaluations: 0,
    };
    (count, ops)
}
