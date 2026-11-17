//! # Uninstrumented Counting Algorithms
//!
//! Pure, uninstrumented implementations of 64-bit population counting.
//! Kept strictly isolated from measurement code to ensure clear separation
//! of algorithmic intent and measurement overhead.

/// Fixed-width naive bit-counting loop.
///
/// Iterates through all 64 bit positions one by one. On each iteration,
/// it tests the least significant bit and shifts the word right.
///
/// - Algorithmic complexity: Always exactly 64 steps, regardless of input value.
#[inline(never)]
pub fn popcount_naive(mut n: u64) -> u32 {
    let mut count = 0;
    for _ in 0..64 {
        if (n & 1) != 0 {
            count += 1;
        }
        n >>= 1;
    }
    count
}

/// Brian Kernighan's bit-clearing algorithm.
///
/// Iteratively clears the lowest set bit using `n & (n - 1)`.
/// Terminates as soon as all set bits have been cleared.
///
/// - Algorithmic complexity: Proportional to the number of set bits (k steps, where 0 <= k <= 64).
#[inline(never)]
pub fn popcount_kernighan(mut n: u64) -> u32 {
    let mut count = 0;
    while n != 0 {
        n &= n - 1;
        count += 1;
    }
    count
}

/// Optimized reference implementation using the Rust standard library `count_ones()`.
///
/// Compiles to the target platform's hardware instruction (e.g. `POPCNT` on x86-64)
/// or an optimized software bit-parallel fallback.
#[inline(never)]
pub fn popcount_reference(n: u64) -> u32 {
    n.count_ones()
}
