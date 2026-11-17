#![allow(non_snake_case)]
//! # Counting Analysis Engine (CAE)
//!
//! A framework to investigate what programs are counting, how they count,
//! and whether unnecessary work can be removed without altering the correct result.

pub mod algorithms;
pub mod archive;
pub mod instrumentation;
pub mod report;
pub mod verification;

#[cfg(test)]
mod tests {
    use super::instrumentation::*;
    use super::verification::*;

    #[test]
    fn test_algorithms_agreement_on_standard_vectors() {
        let vectors = generate_standard_test_vectors();
        assert!(!vectors.is_empty(), "Standard test suite must not be empty");

        for vector in &vectors {
            let res = verify_input(vector.value);
            assert!(
                res.all_agree,
                "Algorithm mismatch for input {} ({}): naive={}, kernighan={}, reference={}, oracle={}",
                vector.name, vector.value, res.naive_result, res.kernighan_result, res.reference_result, res.oracle_result
            );
            assert_eq!(
                res.oracle_result, vector.expected_count,
                "Computed result did not match expected count for {}",
                vector.name
            );
        }
    }

    #[test]
    fn test_algorithms_agreement_on_deterministic_pseudorandom_inputs() {
        let mut rng = DeterministicRng::new(0xCAFE_BABE_DEAD_BEEF);
        const ITERATIONS: usize = 1_000;

        for _ in 0..ITERATIONS {
            let val = rng.next_u64();
            let res = verify_input(val);
            assert!(
                res.all_agree,
                "Mismatch on pseudorandom input 0x{:016X}: naive={}, kernighan={}, reference={}, oracle={}",
                val, res.naive_result, res.kernighan_result, res.reference_result, res.oracle_result
            );
        }
    }

    #[test]
    fn test_naive_instrumentation_strict_invariants() {
        let test_values = [0u64, 1, 7, 0x5555_5555_5555_5555, u64::MAX];

        for &val in &test_values {
            let (count, ops) = popcount_naive_instrumented(val);
            let expected_count = val.count_ones();

            assert_eq!(count, expected_count);
            // Fixed-width loop invariants:
            assert_eq!(ops.loop_iterations, 64, "Naive loop must always iterate 64 times");
            assert_eq!(ops.bit_shifts, 64, "Naive loop must always perform 64 shifts");
            assert_eq!(ops.bitwise_ands, 64, "Naive loop must always perform 64 bitwise ANDs");
            assert_eq!(ops.counter_updates, expected_count as u64, "Counter updates must match set bits count");
            assert_eq!(ops.condition_evaluations, 64 * 2 + 1, "Naive loop evaluates loop bound and bit check each pass plus final termination");
        }
    }

    #[test]
    fn test_kernighan_instrumentation_strict_invariants() {
        let test_values = [0u64, 1, 7, 0x5555_5555_5555_5555, u64::MAX];

        for &val in &test_values {
            let (count, ops) = popcount_kernighan_instrumented(val);
            let k = val.count_ones() as u64;

            assert_eq!(count, val.count_ones());
            // Proportional-to-k invariants:
            assert_eq!(ops.loop_iterations, k, "Kernighan iterations must strictly equal number of set bits");
            assert_eq!(ops.counter_updates, k, "Kernighan counter updates must strictly equal number of set bits");
            assert_eq!(ops.bitwise_ands, k, "Kernighan bitwise ANDs must strictly equal number of set bits");
            assert_eq!(ops.arithmetic_subtractions, k, "Kernighan subtractions must strictly equal number of set bits");
            assert_eq!(ops.condition_evaluations, k + 1, "Kernighan evaluates while-condition k + 1 times (terminates on zero)");
        }
    }

    #[test]
    fn test_reference_instrumentation_strict_invariants() {
        let (count, ops) = popcount_reference_instrumented(0x1234_5678_9ABC_DEF0);
        assert_eq!(count, 0x1234_5678_9ABC_DEF0u64.count_ones());
        assert_eq!(ops.loop_iterations, 0, "Reference count_ones has 0 source loop iterations");
        assert_eq!(ops.counter_updates, 1, "Reference count_ones performs 1 direct count update");
        assert_eq!(ops.bitwise_ands, 0);
        assert_eq!(ops.condition_evaluations, 0);
    }
}
