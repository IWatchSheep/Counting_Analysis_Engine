#![allow(non_snake_case)]
//! # Counting Analysis Engine (CAE)
//!
//! A framework to investigate what programs are counting, how they count,
//! and whether unnecessary work can be removed without altering the correct result.

pub mod algorithms;
pub mod archive;
pub mod dynamic_analysis;
pub mod instrumentation;
pub mod report;
pub mod static_analysis;
pub mod verification;

#[cfg(test)]
mod tests {
    use super::algorithms::*;
    use super::archive::*;
    use super::dynamic_analysis::*;
    use super::instrumentation::*;
    use super::static_analysis::*;
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
    fn test_exhaustive_16bit_subdomain_proof() {
        let (passed, count) = verify_exhaustive_16bit_subdomain();
        assert!(passed, "Exhaustive verification failed within 16-bit space");
        assert_eq!(count, 65536, "All 65,536 values in 16-bit space must be checked");
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
            assert_eq!(ops.opaque_invocations, 0, "Naive loop has 0 opaque intrinsic invocations");
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
            assert_eq!(ops.opaque_invocations, 0, "Kernighan has 0 opaque intrinsic invocations");
            assert_eq!(ops.condition_evaluations, k + 1, "Kernighan evaluates while-condition k + 1 times (terminates on zero)");
        }
    }

    #[test]
    fn test_reference_instrumentation_strict_invariants() {
        let (count, ops) = popcount_reference_instrumented(0x1234_5678_9ABC_DEF0);
        assert_eq!(count, 0x1234_5678_9ABC_DEF0u64.count_ones());
        assert_eq!(ops.loop_iterations, 0, "Reference count_ones has 0 source loop iterations");
        assert_eq!(ops.counter_updates, 0, "Reference count_ones performs 0 iterative counter updates");
        assert_eq!(ops.opaque_invocations, 1, "Reference count_ones performs 1 opaque intrinsic invocation");
        assert_eq!(ops.bitwise_ands, 0);
        assert_eq!(ops.condition_evaluations, 0);
    }

    #[test]
    fn test_address_stride_contraindication_avoids_false_positive() {
        #[rustfmt::skip]
        let code_bytes: &[u8] = &[
            0x8B, 0x07,             // mov eax, [rdi]
            0x48, 0x8D, 0x7F, 0x08, // lea rdi, [rdi + 8]
            0xFF, 0xC9,             // dec ecx
            0x75, 0xF7,             // jnz 0x0 (back to loop start)
            0xC3,                   // ret
        ];

        let profile = disassemble_buffer("synthetic_pointer_stride", code_bytes, 0x1000).unwrap();
        assert_eq!(profile.loops.len(), 1, "Must detect 1 static loop");

        let rdi_candidate = profile.candidate_accumulators.iter().find(|c| c.register_name == "RDI");
        assert!(rdi_candidate.is_some(), "RDI must be analyzed as a candidate");
        let rdi = rdi_candidate.unwrap();
        assert_eq!(rdi.role_hypothesis, AccumulatorRole::AddressStride, "RDI must be classified as AddressStride");
        assert_eq!(rdi.confidence, ConfidenceLevel::High);
        assert!(!rdi.contraindications.is_empty(), "Must report contraindication of memory dereference");
    }

    #[test]
    fn test_disassemble_live_functions() {
        let naive_profile = disassemble_function_pointer("popcount_naive", popcount_naive as *const (), 256).unwrap();
        let kernighan_profile = disassemble_function_pointer("popcount_kernighan", popcount_kernighan as *const (), 256).unwrap();
        let reference_profile = disassemble_function_pointer("popcount_reference", popcount_reference as *const (), 256).unwrap();

        assert!(naive_profile.total_instructions > 0);
        assert!(kernighan_profile.total_instructions > 0);
        assert!(reference_profile.total_instructions > 0);
        assert_eq!(reference_profile.loops.len(), 0, "Reference popcount has no static loops");
    }

    #[test]
    fn test_interpretation_archive_entries() {
        let archive = InterpretationArchive::populate_cae1b_findings();
        assert_eq!(archive.entries.len(), 6);

        let correct_count = archive.entries.iter().filter(|e| matches!(e.verdict, InterpretationVerdict::CorrectClassification)).count();
        let false_pos_avoided_count = archive.entries.iter().filter(|e| matches!(e.verdict, InterpretationVerdict::FalsePositiveAvoided { .. })).count();

        assert_eq!(correct_count, 5);
        assert_eq!(false_pos_avoided_count, 1);
    }

    #[test]
    fn test_dynamic_measurement_preserves_correctness() {
        let test_inputs = [0u64, 1, 0x5555_5555_5555_5555, u64::MAX];
        for &input in &test_inputs {
            let (naive_res, _) = measure_dynamic_kernel("popcount_naive", input, popcount_naive);
            let (kern_res, _) = measure_dynamic_kernel("popcount_kernighan", input, popcount_kernighan);
            let (ref_res, _) = measure_dynamic_kernel("popcount_reference", input, popcount_reference);

            assert_eq!(naive_res, input.count_ones());
            assert_eq!(kern_res, input.count_ones());
            assert_eq!(ref_res, input.count_ones());
        }
    }

    #[test]
    fn test_known_dynamic_instruction_step_scaling() {
        // Kernighan must scale dynamically with number of set bits k
        let k0 = step_count_kernighan(0);
        let k1 = step_count_kernighan(1);
        let k32 = step_count_kernighan(0x5555_5555_5555_5555);
        let k64 = step_count_kernighan(u64::MAX);

        assert!(k0 < k1);
        assert!(k1 < k32);
        assert!(k32 < k64);

        // Reference must be constant
        assert_eq!(step_count_reference(0), step_count_reference(u64::MAX));
    }

    #[test]
    fn test_optimization_archive_integrity() {
        let opt_archive = OptimizationArchive::populate_cae1c_findings();
        assert_eq!(opt_archive.entries.len(), 4);

        let accepted = opt_archive.entries.iter().any(|e| matches!(e.verdict, OptimizationVerdict::Accepted { .. }));
        let cond_accepted = opt_archive.entries.iter().any(|e| matches!(e.verdict, OptimizationVerdict::ConditionallyAccepted { .. }));
        let rejected = opt_archive.entries.iter().any(|e| matches!(e.verdict, OptimizationVerdict::Rejected { .. }));

        assert!(accepted, "Archive must contain accepted optimizations");
        assert!(cond_accepted, "Archive must contain conditionally accepted optimizations");
        assert!(rejected, "Archive must contain rejected optimizations");
    }
}
