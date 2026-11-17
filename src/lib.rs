#![allow(non_snake_case)]
#![allow(clippy::bool_assert_comparison)]
//! # Counting Analysis Engine (CAE)
//!
//! A framework to investigate what programs are counting, how they count,
//! and whether unnecessary work can be removed without altering the correct result.

pub mod algorithms;
pub mod archive;
pub mod dynamic_analysis;
pub mod emulation;
pub mod instrumentation;
pub mod native_trace;
pub mod report;
pub mod static_analysis;
pub mod verification;
pub mod llm_protocol;

#[cfg(test)]
mod tests {
    use super::algorithms::*;
    use super::archive::*;
    use super::dynamic_analysis::*;
    use super::emulation::*;
    use super::instrumentation::*;
    use super::native_trace::*;
    use super::static_analysis::*;
    use super::verification::*;
    use super::llm_protocol::*;

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
        // Historical CAE-1C Model Prediction Invariants:
        // 1. Naive Model: 585 + 3*k
        assert_eq!(step_count_naive(0), 585);
        assert_eq!(step_count_naive(1), 588);
        assert_eq!(step_count_naive(0x5555_5555_5555_5555), 681);
        assert_eq!(step_count_naive(u64::MAX), 777);

        // 2. Kernighan Model: 9 + 13*k
        let k0 = step_count_kernighan(0);
        let k1 = step_count_kernighan(1);
        let k32 = step_count_kernighan(0x5555_5555_5555_5555);
        let k64 = step_count_kernighan(u64::MAX);

        assert_eq!(k0, 9);
        assert_eq!(k1, 22);
        assert_eq!(k32, 425);
        assert_eq!(k64, 841);
        assert!(k0 < k1);
        assert!(k1 < k32);
        assert!(k32 < k64);

        // 3. Reference Model: 7 (POPCNT assumption)
        assert_eq!(step_count_reference(0), 7);
        assert_eq!(step_count_reference(u64::MAX), 7);
    }

    #[test]
    fn test_optimization_archive_integrity() {
        let opt_archive = OptimizationArchive::populate_cae1c_findings();
        assert_eq!(opt_archive.entries.len(), 4);
        assert!(opt_archive.entries.iter().any(|e| matches!(e.verdict, OptimizationVerdict::Accepted { .. })));
        assert!(opt_archive.entries.iter().any(|e| matches!(e.verdict, OptimizationVerdict::ConditionallyAccepted { .. })));
        assert!(opt_archive.entries.iter().any(|e| matches!(e.verdict, OptimizationVerdict::Rejected { .. })));
    }

    // --- CAE-1D Phase 1: Machine-Code Emulation & Tracing Tests ---

    #[test]
    fn test_emulation_exp_a_straight_line() {
        let report = MicroExperiments::run_experiment_a(42);
        assert_eq!(report.status, EmulationStatus::CompletedSuccess);
        assert_eq!(report.termination_reason, TerminationReason::NormalRet);
        // Formula: (42 + 10) * 2 = 104
        assert_eq!(report.return_value, 104);
        assert_eq!(report.instruction_count, 4);

        let mnemonics: Vec<&str> = report.steps.iter().map(|s| s.mnemonic.as_str()).collect();
        assert_eq!(mnemonics, vec!["Mov", "Add", "Shl", "Ret"]);
    }

    #[test]
    fn test_emulation_exp_b_branch_even_not_taken() {
        // Input 10 is even -> test rcx, 1 produces ZF=1 -> JNZ is NOT taken -> executes mov eax, 100, ret
        let report = MicroExperiments::run_experiment_b(10);
        assert_eq!(report.status, EmulationStatus::CompletedSuccess);
        assert_eq!(report.return_value, 100);
        assert_eq!(report.instruction_count, 4);

        let mnemonics: Vec<&str> = report.steps.iter().map(|s| s.mnemonic.as_str()).collect();
        assert_eq!(mnemonics, vec!["Test", "Jne", "Mov", "Ret"]);
    }

    #[test]
    fn test_emulation_exp_b_branch_odd_taken() {
        // Input 11 is odd -> test rcx, 1 produces ZF=0 -> JNZ IS taken -> executes mov eax, 200, ret
        let report = MicroExperiments::run_experiment_b(11);
        assert_eq!(report.status, EmulationStatus::CompletedSuccess);
        assert_eq!(report.return_value, 200);
        assert_eq!(report.instruction_count, 4); // test, jnz [taken], mov 200, ret

        let mnemonics: Vec<&str> = report.steps.iter().map(|s| s.mnemonic.as_str()).collect();
        assert_eq!(mnemonics, vec!["Test", "Jne", "Mov", "Ret"]);
    }

    #[test]
    fn test_emulation_exp_c_bounded_loop_zero() {
        // Loop count 0: xor, test, jz [taken to ret], ret
        let report = MicroExperiments::run_experiment_c(0);
        assert_eq!(report.status, EmulationStatus::CompletedSuccess);
        assert_eq!(report.return_value, 0);
        assert_eq!(report.instruction_count, 4);
    }

    #[test]
    fn test_emulation_exp_c_bounded_loop_one() {
        // Loop count 1: xor, (test, jz [not taken], add, dec, jmp) * 1, test, jz [taken], ret
        let report = MicroExperiments::run_experiment_c(1);
        assert_eq!(report.status, EmulationStatus::CompletedSuccess);
        assert_eq!(report.return_value, 1);
        assert_eq!(report.instruction_count, 9);
    }

    #[test]
    fn test_emulation_exp_c_bounded_loop_five() {
        // Loop count 5: sum = 5+4+3+2+1 = 15. Total steps = 4 + 5 * 5 = 29.
        let report = MicroExperiments::run_experiment_c(5);
        assert_eq!(report.status, EmulationStatus::CompletedSuccess);
        assert_eq!(report.return_value, 15);
        assert_eq!(report.instruction_count, 29);
    }

    #[test]
    fn test_emulation_execution_budget_exhaustion() {
        // Infinite loop: jmp $ (EB FE)
        let infinite_loop: &[u8] = &[0xEB, 0xFE];
        let mut emu = X64MicroEmulator::new(infinite_loop, 0, 0, 50);
        let report = emu.run_trace("EXP-INF", "Infinite Loop", 0);

        assert_eq!(report.status, EmulationStatus::BudgetExceeded);
        assert_eq!(report.termination_reason, TerminationReason::BudgetExhausted(50));
        assert_eq!(report.instruction_count, 50);
    }

    #[test]
    fn test_emulation_invalid_opcode_handling() {
        // Invalid opcode: 0x0F, 0x0B (UD2 - undefined instruction)
        let invalid_code: &[u8] = &[0x0F, 0x0B];
        let mut emu = X64MicroEmulator::new(invalid_code, 0, 0, 10);
        let report = emu.run_trace("EXP-INV", "Invalid Opcode UD2", 0);

        let corrupt_code: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF];
        let mut corrupt_emu = X64MicroEmulator::new(corrupt_code, 0, 0, 10);
        let corrupt_report = corrupt_emu.run_trace("EXP-CORRUPT", "Corrupted Opcode", 0);

        assert!(
            matches!(report.termination_reason, TerminationReason::UnsupportedInstruction(_))
                || matches!(corrupt_report.termination_reason, TerminationReason::InvalidOpcode(_))
                || matches!(corrupt_report.termination_reason, TerminationReason::UnsupportedInstruction(_))
        );
    }

    #[test]
    fn test_emulation_repeatability_and_state_isolation() {
        let r1 = MicroExperiments::run_experiment_c(5);
        let r2 = MicroExperiments::run_experiment_c(5);

        assert_eq!(r1.instruction_count, r2.instruction_count);
        assert_eq!(r1.return_value, r2.return_value);
        assert_eq!(r1.steps.len(), r2.steps.len());

        for i in 0..r1.steps.len() {
            assert_eq!(r1.steps[i].address, r2.steps[i].address);
            assert_eq!(r1.steps[i].mnemonic, r2.steps[i].mnemonic);
            assert_eq!(r1.steps[i].registers_after, r2.steps[i].registers_after);
        }
    }

    #[test]
    fn test_emulation_assess_live_popcount_functions() {
        let test_val = 0x5555_5555_5555_5555u64;

        // 1. Reference
        let ref_rep = X64MicroEmulator::trace_live_function(
            popcount_reference as *const (),
            "popcount_reference",
            test_val,
            100,
        );
        eprintln!("\n=== Live popcount_reference Assessment ===");
        match ref_rep {
            Ok(rep) => {
                eprintln!("Status: {:?}", rep.status);
                eprintln!("Reason: {:?}", rep.termination_reason);
                eprintln!("Steps: {}", rep.instruction_count);
                eprintln!("Result: {} (expected {})", rep.return_value, test_val.count_ones());
                for s in &rep.steps {
                    eprintln!("  0x{:X}: {} {}", s.address, s.mnemonic, s.operands_str);
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }

        // 2. Kernighan
        let kern_rep = X64MicroEmulator::trace_live_function(
            popcount_kernighan as *const (),
            "popcount_kernighan",
            test_val,
            2_000,
        );
        eprintln!("\n=== Live popcount_kernighan Assessment ===");
        match kern_rep {
            Ok(rep) => {
                eprintln!("Status: {:?}", rep.status);
                eprintln!("Reason: {:?}", rep.termination_reason);
                eprintln!("Steps: {}", rep.instruction_count);
                eprintln!("Result: {} (expected {})", rep.return_value, test_val.count_ones());
                if rep.status != EmulationStatus::CompletedSuccess {
                    eprintln!("Last step: {:?}", rep.steps.last().map(|s| (&s.mnemonic, &s.operands_str)));
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }

        // 3. Naive
        let naive_rep = X64MicroEmulator::trace_live_function(
            popcount_naive as *const (),
            "popcount_naive",
            test_val,
            2_000,
        );
        eprintln!("\n=== Live popcount_naive Assessment ===");
        match naive_rep {
            Ok(rep) => {
                eprintln!("Status: {:?}", rep.status);
                eprintln!("Reason: {:?}", rep.termination_reason);
                eprintln!("Steps: {}", rep.instruction_count);
                eprintln!("Result: {} (expected {})", rep.return_value, test_val.count_ones());
                if rep.status != EmulationStatus::CompletedSuccess {
                    eprintln!("Last step: {:?}", rep.steps.last().map(|s| (&s.mnemonic, &s.operands_str)));
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    /// Black-Box Functional Differential Test (Rust ABI Return Value).
    ///
    /// SCIENTIFIC LIMITATION NOTE:
    /// Matching final return values proves functional input-output equivalence according to the
    /// compiler calling convention (RAX return value), but does NOT prove that every intermediate
    /// machine register, condition flag, stack spill, or unread operand was identically reproduced.
    /// Full architectural equivalence requires intermediate state bisimulation or hardware single-stepping.
    #[test]
    fn test_emulation_differential_oracle_comparison() {
        let test_cases = [
            ("Zero", 0u64),
            ("Sparse (1 bit)", 1u64),
            ("Small (3 bits)", 7u64),
            ("Alternating (32 bits)", 0x5555_5555_5555_5555u64),
            ("Dense (64 bits)", u64::MAX),
        ];

        for (name, val) in test_cases {
            let native_kern = popcount_kernighan(val);
            let emu_kern = X64MicroEmulator::trace_live_function(
                popcount_kernighan as *const (),
                "popcount_kernighan",
                val,
                5_000,
            ).expect("Kernighan emulation failed");

            assert_eq!(emu_kern.status, EmulationStatus::CompletedSuccess);
            assert_eq!(
                emu_kern.return_value as u32, native_kern,
                "Differential mismatch on {} (val=0x{:X}): native={}, emulator={}",
                name, val, native_kern, emu_kern.return_value
            );

            let native_ref = popcount_reference(val);
            let emu_ref = X64MicroEmulator::trace_live_function(
                popcount_reference as *const (),
                "popcount_reference",
                val,
                500,
            ).expect("Reference emulation failed");

            assert_eq!(emu_ref.status, EmulationStatus::CompletedSuccess);
            assert_eq!(
                emu_ref.return_value as u32, native_ref,
                "Differential mismatch on {} (val=0x{:X}): native={}, emulator={}",
                name, val, native_ref, emu_ref.return_value
            );

            eprintln!("Differential Match on {}: native={}, emu_kern_steps={}, emu_ref_steps={}",
                name, native_kern, emu_kern.instruction_count, emu_ref.instruction_count);
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_emulation_hardware_native_state_differential() {
        // 1. Experiment A: Straight-line execution
        let native_a = unsafe { MicroExperiments::execute_native_hardware_exp_a(42) };
        let emu_a = MicroExperiments::run_experiment_a(42);

        assert_eq!(emu_a.status, EmulationStatus::CompletedSuccess);
        assert_eq!(emu_a.final_registers.rax, native_a.rax, "RAX mismatch on Exp A");
        assert_eq!(emu_a.final_flags.zf, native_a.zf, "ZF flag mismatch on Exp A");
        assert_eq!(emu_a.final_flags.cf, native_a.cf, "CF flag mismatch on Exp A");
        assert_eq!(emu_a.final_flags.sf, native_a.sf, "SF flag mismatch on Exp A");
        // Verify native stack balance independently:
        assert_eq!(native_a.rsp_delta, 0, "Native host stack must be perfectly balanced across the asm block");
        // Verify virtual emulator stack frame balance independently:
        // Entry top_rsp = initial_rsp - 8; RET pops sentinel -> delta = +8.
        let emu_rsp_delta = emu_a.final_registers.rsp as i64 - emu_a.initial_registers.rsp as i64;
        assert_eq!(emu_rsp_delta, 8, "Emulator stack pointer delta must be exactly +8 bytes (sentinel RET popped)");

        // 2. Experiment B: Conditional Branching (Even input -> Not-Taken branch)
        let native_b_even = unsafe { MicroExperiments::execute_native_hardware_exp_b(10) };
        let emu_b_even = MicroExperiments::run_experiment_b(10);

        assert_eq!(emu_b_even.status, EmulationStatus::CompletedSuccess);
        assert_eq!(emu_b_even.final_registers.rax, native_b_even.rax, "RAX mismatch on Exp B (even)");
        assert_eq!(emu_b_even.final_flags.zf, native_b_even.zf, "ZF flag mismatch on Exp B (even)");
        assert_eq!(native_b_even.rsp_delta, 0);

        // 3. Experiment B: Conditional Branching (Odd input -> Taken branch)
        let native_b_odd = unsafe { MicroExperiments::execute_native_hardware_exp_b(11) };
        let emu_b_odd = MicroExperiments::run_experiment_b(11);

        assert_eq!(emu_b_odd.status, EmulationStatus::CompletedSuccess);
        assert_eq!(emu_b_odd.final_registers.rax, native_b_odd.rax, "RAX mismatch on Exp B (odd)");
        assert_eq!(emu_b_odd.final_flags.zf, native_b_odd.zf, "ZF flag mismatch on Exp B (odd)");
        assert_eq!(native_b_odd.rsp_delta, 0);

        // 4. Experiment C: Bounded Loop (n = 5)
        let native_c_5 = unsafe { MicroExperiments::execute_native_hardware_exp_c(5) };
        let emu_c_5 = MicroExperiments::run_experiment_c(5);

        assert_eq!(emu_c_5.status, EmulationStatus::CompletedSuccess);
        assert_eq!(emu_c_5.final_registers.rax, native_c_5.rax, "RAX mismatch on Exp C (n=5)");
        assert_eq!(emu_c_5.final_flags.zf, native_c_5.zf, "ZF flag mismatch on Exp C (n=5)");
        assert_eq!(native_c_5.rsp_delta, 0);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_condition_flags_arithmetic_boundaries_zf_cf_sf_of() {
        // Case 1: Zero Flag (ZF=true, CF=false, SF=false, OF=false)
        let nat_zero = unsafe { MicroExperiments::execute_native_sub(42, 42) };
        let emu_zero = MicroExperiments::run_dynamic_sub(42, 42);
        assert_eq!(nat_zero.rsp_delta, 0);
        assert_eq!(emu_zero.final_registers.rax, nat_zero.rax);
        assert_eq!(emu_zero.final_flags.zf, true);
        assert_eq!(nat_zero.zf, true);
        assert_eq!(emu_zero.final_flags.cf, false);
        assert_eq!(nat_zero.cf, false);
        assert_eq!(emu_zero.final_flags.sf, false);
        assert_eq!(nat_zero.sf, false);
        assert_eq!(emu_zero.final_flags.of, false);
        assert_eq!(nat_zero.of, false);

        // Case 2: Carry Flag on Subtraction Borrow (CF=true, SF=true, ZF=false, OF=false)
        let nat_borrow = unsafe { MicroExperiments::execute_native_sub(0, 1) };
        let emu_borrow = MicroExperiments::run_dynamic_sub(0, 1);
        assert_eq!(nat_borrow.rsp_delta, 0);
        assert_eq!(emu_borrow.final_registers.rax, nat_borrow.rax);
        assert_eq!(emu_borrow.final_flags.cf, true);
        assert_eq!(nat_borrow.cf, true);
        assert_eq!(emu_borrow.final_flags.sf, true);
        assert_eq!(nat_borrow.sf, true);
        assert_eq!(emu_borrow.final_flags.zf, false);
        assert_eq!(nat_borrow.zf, false);
        assert_eq!(emu_borrow.final_flags.of, false);
        assert_eq!(nat_borrow.of, false);

        // Case 3: Carry Flag on Unsigned Overflow (CF=true, ZF=true, SF=false, OF=false)
        let nat_uoverflow = unsafe { MicroExperiments::execute_native_add(u64::MAX, 1) };
        let emu_uoverflow = MicroExperiments::run_dynamic_add(u64::MAX, 1);
        assert_eq!(nat_uoverflow.rsp_delta, 0);
        assert_eq!(emu_uoverflow.final_registers.rax, nat_uoverflow.rax);
        assert_eq!(emu_uoverflow.final_flags.cf, true);
        assert_eq!(nat_uoverflow.cf, true);
        assert_eq!(emu_uoverflow.final_flags.zf, true);
        assert_eq!(nat_uoverflow.zf, true);
        assert_eq!(emu_uoverflow.final_flags.sf, false);
        assert_eq!(nat_uoverflow.sf, false);
        assert_eq!(emu_uoverflow.final_flags.of, false);
        assert_eq!(nat_uoverflow.of, false);

        // Case 4: Sign Flag on Negative Subtraction (SF=true, CF=true, ZF=false, OF=false)
        let nat_sign = unsafe { MicroExperiments::execute_native_sub(10, 20) };
        let emu_sign = MicroExperiments::run_dynamic_sub(10, 20);
        assert_eq!(nat_sign.rsp_delta, 0);
        assert_eq!(emu_sign.final_registers.rax, nat_sign.rax);
        assert_eq!(emu_sign.final_flags.sf, true);
        assert_eq!(nat_sign.sf, true);
        assert_eq!(emu_sign.final_flags.cf, true);
        assert_eq!(nat_sign.cf, true);
        assert_eq!(emu_sign.final_flags.zf, false);
        assert_eq!(nat_sign.zf, false);
        assert_eq!(emu_sign.final_flags.of, false);
        assert_eq!(nat_sign.of, false);

        // Case 5: Signed Overflow Flag on Positive Addition (OF=true, SF=true, ZF=false, CF=false)
        let max_i64_as_u64 = i64::MAX as u64; // 0x7FFF_FFFF_FFFF_FFFF
        let nat_soverflow_add = unsafe { MicroExperiments::execute_native_add(max_i64_as_u64, 1) };
        let emu_soverflow_add = MicroExperiments::run_dynamic_add(max_i64_as_u64, 1);
        assert_eq!(nat_soverflow_add.rsp_delta, 0);
        assert_eq!(emu_soverflow_add.final_registers.rax, nat_soverflow_add.rax);
        assert_eq!(emu_soverflow_add.final_flags.of, true);
        assert_eq!(nat_soverflow_add.of, true);
        assert_eq!(emu_soverflow_add.final_flags.sf, true);
        assert_eq!(nat_soverflow_add.sf, true);
        assert_eq!(emu_soverflow_add.final_flags.zf, false);
        assert_eq!(nat_soverflow_add.zf, false);
        assert_eq!(emu_soverflow_add.final_flags.cf, false);
        assert_eq!(nat_soverflow_add.cf, false);

        // Case 6: Signed Overflow Flag on Negative Subtraction (OF=true, CF=false, SF=false, ZF=false)
        let min_i64_as_u64 = i64::MIN as u64; // 0x8000_0000_0000_0000
        let nat_soverflow_sub = unsafe { MicroExperiments::execute_native_sub(min_i64_as_u64, 1) };
        let emu_soverflow_sub = MicroExperiments::run_dynamic_sub(min_i64_as_u64, 1);
        assert_eq!(nat_soverflow_sub.rsp_delta, 0);
        assert_eq!(emu_soverflow_sub.final_registers.rax, nat_soverflow_sub.rax);
        assert_eq!(emu_soverflow_sub.final_flags.of, true);
        assert_eq!(nat_soverflow_sub.of, true);
        assert_eq!(emu_soverflow_sub.final_flags.cf, false);
        assert_eq!(nat_soverflow_sub.cf, false);
        assert_eq!(emu_soverflow_sub.final_flags.sf, false);
        assert_eq!(nat_soverflow_sub.sf, false);
        assert_eq!(emu_soverflow_sub.final_flags.zf, false);
        assert_eq!(nat_soverflow_sub.zf, false);
    }

    #[test]
    fn test_interpretation_archive_cae1d_entries() {
        let archive = InterpretationArchive::populate_cae1d_findings();
        assert_eq!(archive.entries.len(), 10);

        let unresolved = archive.entries.iter().filter(|e| matches!(e.verdict, InterpretationVerdict::UnresolvedHypothesis { .. })).count();
        let false_pos = archive.entries.iter().filter(|e| matches!(e.verdict, InterpretationVerdict::FalsePositiveAvoided { .. })).count();

        assert_eq!(unresolved, 2, "Expected 2 UnresolvedHypothesis (intermediate state bisimulation and arbitrary program generalization)");
        assert_eq!(false_pos, 3, "Expected 3 FalsePositiveAvoided (synthetic pointer stride, hardware register capture, and in-process VEH)");
    }

    // --- CAE-1D Phase 2: Native Hardware Instruction Tracing Tests ---

    #[test]
    #[cfg(windows)]
    fn test_native_trace_exp_a_straight_line() {
        let report = WindowsNativeDebugger::trace_kernel("exp-a", 42, 100)
            .expect("Native trace of exp-a should succeed");

        assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(report.total_observed_instructions, 3, "Exp A has exactly 3 straight-line instructions");
        assert_eq!(report.return_value_rax, 104, "Formula (42 + 10) * 2 = 104");

        let mnemonics: Vec<&str> = report.steps.iter().map(|s| s.mnemonic.as_str()).collect();
        assert_eq!(mnemonics, vec!["mov", "add", "shl"]);
    }

    #[test]
    #[cfg(windows)]
    fn test_native_trace_exp_b_branch_even() {
        // Even input (42) -> test rcx, 1 produces ZF=1 -> JNZ is NOT taken -> executes mov eax, 100 -> jmp exit
        let report = WindowsNativeDebugger::trace_kernel("exp-b", 42, 100)
            .expect("Native trace of exp-b (even) should succeed");

        assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(report.total_observed_instructions, 4, "Exp B (even) executes 4 instructions");
        assert_eq!(report.return_value_rax, 100);

        let mnemonics: Vec<&str> = report.steps.iter().map(|s| s.mnemonic.as_str()).collect();
        assert_eq!(mnemonics, vec!["test", "jne", "mov", "jmp"]);
    }

    #[test]
    #[cfg(windows)]
    fn test_native_trace_exp_b_branch_odd() {
        // Odd input (7) -> test rcx, 1 produces ZF=0 -> JNZ IS taken -> executes mov eax, 200 -> exit
        let report = WindowsNativeDebugger::trace_kernel("exp-b", 7, 100)
            .expect("Native trace of exp-b (odd) should succeed");

        assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(report.total_observed_instructions, 3, "Exp B (odd) executes 3 instructions");
        assert_eq!(report.return_value_rax, 200);

        let mnemonics: Vec<&str> = report.steps.iter().map(|s| s.mnemonic.as_str()).collect();
        assert_eq!(mnemonics, vec!["test", "jne", "mov"]);
    }

    #[test]
    #[cfg(windows)]
    fn test_native_trace_exp_c_loop_zero() {
        // Loop count 0: xor, test, jz [taken]
        let report = WindowsNativeDebugger::trace_kernel("exp-c", 0, 100)
            .expect("Native trace of exp-c (0) should succeed");

        assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(report.total_observed_instructions, 3);
        assert_eq!(report.return_value_rax, 0);
        assert_eq!(report.final_flags.zf, true);

        let mnemonics: Vec<&str> = report.steps.iter().map(|s| s.mnemonic.as_str()).collect();
        assert_eq!(mnemonics, vec!["xor", "test", "je"]);
    }

    #[test]
    #[cfg(windows)]
    fn test_native_trace_exp_c_loop_one() {
        // Loop count 1: xor, (test, jz, add, dec, jmp) * 1, test, jz -> 1 + 5 + 2 = 8 instructions
        let report = WindowsNativeDebugger::trace_kernel("exp-c", 1, 100)
            .expect("Native trace of exp-c (1) should succeed");

        assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(report.total_observed_instructions, 8);
        assert_eq!(report.return_value_rax, 1);
        assert_eq!(report.final_registers.rcx, 0);
        assert_eq!(report.final_flags.zf, true);
    }

    #[test]
    #[cfg(windows)]
    fn test_native_trace_exp_c_loop_five() {
        // Loop count 5: 1 + 5*5 + 2 = 28 instructions. Sum = 15.
        let report = WindowsNativeDebugger::trace_kernel("exp-c", 5, 100)
            .expect("Native trace of exp-c (5) should succeed");

        assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(report.total_observed_instructions, 28);
        assert_eq!(report.return_value_rax, 15);
        assert_eq!(report.final_registers.rcx, 0);
        assert_eq!(report.final_flags.zf, true);
    }

    #[test]
    #[cfg(windows)]
    fn test_native_trace_budget_exhaustion_safety() {
        // Run loop with n=100 (which would be 503 steps), but cap budget at 10 steps.
        let report = WindowsNativeDebugger::trace_kernel("exp-c", 100, 10)
            .expect("Native trace with budget exhaustion should succeed cleanly");

        assert_eq!(report.status, NativeTraceStatus::BudgetExhausted(10));
        assert_eq!(report.total_observed_instructions, 10);
    }

    // --- CAE-1D Phase 3: Native Popcount (Kernighan) Tracing Tests ---

    #[test]
    #[cfg(windows)]
    fn test_native_trace_kernighan_debug_vectors() {
        let debug_exe = std::path::Path::new("target/debug/cae_trace_target.exe");
        if !debug_exe.exists() {
            let status = std::process::Command::new("cargo")
                .args(["build", "--bin", "cae_trace_target"])
                .status()
                .expect("Failed to build cae_trace_target");
            assert!(status.success());
        }

        // In Debug mode (top-tested loop with stack frame):
        // Formula: Total = 1 + (8 + 21*k), Internal = 8 + 21*k.
        // Backedges = k (unconditional jmp back to condition check).
        // Note: Epilogue `add rsp, 48h` updates RFLAGS and clears ZF (RSP != 0).
        let test_cases = [
            (0u64, 0u32, 9, 8, 0),                       // k=0: 1+8=9 steps, 0 backedges
            (1u64, 1u32, 30, 29, 1),                     // k=1: 1+29=30 steps, 1 backedge
            (7u64, 3u32, 72, 71, 3),                     // k=3: 1+71=72 steps, 3 backedges
            (0x5555_5555_5555_5555u64, 32u32, 681, 680, 32), // k=32: 1+680=681 steps, 32 backedges
            (u64::MAX, 64u32, 1353, 1352, 64),           // k=64: 1+1352=1353 steps, 64 backedges
        ];

        for (input, expected_count, expected_total_steps, expected_internal_steps, expected_backedges) in test_cases {
            let report = WindowsNativeDebugger::trace_kernel_with_exe(debug_exe, "kernighan", input, 2000)
                .expect("Native trace of kernighan should succeed");

            assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
            assert_eq!(report.return_value_rax as u32, expected_count);
            assert_eq!(
                report.total_observed_instructions, expected_total_steps,
                "Debug total observed steps mismatch for input 0x{:X}", input
            );
            assert_eq!(
                report.function_instruction_count(), expected_internal_steps,
                "Debug internal function steps mismatch for input 0x{:X}", input
            );
            assert_eq!(
                report.count_loop_backedges(), expected_backedges,
                "Debug loop backedges mismatch for input 0x{:X}", input
            );
            // Epilogue `add rsp, 48h` clears ZF on physical silicon:
            assert_eq!(report.final_flags.zf, false, "Epilogue add rsp, 48h clears ZF");
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_native_trace_kernighan_release_vectors() {
        let release_exe = std::path::Path::new("target/release/cae_trace_target.exe");
        if !release_exe.exists() {
            let status = std::process::Command::new("cargo")
                .args(["build", "--release", "--bin", "cae_trace_target"])
                .status()
                .expect("Failed to build cae_trace_target --release");
            assert!(status.success());
        }

        // In Release mode (bottom-tested loop, no stack frame):
        // Formula: For k=0: 1+4=5 total, 4 internal, 0 backedges.
        //          For k>=1: 1+(5+5*k) total, 5+5*k internal, k-1 backedges (fallthrough on final iteration).
        // Final flag: ZF=true (from test rcx,rcx for k=0, or and rcx,rdx for k>=1).
        let test_cases = [
            (0u64, 0u32, 5, 4, 0),                       // k=0: 1+4=5 steps, 0 backedges
            (1u64, 1u32, 11, 10, 0),                     // k=1: 1+10=11 steps, 0 backedges (fallthrough)
            (7u64, 3u32, 21, 20, 2),                     // k=3: 1+20=21 steps, 2 backedges
            (0x5555_5555_5555_5555u64, 32u32, 166, 165, 31), // k=32: 1+165=166 steps, 31 backedges
            (u64::MAX, 64u32, 326, 325, 63),             // k=64: 1+325=326 steps, 63 backedges
        ];

        for (input, expected_count, expected_total_steps, expected_internal_steps, expected_backedges) in test_cases {
            let report = WindowsNativeDebugger::trace_kernel_with_exe(release_exe, "kernighan", input, 2000)
                .expect("Native trace of kernighan (release) should succeed");

            assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
            assert_eq!(report.return_value_rax as u32, expected_count);
            assert_eq!(
                report.total_observed_instructions, expected_total_steps,
                "Release total observed steps mismatch for input 0x{:X}", input
            );
            assert_eq!(
                report.function_instruction_count(), expected_internal_steps,
                "Release internal function steps mismatch for input 0x{:X}", input
            );
            assert_eq!(
                report.count_loop_backedges(), expected_backedges,
                "Release loop backedges mismatch for input 0x{:X}", input
            );
            assert_eq!(report.final_flags.zf, true, "ZF must be 1 upon exit in release build");
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_native_trace_rsp_and_flag_transitions_before_and_after() {
        let debug_exe = std::path::Path::new("target/debug/cae_trace_target.exe");
        let report = WindowsNativeDebugger::trace_kernel_with_exe(debug_exe, "kernighan", 1, 100)
            .expect("Native trace of kernighan (k=1) should succeed");

        assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(report.total_observed_instructions, 30);

        // 1. Verify Step 1: `call` instruction pushes 8-byte return address
        let step_call = &report.steps[0];
        assert_eq!(step_call.mnemonic, "call");
        assert_eq!(step_call.rsp_before - step_call.registers_after.rsp, 8, "CALL must push 8-byte return address");

        // 2. Verify Step 2: `sub rsp, 48h` allocates 72-byte stack frame
        let step_prologue = &report.steps[1];
        assert_eq!(step_prologue.mnemonic, "sub");
        assert_eq!(step_prologue.rsp_before - step_prologue.registers_after.rsp, 72, "Prologue must allocate 72-byte stack frame");

        // 3. Verify Step 29: `add rsp, 48h` deallocates frame AND overwrites condition flag ZF
        let step_epilogue = &report.steps[28];
        assert_eq!(step_epilogue.mnemonic, "add");
        assert_eq!(step_epilogue.registers_after.rsp - step_epilogue.rsp_before, 72, "Epilogue must restore 72 bytes to RSP");
        assert_eq!(step_epilogue.flags_before.zf, true, "ZF must be 1 from termination check before epilogue add");
        assert_eq!(step_epilogue.flags_after.zf, false, "Epilogue add rsp, 48h arithmetic must clear ZF");

        // 4. Verify Step 30: `ret` pops 8-byte return address and restores caller RSP
        let step_ret = &report.steps[29];
        assert_eq!(step_ret.mnemonic, "ret");
        assert_eq!(step_ret.registers_after.rsp - step_ret.rsp_before, 8, "RET must pop 8-byte return address");
        assert_eq!(step_ret.registers_after.rsp, step_call.rsp_before, "RSP must be fully restored to initial caller RSP");
    }

    #[test]
    #[cfg(windows)]
    fn test_prediction_vs_observation_scientific_audit() {
        let debug_exe = std::path::Path::new("target/debug/cae_trace_target.exe");
        let release_exe = std::path::Path::new("target/release/cae_trace_target.exe");

        let test_cases = [
            (0u64, 0usize),
            (1u64, 1usize),
            (7u64, 3usize),
            (0x5555_5555_5555_5555u64, 32usize),
            (u64::MAX, 64usize),
        ];

        for (input, k) in test_cases {
            // Independent CAE-1C Model Prediction (step_count_kernighan = 9 + 13*k)
            let predicted = step_count_kernighan(input) as usize;
            assert_eq!(predicted, 9 + 13 * k, "CAE-1C baseline formula invariant");

            // Debug Observation vs Prediction
            let rep_dbg = WindowsNativeDebugger::trace_kernel_with_exe(debug_exe, "kernighan", input, 2000)
                .expect("Debug trace must succeed");
            let observed_dbg_internal = rep_dbg.function_instruction_count();
            let dbg_discrepancy = observed_dbg_internal as isize - predicted as isize;
            // Analytical discrepancy for debug: (8 + 21*k) - (9 + 13*k) = 8*k - 1
            let expected_dbg_discrepancy = (8 * k as isize) - 1;
            assert_eq!(dbg_discrepancy, expected_dbg_discrepancy, "Debug model discrepancy audit for input 0x{:X}", input);

            // Release Observation vs Prediction
            let rep_rel = WindowsNativeDebugger::trace_kernel_with_exe(release_exe, "kernighan", input, 2000)
                .expect("Release trace must succeed");
            let observed_rel_internal = rep_rel.function_instruction_count();
            let rel_discrepancy = observed_rel_internal as isize - predicted as isize;
            let expected_rel_discrepancy = if k == 0 {
                4 - 9 // -5
            } else {
                (5 + 5 * k as isize) - (9 + 13 * k as isize) // -8*k - 4
            };
            assert_eq!(rel_discrepancy, expected_rel_discrepancy, "Release model discrepancy audit for input 0x{:X}", input);
        }
    }

    // --- CAE-1D Phase 4: Native Naive and Reference (count_ones) Tracing Tests ---

    #[test]
    #[cfg(windows)]
    fn test_native_trace_naive_debug_vectors() {
        let debug_exe = std::path::Path::new("target/debug/cae_trace_target.exe");
        // Rigorous Branch Breakdown for naive in Debug:
        // - Loop header backedge (jmp short 00007FF68A073065h): exactly 64 times for all inputs.
        // - Increment forward join (jmp short 00007FF68A073093h, which jumps backward over the shift): exactly k times.
        // - Total backward branch instructions executed: 64 + k.
        // - True loop header induction backedges: exactly 64.
        let test_cases = [
            (0u64, 0u32, 4653, 4652, 64, 64),
            (1u64, 1u32, 4661, 4660, 65, 64),
            (7u64, 3u32, 4677, 4676, 67, 64),
            (0x5555_5555_5555_5555u64, 32u32, 4909, 4908, 96, 64),
            (u64::MAX, 64u32, 5165, 5164, 128, 64),
        ];

        for (input, expected_count, expected_total, expected_internal, expected_backward_branches, expected_header_backedges) in test_cases {
            let report = WindowsNativeDebugger::trace_kernel_with_exe(debug_exe, "naive", input, 10000)
                .expect("Native trace of naive (debug) should succeed");

            assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
            assert_eq!(report.return_value_rax as u32, expected_count);
            assert_eq!(report.total_observed_instructions, expected_total, "Mismatch on input 0x{:X}", input);
            assert_eq!(report.function_instruction_count(), expected_internal, "Mismatch on input 0x{:X}", input);
            assert_eq!(report.count_backward_branches(), expected_backward_branches, "Backward branches mismatch on input 0x{:X}", input);

            // Audit true loop header backedges specifically:
            // The loop header backedge is the unconditional jump returning to the Range iterator loop header.
            // We identify the header target address dynamically from the first loop iteration rather than hardcoding ASLR strings.
            let header_target = report.steps.iter().enumerate().find_map(|(i, s)| {
                if i + 1 < report.steps.len() {
                    let next = &report.steps[i + 1];
                    if next.address < s.address && s.mnemonic == "jmp" {
                        return Some(next.address);
                    }
                }
                None
            });
            let header_backedges = report.steps.iter().enumerate().filter(|(i, s)| {
                if *i + 1 < report.steps.len() {
                    let next = &report.steps[*i + 1];
                    s.mnemonic == "jmp" && Some(next.address) == header_target
                } else {
                    false
                }
            }).count();
            assert_eq!(header_backedges, expected_header_backedges, "Header backedges mismatch on input 0x{:X}", input);
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_trace_step_indexing_integrity() {
        let release_exe = std::path::Path::new("target/release/cae_trace_target.exe");
        let report = WindowsNativeDebugger::trace_kernel_with_exe(release_exe, "reference", 1, 1000)
            .expect("Native trace of reference (release) must succeed");

        assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(report.total_observed_instructions, 21, "Total observed instructions must be exactly 21");
        assert_eq!(report.function_instruction_count(), 20, "Function internal instructions must be exactly 20");
        assert_eq!(report.steps.len(), 21, "Report steps vector length must be exactly 21");

        // Rigorous check: Every step's step_index must strictly equal its 1-based index (1..=21)
        for (i, step) in report.steps.iter().enumerate() {
            assert_eq!(step.step_index, i + 1, "Step index must match 1-based vector index");
        }
        let last_step = report.steps.last().unwrap();
        assert_eq!(last_step.step_index, 21, "Final step (RET) step_index must be 21, not 22");
        assert_eq!(last_step.mnemonic, "ret", "Final instruction must be RET");
    }

    #[test]
    #[cfg(windows)]
    fn test_native_trace_naive_release_vectors() {
        let release_exe = std::path::Path::new("target/release/cae_trace_target.exe");
        let test_cases = [
            (0u64, 0u32),
            (1u64, 1u32),
            (7u64, 3u32),
            (0x5555_5555_5555_5555u64, 32u32),
            (u64::MAX, 64u32),
        ];

        for (input, expected_count) in test_cases {
            let report = WindowsNativeDebugger::trace_kernel_with_exe(release_exe, "naive", input, 5000)
                .expect("Native trace of naive (release) should succeed");

            assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
            assert_eq!(report.return_value_rax as u32, expected_count);
            // In release, unrolled straight-line bit-test sequence: exactly 1 dispatch call + 196 internal instrs
            assert_eq!(report.total_observed_instructions, 197);
            assert_eq!(report.function_instruction_count(), 196);
            assert_eq!(report.count_loop_backedges(), 0, "Unrolled sequence has zero loop backedges");
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_native_trace_reference_debug_vectors() {
        let debug_exe = std::path::Path::new("target/debug/cae_trace_target.exe");
        let test_cases = [
            (0u64, 0u32),
            (1u64, 1u32),
            (7u64, 3u32),
            (0x5555_5555_5555_5555u64, 32u32),
            (u64::MAX, 64u32),
        ];

        for (input, expected_count) in test_cases {
            let report = WindowsNativeDebugger::trace_kernel_with_exe(debug_exe, "reference", input, 1000)
                .expect("Native trace of reference (debug) should succeed");

            assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
            assert_eq!(report.return_value_rax as u32, expected_count);
            // Default target baseline: software bitwise tree (24 internal instrs + 1 call)
            assert_eq!(report.total_observed_instructions, 25);
            assert_eq!(report.function_instruction_count(), 24);
            assert_eq!(report.count_loop_backedges(), 0);
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_native_trace_reference_release_vectors() {
        let release_exe = std::path::Path::new("target/release/cae_trace_target.exe");
        let test_cases = [
            (0u64, 0u32),
            (1u64, 1u32),
            (7u64, 3u32),
            (0x5555_5555_5555_5555u64, 32u32),
            (u64::MAX, 64u32),
        ];

        for (input, expected_count) in test_cases {
            let report = WindowsNativeDebugger::trace_kernel_with_exe(release_exe, "reference", input, 1000)
                .expect("Native trace of reference (release) should succeed");

            assert_eq!(report.status, NativeTraceStatus::CompletedSuccess);
            assert_eq!(report.return_value_rax as u32, expected_count);
            // In release: software bitwise tree without stack frame (20 internal instrs + 1 call)
            assert_eq!(report.total_observed_instructions, 21);
            assert_eq!(report.function_instruction_count(), 20);
            assert_eq!(report.count_loop_backedges(), 0);
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_native_trace_kernighan_budget_exhaustion() {
        let debug_exe = std::path::Path::new("target/debug/cae_trace_target.exe");
        let report = WindowsNativeDebugger::trace_kernel_with_exe(debug_exe, "kernighan", u64::MAX, 50)
            .expect("Native trace of kernighan with budget 50 should cleanly terminate");

        assert_eq!(report.status, NativeTraceStatus::BudgetExhausted(50));
        assert_eq!(report.total_observed_instructions, 50);
    }

    // --- CAE-1E Phase 1: Experimental Protocol & Prediction Archive Tests ---

    #[test]
    fn test_sha256_nist_and_boundary_vectors() {
        // NIST Vector 1: Empty string
        assert_eq!(
            compute_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // NIST Vector 2: "abc"
        assert_eq!(
            compute_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        // NIST Vector 3: 56 bytes (single-block boundary condition padding check)
        let msg56 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(msg56.len(), 56);
        assert_eq!(
            compute_sha256(msg56),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );

        // Multi-block vector: 1000 repetitions of 'a'
        let msg1000 = vec![b'a'; 1000];
        assert_eq!(
            compute_sha256(&msg1000),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    #[test]
    fn test_experiment_definitions_calibration_set() {
        let exps = ExperimentDefinition::populate_standard_calibration_experiments();
        assert_eq!(exps.len(), 6, "Must define exactly 6 calibration experiments");

        let mut ids = std::collections::HashSet::new();
        for exp in &exps {
            assert!(ids.insert(&exp.experiment_id), "Duplicate experiment ID: {}", exp.experiment_id);
            assert_eq!(exp.classification, ExperimentClassification::Calibration);
            assert!(!exp.permitted_information.is_empty());
        }
    }

    #[test]
    fn test_canonical_digest_protects_all_prediction_fields() {
        let base_structured = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::Linear { intercept: 9, slope: 13 },
            loop_branch: LoopBranchHypothesis::LoopWithBackedges {
                loop_header_backedges: "64 iterations".to_string(),
                backward_join_branches: Some("k joins".to_string()),
            },
            register_roles: vec![
                RegisterRoleHypothesis { register_name: "RAX".to_string(), hypothesized_role: "accumulator".to_string() },
            ],
            confidence_percent: Some(85),
            notes_and_rationale: "Analytical model".to_string(),
        };

        let base_record = PredictionRecord::new_draft(
            "PRED-BASE",
            "CAE-1E-CAL-003",
            "Model-A",
            "Initial prompt response text",
            base_structured.clone(),
            "2026-11-17T12:00:00Z",
        );
        let base_hash = base_record.compute_canonical_hash();

        // 1. Changing original text changes digest
        let mut r = base_record.clone();
        r.update_draft(base_structured.clone(), "Modified response text").unwrap();
        assert_ne!(r.compute_canonical_hash(), base_hash);

        // 2. Changing instruction count hypothesis changes digest
        let mut s_mod = base_structured.clone();
        s_mod.instruction_count = InstructionCountHypothesis::Linear { intercept: 8, slope: 13 };
        let mut r = base_record.clone();
        r.update_draft(s_mod, "Initial prompt response text").unwrap();
        assert_ne!(r.compute_canonical_hash(), base_hash);

        // 3. Changing loop/branch hypothesis changes digest
        let mut s_mod = base_structured.clone();
        s_mod.loop_branch = LoopBranchHypothesis::Unrolled { explanation: "unrolled".to_string() };
        let mut r = base_record.clone();
        r.update_draft(s_mod, "Initial prompt response text").unwrap();
        assert_ne!(r.compute_canonical_hash(), base_hash);

        // 4. Changing register roles changes digest
        let mut s_mod = base_structured.clone();
        s_mod.register_roles.push(RegisterRoleHypothesis { register_name: "RCX".to_string(), hypothesized_role: "counter".to_string() });
        let mut r = base_record.clone();
        r.update_draft(s_mod, "Initial prompt response text").unwrap();
        assert_ne!(r.compute_canonical_hash(), base_hash);

        // 5. Changing confidence percent changes digest
        let mut s_mod = base_structured.clone();
        s_mod.confidence_percent = Some(95);
        let mut r = base_record.clone();
        r.update_draft(s_mod, "Initial prompt response text").unwrap();
        assert_ne!(r.compute_canonical_hash(), base_hash);

        // 6. Changing notes/rationale changes digest
        let mut s_mod = base_structured.clone();
        s_mod.notes_and_rationale = "Altered rationale".to_string();
        let mut r = base_record.clone();
        r.update_draft(s_mod, "Initial prompt response text").unwrap();
        assert_ne!(r.compute_canonical_hash(), base_hash);

        // 7. Changing model configuration changes digest
        let mut r = base_record.clone();
        r.set_model_configuration(Some("temp=0.7".to_string())).unwrap();
        assert_ne!(r.compute_canonical_hash(), base_hash);
    }

    #[test]
    fn test_prediction_record_lifecycle_and_immutability() {
        let structured = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::Linear { intercept: 9, slope: 13 },
            loop_branch: LoopBranchHypothesis::LoopWithBackedges {
                loop_header_backedges: "k backedges".to_string(),
                backward_join_branches: None,
            },
            register_roles: vec![
                RegisterRoleHypothesis { register_name: "RAX".to_string(), hypothesized_role: "bitmask".to_string() },
            ],
            confidence_percent: Some(85),
            notes_and_rationale: "Analytical model of Kernighan popcount".to_string(),
        };

        let mut record = PredictionRecord::new_draft(
            "PRED-001",
            "CAE-1E-CAL-003",
            "Model-GPT-Calibration",
            "I predict 9 + 13*k instructions with k backedges.",
            structured.clone(),
            "2026-11-17T12:00:00Z",
        );

        assert_eq!(record.state(), PredictionState::Draft);
        assert!(record.verify_integrity());

        // Update draft allowed
        let mut modified_structured = structured.clone();
        modified_structured.confidence_percent = Some(90);
        assert!(record.update_draft(modified_structured, "Updated text: 9 + 13*k").is_ok());
        assert_eq!(record.structured_prediction().confidence_percent, Some(90));
        assert!(record.verify_integrity());

        // Freeze prediction
        assert!(record.freeze().is_ok());
        assert_eq!(record.state(), PredictionState::Frozen);
        assert!(record.verify_integrity());

        // Attempting to modify frozen prediction via any mutation method must be rejected
        let rejected = record.update_draft(structured.clone(), "Illegal edit");
        assert!(matches!(rejected, Err(PredictionProtocolError::FrozenPredictionImmutable { .. })));
        let rejected_cfg = record.set_model_configuration(Some("temp=0".to_string()));
        assert!(matches!(rejected_cfg, Err(PredictionProtocolError::FrozenPredictionImmutable { .. })));

        // Cannot skip to Archived
        assert!(record.archive().is_err());

        // Transition Frozen -> Verified -> Archived
        assert!(record.mark_verified().is_ok());
        assert_eq!(record.state(), PredictionState::Verified);
        assert!(record.archive().is_ok());
        assert_eq!(record.state(), PredictionState::Archived);

        // Cannot transition backwards
        assert!(record.freeze().is_err());
    }

    #[test]
    fn test_disproven_prediction_evaluation_and_archival() {
        // Demonstrates that a disproven prediction can be evaluated (mark_verified)
        // and archived with its PlausibleSemanticFailure verdict, without being falsely marked correct.
        let false_hypothesis = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::Linear { intercept: 585, slope: 3 },
            loop_branch: LoopBranchHypothesis::LoopWithBackedges {
                loop_header_backedges: "64 iterations".to_string(),
                backward_join_branches: None,
            },
            register_roles: vec![],
            confidence_percent: Some(99),
            notes_and_rationale: "Hypothesized that release popcount retains 64-step loop".to_string(),
        };

        let mut record = PredictionRecord::new_draft(
            "PRED-DISPROVEN-001",
            "CAE-1E-CAL-002",
            "Model-Predictor",
            "Predicts naive loop in release build.",
            false_hypothesis,
            "2026-11-17T12:00:00Z",
        );

        record.freeze().unwrap();

        // Link evidence showing complete unrolling (196 instructions, 0 backedges)
        let evidence = EvidenceRecord {
            evidence_id: "EV-DISPROVEN-001".to_string(),
            experiment_id: "CAE-1E-CAL-002".to_string(),
            prediction_id: "PRED-DISPROVEN-001".to_string(),
            collection_timestamp_iso8601: "2026-11-17T12:15:00Z".to_string(),
            native_trace: Some(NativeTraceEvidence {
                target_executable_name: "cae_trace_target.exe".to_string(),
                target_executable_sha256: None,
                compiler_profile: "Release".to_string(),
                test_inputs_evaluated: vec![0, 1, 7, 0x5555_5555_5555_5555, u64::MAX],
                observed_instruction_counts: vec![(0, 196), (1, 196), (7, 196), (0x5555_5555_5555_5555, 196), (u64::MAX, 196)],
                loop_header_backedges_observed: Some(0),
                total_backward_branches_observed: Some(0),
                key_register_states_observed: vec![],
                trace_artifact_reference: "trace_release_naive.txt".to_string(),
            }),
            discrepancy_summary: "Observed flat 196 instrs and 0 backedges vs. predicted 585+3k with 64 backedges".to_string(),
            scientific_verdict: ScientificVerdict::PlausibleSemanticFailure,
            verdict_explanation: "LLVM completely unrolled loop into straight-line BT/ADC sequences; prediction falsified.".to_string(),
            evidence_disclosed_prior_to_prediction: false,
        };

        assert_eq!(evidence.scientific_verdict, ScientificVerdict::PlausibleSemanticFailure);

        // Lifecycle transition: evaluation completed -> archived
        assert!(record.mark_verified().is_ok());
        assert_eq!(record.state(), PredictionState::Verified);
        assert!(record.archive().is_ok());
        assert_eq!(record.state(), PredictionState::Archived);
    }

    #[test]
    fn test_instruction_count_hypothesis_evaluation() {
        // Constant model
        let c = InstructionCountHypothesis::Constant(196);
        assert_eq!(c.evaluate_popcount(0), Some(196));
        assert_eq!(c.evaluate_popcount(32), Some(196));

        // Linear model: 9 + 13*k
        let lin = InstructionCountHypothesis::Linear { intercept: 9, slope: 13 };
        assert_eq!(lin.evaluate_popcount(0), Some(9));
        assert_eq!(lin.evaluate_popcount(1), Some(22));
        assert_eq!(lin.evaluate_popcount(32), Some(425));

        // Piecewise popcount model: 4 if k=0, 5 + 5*k if k>=1
        let piece = InstructionCountHypothesis::PiecewisePopcount {
            zero_case: 4,
            non_zero_intercept: 5,
            non_zero_slope: 5,
        };
        assert_eq!(piece.evaluate_popcount(0), Some(4));
        assert_eq!(piece.evaluate_popcount(1), Some(10));
        assert_eq!(piece.evaluate_popcount(32), Some(165));

        // Unknown and Abstention evaluate to None
        let unk = InstructionCountHypothesis::Unknown { reason: "Indirect jump target not provided".to_string() };
        assert_eq!(unk.evaluate_popcount(32), None);

        let abst = InstructionCountHypothesis::Abstention { reason: "Cannot determine without knowing runtime helper".to_string() };
        assert_eq!(abst.evaluate_popcount(32), None);
    }

    #[test]
    fn test_evidence_provenance_linkage() {
        let evidence = EvidenceRecord {
            evidence_id: "EV-001".to_string(),
            experiment_id: "CAE-1E-CAL-004".to_string(),
            prediction_id: "PRED-001".to_string(),
            collection_timestamp_iso8601: "2026-11-17T12:05:00Z".to_string(),
            native_trace: Some(NativeTraceEvidence {
                target_executable_name: "cae_trace_target.exe".to_string(),
                target_executable_sha256: Some("dummy-hash".to_string()),
                compiler_profile: "Release".to_string(),
                test_inputs_evaluated: vec![0, 1, 7, 0x5555_5555_5555_5555, u64::MAX],
                observed_instruction_counts: vec![(0, 4), (1, 10), (7, 40), (0x5555_5555_5555_5555, 165), (u64::MAX, 325)],
                loop_header_backedges_observed: Some(31),
                total_backward_branches_observed: Some(31),
                key_register_states_observed: vec!["RCX=0".to_string(), "EAX=result".to_string()],
                trace_artifact_reference: "native_trace_log_001.txt".to_string(),
            }),
            discrepancy_summary: "Observed counts match piecewise formula: 4 if k=0 else 5 + 5*k".to_string(),
            scientific_verdict: ScientificVerdict::VerifiedPrediction,
            verdict_explanation: "Predicted linear loop matches native single-step trace in release profile.".to_string(),
            evidence_disclosed_prior_to_prediction: false,
        };

        assert_eq!(evidence.scientific_verdict, ScientificVerdict::VerifiedPrediction);
        assert!(!evidence.evidence_disclosed_prior_to_prediction);
    }

    #[test]
    fn test_unresolved_discrepancy_and_missing_evidence_handling() {
        let unresolved = EvidenceRecord {
            evidence_id: "EV-002".to_string(),
            experiment_id: "CAE-1E-CAL-001".to_string(),
            prediction_id: "PRED-002".to_string(),
            collection_timestamp_iso8601: "2026-11-17T12:10:00Z".to_string(),
            native_trace: None,
            discrepancy_summary: "Execution trace was interrupted by debugger timeout".to_string(),
            scientific_verdict: ScientificVerdict::UnresolvedDiscrepancy,
            verdict_explanation: "Trace incomplete; cannot assign attribution to predictor or harness.".to_string(),
            evidence_disclosed_prior_to_prediction: false,
        };

        assert_eq!(unresolved.scientific_verdict, ScientificVerdict::UnresolvedDiscrepancy);
        assert!(unresolved.native_trace.is_none(), "Missing evidence must be represented as None without fabrication");
    }

    // --- CAE-1E Phase 2: Durable Storage & Integrity Verification Tests ---

    #[test]
    fn test_durable_storage_roundtrip_and_reload() {
        let temp_dir = std::env::temp_dir().join(format!("cae_test_store_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation should succeed");

        // 1. Experiment definition roundtrip
        let exps = ExperimentDefinition::populate_standard_calibration_experiments();
        let exp = &exps[2]; // CAE-1E-CAL-003
        store.save_experiment(exp).expect("Save experiment should succeed");
        let reloaded_exp = store.load_experiment(&exp.experiment_id).expect("Load experiment should succeed");
        assert_eq!(*exp, reloaded_exp);

        // 2. Prediction record roundtrip
        let structured = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::Linear { intercept: 9, slope: 13 },
            loop_branch: LoopBranchHypothesis::LoopWithBackedges {
                loop_header_backedges: "k backedges".to_string(),
                backward_join_branches: Some("none".to_string()),
            },
            register_roles: vec![
                RegisterRoleHypothesis { register_name: "RAX".to_string(), hypothesized_role: "bitmask".to_string() },
            ],
            confidence_percent: Some(92),
            notes_and_rationale: "Kernighan debug model hypothesis".to_string(),
        };

        let mut record = PredictionRecord::new_draft(
            "PRED-ROUNDTRIP-001",
            "CAE-1E-CAL-003",
            "Model-Durable-Test",
            "Original verbatim response predicting 9 + 13*k",
            structured,
            "2026-11-17T12:00:00Z",
        );
        record.freeze().expect("Freeze must succeed");
        let orig_hash = record.canonical_sha256().to_string();

        store.save_prediction(&record).expect("Save prediction should succeed");

        // Load prediction back and verify all fields + canonical digest
        let reloaded_pred = store.load_prediction("PRED-ROUNDTRIP-001").expect("Load prediction should succeed");
        assert_eq!(reloaded_pred.prediction_id(), "PRED-ROUNDTRIP-001");
        assert_eq!(reloaded_pred.experiment_id(), "CAE-1E-CAL-003");
        assert_eq!(reloaded_pred.model_identifier(), "Model-Durable-Test");
        assert_eq!(reloaded_pred.state(), PredictionState::Frozen);
        assert_eq!(reloaded_pred.canonical_sha256(), orig_hash);
        assert!(reloaded_pred.verify_integrity());

        // 3. Evidence record roundtrip
        let evidence = EvidenceRecord {
            evidence_id: "EV-ROUNDTRIP-001".to_string(),
            experiment_id: "CAE-1E-CAL-003".to_string(),
            prediction_id: "PRED-ROUNDTRIP-001".to_string(),
            collection_timestamp_iso8601: "2026-11-17T12:30:00Z".to_string(),
            native_trace: Some(NativeTraceEvidence {
                target_executable_name: "cae_trace_target.exe".to_string(),
                target_executable_sha256: Some("sha256-dummy".to_string()),
                compiler_profile: "Debug".to_string(),
                test_inputs_evaluated: vec![0, 1, 32],
                observed_instruction_counts: vec![(0, 8), (1, 29), (32, 680)],
                loop_header_backedges_observed: Some(32),
                total_backward_branches_observed: Some(32),
                key_register_states_observed: vec!["RAX=result".to_string()],
                trace_artifact_reference: "trace_debug_kernighan.txt".to_string(),
            }),
            discrepancy_summary: "Observed 8 + 21*k vs predicted 9 + 13*k".to_string(),
            scientific_verdict: ScientificVerdict::PlausibleSemanticFailure,
            verdict_explanation: "Stack spills and debug checks add 8 instructions per loop iteration".to_string(),
            evidence_disclosed_prior_to_prediction: false,
        };

        store.append_evidence(&evidence).expect("Append evidence should succeed");
        let reloaded_ev = store.load_evidence("EV-ROUNDTRIP-001").expect("Load evidence should succeed");
        assert_eq!(evidence, reloaded_ev);

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_durable_storage_corruption_and_tamper_detection() {
        let temp_dir = std::env::temp_dir().join(format!("cae_tamper_store_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation should succeed");

        let structured = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::Linear { intercept: 9, slope: 13 },
            loop_branch: LoopBranchHypothesis::StraightLine,
            register_roles: vec![],
            confidence_percent: Some(80),
            notes_and_rationale: "Untampered record".to_string(),
        };

        let mut record = PredictionRecord::new_draft(
            "PRED-TAMPER-001",
            "CAE-1E-CAL-003",
            "Model-X",
            "Original prediction text",
            structured,
            "2026-11-17T12:00:00Z",
        );
        record.freeze().expect("Freeze must succeed");
        store.save_prediction(&record).expect("Save must succeed");

        // Tamper directly with the file on disk: alter the intercept from 9 to 8
        let pred_file = temp_dir.join("predictions").join("PRED-TAMPER-001.prediction");
        let file_content = std::fs::read_to_string(&pred_file).expect("File read should succeed");
        let tampered_content = file_content.replace("Linear:9:13", "Linear:8:13");
        std::fs::write(&pred_file, tampered_content).expect("Write tampered file must succeed");

        // Reloading must detect the hash mismatch and fail with IntegrityViolation
        let load_res = store.load_prediction("PRED-TAMPER-001");
        assert!(matches!(load_res, Err(StorageError::IntegrityViolation { .. })), "Tampered file must fail integrity verification");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_durable_storage_rejection_of_unauthorized_overwrite() {
        let temp_dir = std::env::temp_dir().join(format!("cae_overwrite_store_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation should succeed");

        let structured1 = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::Constant(196),
            loop_branch: LoopBranchHypothesis::StraightLine,
            register_roles: vec![],
            confidence_percent: Some(90),
            notes_and_rationale: "Initial hypothesis".to_string(),
        };

        let mut record1 = PredictionRecord::new_draft(
            "PRED-OVERWRITE-001",
            "CAE-1E-CAL-002",
            "Model-A",
            "196 instructions unrolled",
            structured1,
            "2026-11-17T12:00:00Z",
        );
        record1.freeze().expect("Freeze must succeed");
        store.save_prediction(&record1).expect("Initial save must succeed");

        // Attempt to save a modified hypothesis under the same prediction_id
        let structured2 = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::Constant(200),
            loop_branch: LoopBranchHypothesis::StraightLine,
            register_roles: vec![],
            confidence_percent: Some(95),
            notes_and_rationale: "Tampered overwrite hypothesis".to_string(),
        };

        let mut record2 = PredictionRecord::new_draft(
            "PRED-OVERWRITE-001",
            "CAE-1E-CAL-002",
            "Model-A",
            "Different text",
            structured2,
            "2026-11-17T12:00:00Z",
        );
        record2.freeze().expect("Freeze must succeed");

        let overwrite_res = store.save_prediction(&record2);
        assert!(matches!(overwrite_res, Err(StorageError::UnauthorizedOverwrite { .. })), "Overwriting frozen prediction with differing content must be rejected");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_durable_storage_append_only_evidence_and_duplicate_rejection() {
        let temp_dir = std::env::temp_dir().join(format!("cae_evidence_store_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation should succeed");

        let structured = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::Constant(20),
            loop_branch: LoopBranchHypothesis::StraightLine,
            register_roles: vec![],
            confidence_percent: Some(99),
            notes_and_rationale: "Reference release model".to_string(),
        };

        let mut record = PredictionRecord::new_draft(
            "PRED-EVID-001",
            "CAE-1E-CAL-006",
            "Model-Ref",
            "Reference popcount release",
            structured,
            "2026-11-17T12:00:00Z",
        );
        record.freeze().expect("Freeze must succeed");
        store.save_prediction(&record).expect("Save prediction must succeed");

        // 1. Evidence appending for non-existent prediction fails
        let invalid_ev = EvidenceRecord {
            evidence_id: "EV-ORPHAN".to_string(),
            experiment_id: "CAE-1E-CAL-006".to_string(),
            prediction_id: "PRED-NONEXISTENT".to_string(),
            collection_timestamp_iso8601: "2026-11-17T12:00:00Z".to_string(),
            native_trace: None,
            discrepancy_summary: "none".to_string(),
            scientific_verdict: ScientificVerdict::UnsupportedEvaluation,
            verdict_explanation: "none".to_string(),
            evidence_disclosed_prior_to_prediction: false,
        };
        assert!(matches!(store.append_evidence(&invalid_ev), Err(StorageError::PredictionNotFound(..))));

        // 2. Append valid evidence succeeds
        let valid_ev = EvidenceRecord {
            evidence_id: "EV-001".to_string(),
            experiment_id: "CAE-1E-CAL-006".to_string(),
            prediction_id: "PRED-EVID-001".to_string(),
            collection_timestamp_iso8601: "2026-11-17T12:00:00Z".to_string(),
            native_trace: None,
            discrepancy_summary: "Observed 20 instrs matches prediction".to_string(),
            scientific_verdict: ScientificVerdict::VerifiedPrediction,
            verdict_explanation: "Exact match on reference release".to_string(),
            evidence_disclosed_prior_to_prediction: false,
        };
        assert!(store.append_evidence(&valid_ev).is_ok());

        // 3. Duplicate evidence ID is rejected
        assert!(matches!(store.append_evidence(&valid_ev), Err(StorageError::DuplicateEvidenceId(..))));

        // 4. Query evidence for prediction
        let list = store.list_evidence_for_prediction("PRED-EVID-001").expect("List evidence must succeed");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].evidence_id, "EV-001");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_durable_storage_recovery_from_incomplete_write() {
        let temp_dir = std::env::temp_dir().join(format!("cae_recovery_store_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation should succeed");

        // Simulate an interrupted write leaving a temporary sibling file in predictions/
        let orphan_tmp = temp_dir.join("predictions").join("PRED-ORPHAN.prediction.tmp.9999_12345678");
        std::fs::write(&orphan_tmp, "partial content from crash").expect("Write tmp file must succeed");

        // The store listing must ignore temporary files
        let list = store.list_predictions().expect("Listing predictions should succeed");
        assert!(!list.contains(&"PRED-ORPHAN".to_string()));

        // Cleanup operation should quarantine or remove orphan tmp files
        let cleaned = store.cleanup_interrupted_temporary_files().expect("Cleanup must succeed");
        assert_eq!(cleaned, 1);
        assert!(!orphan_tmp.exists(), "Orphan temporary file must be cleaned up");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_durable_storage_archival_of_disproven_prediction() {
        let temp_dir = std::env::temp_dir().join(format!("cae_disproven_store_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation should succeed");

        // Create, freeze and save disproven hypothesis
        let false_hypothesis = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::Linear { intercept: 585, slope: 3 },
            loop_branch: LoopBranchHypothesis::LoopWithBackedges {
                loop_header_backedges: "64 iterations".to_string(),
                backward_join_branches: None,
            },
            register_roles: vec![],
            confidence_percent: Some(99),
            notes_and_rationale: "Hypothesized naive loop survives in release build".to_string(),
        };

        let mut record = PredictionRecord::new_draft(
            "PRED-DISPROVEN-STORE-001",
            "CAE-1E-CAL-002",
            "Model-Predictor",
            "Predicts naive loop in release build.",
            false_hypothesis,
            "2026-11-17T12:00:00Z",
        );
        record.freeze().unwrap();
        store.save_prediction(&record).expect("Initial freeze save must succeed");

        // Link disproven evidence
        let evidence = EvidenceRecord {
            evidence_id: "EV-DISPROVEN-STORE-001".to_string(),
            experiment_id: "CAE-1E-CAL-002".to_string(),
            prediction_id: "PRED-DISPROVEN-STORE-001".to_string(),
            collection_timestamp_iso8601: "2026-11-17T12:15:00Z".to_string(),
            native_trace: Some(NativeTraceEvidence {
                target_executable_name: "cae_trace_target.exe".to_string(),
                target_executable_sha256: None,
                compiler_profile: "Release".to_string(),
                test_inputs_evaluated: vec![0, 1, 7, 0x5555_5555_5555_5555, u64::MAX],
                observed_instruction_counts: vec![(0, 196), (1, 196), (7, 196), (0x5555_5555_5555_5555, 196), (u64::MAX, 196)],
                loop_header_backedges_observed: Some(0),
                total_backward_branches_observed: Some(0),
                key_register_states_observed: vec![],
                trace_artifact_reference: "trace_release_naive.txt".to_string(),
            }),
            discrepancy_summary: "Observed flat 196 instrs and 0 backedges vs. predicted 585+3k with 64 backedges".to_string(),
            scientific_verdict: ScientificVerdict::PlausibleSemanticFailure,
            verdict_explanation: "LLVM completely unrolled loop into straight-line BT/ADC sequences; prediction falsified.".to_string(),
            evidence_disclosed_prior_to_prediction: false,
        };
        store.append_evidence(&evidence).expect("Append evidence must succeed");

        // Progress lifecycle strictly step-by-step: Frozen -> Verified -> Archived
        record.mark_verified().unwrap();
        store.save_prediction(&record).expect("Verified save must succeed");
        record.archive().unwrap();
        store.save_prediction(&record).expect("Archival save must succeed with same canonical digest");

        // Reopen store from fresh instance and reload
        let store2 = DurablePredictionStore::new(&temp_dir).expect("Reopening store should succeed");
        let reloaded_pred = store2.load_prediction("PRED-DISPROVEN-STORE-001").expect("Reload must succeed");
        let reloaded_ev = store2.load_evidence("EV-DISPROVEN-STORE-001").expect("Reload evidence must succeed");

        assert_eq!(reloaded_pred.state(), PredictionState::Archived);
        assert_eq!(reloaded_ev.scientific_verdict, ScientificVerdict::PlausibleSemanticFailure);
        assert!(reloaded_pred.verify_integrity());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }


    #[test]
    fn test_identifier_validation_rejects_malicious_and_reserved_names() {
        // 1. Rejects empty
        assert!(matches!(validate_identifier("", "test_id"), Err(StorageError::InvalidIdentifier { .. })));

        // 2. Rejects path traversal and separators
        assert!(matches!(validate_identifier("..", "test_id"), Err(StorageError::InvalidIdentifier { .. })));
        assert!(matches!(validate_identifier(".", "test_id"), Err(StorageError::InvalidIdentifier { .. })));
        assert!(matches!(validate_identifier("../escaped", "test_id"), Err(StorageError::InvalidIdentifier { .. })));
        assert!(matches!(validate_identifier("dir/file", "test_id"), Err(StorageError::InvalidIdentifier { .. })));
        assert!(matches!(validate_identifier("dir\\file", "test_id"), Err(StorageError::InvalidIdentifier { .. })));
        assert!(matches!(validate_identifier("C:file", "test_id"), Err(StorageError::InvalidIdentifier { .. })));

        // 3. Rejects Windows reserved device names
        assert!(matches!(validate_identifier("CON", "test_id"), Err(StorageError::InvalidIdentifier { .. })));
        assert!(matches!(validate_identifier("prn", "test_id"), Err(StorageError::InvalidIdentifier { .. })));
        assert!(matches!(validate_identifier("aux.txt", "test_id"), Err(StorageError::InvalidIdentifier { .. })));
        assert!(matches!(validate_identifier("NUL", "test_id"), Err(StorageError::InvalidIdentifier { .. })));
        assert!(matches!(validate_identifier("com1", "test_id"), Err(StorageError::InvalidIdentifier { .. })));
        assert!(matches!(validate_identifier("lpt1", "test_id"), Err(StorageError::InvalidIdentifier { .. })));

        // 4. Rejects illegal characters and trailing dots/spaces
        assert!(matches!(validate_identifier("bad*id", "test_id"), Err(StorageError::InvalidIdentifier { .. })));
        assert!(matches!(validate_identifier("bad?id", "test_id"), Err(StorageError::InvalidIdentifier { .. })));
        assert!(matches!(validate_identifier("trailing. ", "test_id"), Err(StorageError::InvalidIdentifier { .. })));
        assert!(matches!(validate_identifier("trailing.", "test_id"), Err(StorageError::InvalidIdentifier { .. })));

        // 5. Accepts valid calibration and prediction identifiers
        assert!(validate_identifier("CAE-1E-CAL-001", "experiment_id").is_ok());
        assert!(validate_identifier("PRED-001", "prediction_id").is_ok());
        assert!(validate_identifier("EV-001", "evidence_id").is_ok());
        assert!(validate_identifier("model_alpha-v1.2", "model_id").is_ok());
    }

    #[test]
    fn test_concurrent_lifecycle_state_conflict_rejection() {
        let temp_dir = std::env::temp_dir().join(format!("cae_conflict_store_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation should succeed");

        let structured = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::Linear { intercept: 9, slope: 13 },
            loop_branch: LoopBranchHypothesis::StraightLine,
            register_roles: vec![],
            confidence_percent: Some(85),
            notes_and_rationale: "Conflict test".to_string(),
        };

        let mut record = PredictionRecord::new_draft(
            "PRED-CONFLICT-001",
            "CAE-1E-CAL-003",
            "Model-Conflict",
            "Verbatim prediction",
            structured,
            "2026-11-17T12:00:00Z",
        );
        record.freeze().unwrap();
        store.save_prediction(&record).expect("Initial save must succeed");

        // Thread/process A advances state strictly: Frozen -> Verified -> Archived
        let mut record_a = record.clone();
        record_a.mark_verified().unwrap();
        store.save_prediction(&record_a).expect("Verified save must succeed");
        record_a.archive().unwrap();
        store.save_prediction(&record_a).expect("Archival save must succeed");

        // Concurrent thread/process B had an older snapshot and tries to advance Frozen -> Verified
        let mut record_b = record.clone();
        record_b.mark_verified().unwrap();

        let conflict_res = store.save_prediction(&record_b);
        assert!(matches!(
            conflict_res,
            Err(StorageError::ConcurrentLifecycleConflict {
                disk_state: PredictionState::Archived,
                attempted_state: PredictionState::Verified,
                ..
            })
        ), "Attempting stale lifecycle state update against newer disk state must be rejected");

        // Verify the original archived record on disk was not clobbered
        let reloaded = store.load_prediction("PRED-CONFLICT-001").unwrap();
        assert_eq!(reloaded.state(), PredictionState::Archived);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_durable_storage_rejects_skipping_verification_stage() {
        let temp_dir = std::env::temp_dir().join(format!("cae_skip_verify_store_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation should succeed");

        let structured = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::Constant(20),
            loop_branch: LoopBranchHypothesis::StraightLine,
            register_roles: vec![],
            confidence_percent: Some(90),
            notes_and_rationale: "Skip verify test".to_string(),
        };

        let mut record = PredictionRecord::new_draft(
            "PRED-SKIP-001",
            "CAE-1E-CAL-006",
            "Model-Skip",
            "Verbatim response text",
            structured,
            "2026-11-17T12:00:00Z",
        );
        record.freeze().unwrap();
        store.save_prediction(&record).expect("Initial freeze save must succeed");

        // Attempting to advance directly from Frozen to Archived (skipping Verified) on disk must be rejected
        let mut skipped_record = record.clone();
        skipped_record.mark_verified().unwrap();
        skipped_record.archive().unwrap();

        let res = store.save_prediction(&skipped_record);
        assert!(matches!(
            res,
            Err(StorageError::ConcurrentLifecycleConflict {
                disk_state: PredictionState::Frozen,
                attempted_state: PredictionState::Archived,
                ..
            })
        ), "Store must strictly reject jumping from Frozen to Archived without persisted verification stage");

        // Verify disk state remains Frozen
        let reloaded = store.load_prediction("PRED-SKIP-001").unwrap();
        assert_eq!(reloaded.state(), PredictionState::Frozen);

        // Advance to Verified
        let mut verified_record = record.clone();
        verified_record.mark_verified().unwrap();
        store.save_prediction(&verified_record).expect("Advancing Frozen -> Verified must succeed");

        // Attempting backwards transition (Verified -> Frozen) must be rejected
        let res_backwards = store.save_prediction(&record);
        assert!(matches!(
            res_backwards,
            Err(StorageError::ConcurrentLifecycleConflict {
                disk_state: PredictionState::Verified,
                attempted_state: PredictionState::Frozen,
                ..
            })
        ), "Backwards transition from Verified to Frozen must be rejected");

        // Advance to Archived
        let mut archived_record = verified_record.clone();
        archived_record.archive().unwrap();
        store.save_prediction(&archived_record).expect("Advancing Verified -> Archived must succeed");

        // Attempting backwards transition (Archived -> Verified) must be rejected
        let res_archived_backwards = store.save_prediction(&verified_record);
        assert!(matches!(
            res_archived_backwards,
            Err(StorageError::ConcurrentLifecycleConflict {
                disk_state: PredictionState::Archived,
                attempted_state: PredictionState::Verified,
                ..
            })
        ), "Backwards transition from Archived to Verified must be rejected");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // --- CAE-1E Phase 3: Deterministic Prediction Scoring & Calibration Tests ---

    #[test]
    fn test_deterministic_evaluator_exact_matches_across_calibration_suite() {
        let exps = ExperimentDefinition::populate_standard_calibration_experiments();
        let evidence_list = NativeTraceEvidence::populate_standard_calibration_evidence();
        let preds = PredictionRecord::populate_standard_calibration_predictions();

        let correct_preds: Vec<_> = preds
            .iter()
            .filter(|(_, verdict)| *verdict == ScientificVerdict::VerifiedPrediction)
            .collect();

        assert_eq!(correct_preds.len(), 6, "Must have exactly 6 correct calibration predictions");

        for (pred, expected_verdict) in correct_preds {
            let exp = exps.iter().find(|e| e.experiment_id == pred.experiment_id()).unwrap();
            let ev_idx = match pred.experiment_id() {
                "CAE-1E-CAL-001" => 0,
                "CAE-1E-CAL-002" => 1,
                "CAE-1E-CAL-003" => 2,
                "CAE-1E-CAL-004" => 3,
                "CAE-1E-CAL-005" => 4,
                "CAE-1E-CAL-006" => 5,
                _ => panic!("Unknown calibration experiment"),
            };
            let ev = &evidence_list[ev_idx];

            let report = DeterministicPredictionEvaluator::evaluate(exp, pred, Some(ev), false);

            assert_eq!(report.scientific_verdict, *expected_verdict, "Verdict mismatch for {}", pred.prediction_id());
            assert_eq!(report.backedge_status, BackedgeEvaluationStatus::ExactMatch, "Backedge mismatch for {}", pred.prediction_id());
            assert!(report.evaluation_points.iter().all(|p| p.status.is_exact_match()), "All points must match exactly for {}", pred.prediction_id());
            assert_eq!(report.evaluation_points.len(), 5);
            assert!(!report.evidence_disclosed_prior_to_prediction);

            let table = report.render_markdown_table();
            assert!(table.contains("EXACT MATCH"));
            assert!(table.contains("VerifiedPrediction"));
        }
    }

    #[test]
    fn test_deterministic_evaluator_detects_semantic_failure() {
        let exps = ExperimentDefinition::populate_standard_calibration_experiments();
        let evidence_list = NativeTraceEvidence::populate_standard_calibration_evidence();
        let preds = PredictionRecord::populate_standard_calibration_predictions();

        // 1. Release Naive predicting loop with 64 backedges and 585+3k
        let (pred_unrolled_failure, _) = preds.iter().find(|(p, _)| p.prediction_id() == "PRED-CAL-002-FLAWED").unwrap();
        let exp2 = exps.iter().find(|e| e.experiment_id == "CAE-1E-CAL-002").unwrap();
        let ev2 = &evidence_list[1];

        let rep2 = DeterministicPredictionEvaluator::evaluate(exp2, pred_unrolled_failure, Some(ev2), false);
        assert_eq!(rep2.scientific_verdict, ScientificVerdict::PlausibleSemanticFailure);
        assert!(matches!(rep2.backedge_status, BackedgeEvaluationStatus::Discrepancy { .. }));
        assert!(rep2.verdict_explanation.contains("completely unrolled"));

        // 2. Release Kernighan predicting baseline 9+13k
        let (pred_baseline_failure, _) = preds.iter().find(|(p, _)| p.prediction_id() == "PRED-CAL-004-BASELINE").unwrap();
        let exp4 = exps.iter().find(|e| e.experiment_id == "CAE-1E-CAL-004").unwrap();
        let ev4 = &evidence_list[3];

        let rep4 = DeterministicPredictionEvaluator::evaluate(exp4, pred_baseline_failure, Some(ev4), false);
        assert_eq!(rep4.scientific_verdict, ScientificVerdict::PlausibleSemanticFailure);
        assert!(rep4.evaluation_points.iter().any(|p| !p.status.is_exact_match()));
    }

    #[test]
    fn test_deterministic_evaluator_detects_feature_assumption_mismatch() {
        let exps = ExperimentDefinition::populate_standard_calibration_experiments();
        let evidence_list = NativeTraceEvidence::populate_standard_calibration_evidence();
        let preds = PredictionRecord::populate_standard_calibration_predictions();

        let (pred_popcnt_mismatch, _) = preds.iter().find(|(p, _)| p.prediction_id() == "PRED-CAL-006-FLAWED").unwrap();
        let exp6 = exps.iter().find(|e| e.experiment_id == "CAE-1E-CAL-006").unwrap();
        let ev6 = &evidence_list[5];

        let report = DeterministicPredictionEvaluator::evaluate(exp6, pred_popcnt_mismatch, Some(ev6), false);
        assert_eq!(report.scientific_verdict, ScientificVerdict::FeatureAssumptionMismatch);
        assert!(report.verdict_explanation.contains("hardware POPCNT"));
        assert!(report.verdict_explanation.contains("software bitwise reduction tree"));
    }

    #[test]
    fn test_deterministic_evaluator_handles_abstention_and_unknown() {
        let exps = ExperimentDefinition::populate_standard_calibration_experiments();
        let evidence_list = NativeTraceEvidence::populate_standard_calibration_evidence();
        let preds = PredictionRecord::populate_standard_calibration_predictions();

        // Abstention
        let (pred_abstain, _) = preds.iter().find(|(p, _)| p.prediction_id() == "PRED-CAL-ABSTAIN").unwrap();
        let exp1 = exps.iter().find(|e| e.experiment_id == "CAE-1E-CAL-001").unwrap();
        let rep_abstain = DeterministicPredictionEvaluator::evaluate(exp1, pred_abstain, Some(&evidence_list[0]), false);
        assert_eq!(rep_abstain.scientific_verdict, ScientificVerdict::UnsupportedEvaluation);
        assert!(rep_abstain.evaluation_points.iter().all(|p| matches!(p.status, InputEvaluationStatus::Abstention { .. })));

        // Unknown
        let (pred_unknown, _) = preds.iter().find(|(p, _)| p.prediction_id() == "PRED-CAL-UNKNOWN").unwrap();
        let exp3 = exps.iter().find(|e| e.experiment_id == "CAE-1E-CAL-003").unwrap();
        let rep_unknown = DeterministicPredictionEvaluator::evaluate(exp3, pred_unknown, Some(&evidence_list[2]), false);
        assert_eq!(rep_unknown.scientific_verdict, ScientificVerdict::UnsupportedEvaluation);
        assert!(rep_unknown.evaluation_points.iter().all(|p| matches!(p.status, InputEvaluationStatus::UnknownPrediction { .. })));
    }

    #[test]
    fn test_deterministic_evaluator_handles_missing_trace_evidence_without_fabrication() {
        let exps = ExperimentDefinition::populate_standard_calibration_experiments();
        let preds = PredictionRecord::populate_standard_calibration_predictions();

        let (pred_correct, _) = preds.iter().find(|(p, _)| p.prediction_id() == "PRED-CAL-001-CORRECT").unwrap();
        let exp1 = exps.iter().find(|e| e.experiment_id == "CAE-1E-CAL-001").unwrap();

        // Pass evidence: None
        let report = DeterministicPredictionEvaluator::evaluate(exp1, pred_correct, None, false);
        assert_eq!(report.scientific_verdict, ScientificVerdict::UnsupportedEvaluation);
        assert_eq!(report.backedge_status, BackedgeEvaluationStatus::MissingObservation);
        assert!(report.evaluation_points.iter().all(|p| p.observed_count.is_none()));
        assert!(report.verdict_explanation.contains("unavailable"));
        assert!(report.verdict_explanation.contains("no physical observations were fabricated"));
    }

    #[test]
    fn test_deterministic_evaluator_detects_post_hoc_rationalization() {
        let exps = ExperimentDefinition::populate_standard_calibration_experiments();
        let evidence_list = NativeTraceEvidence::populate_standard_calibration_evidence();
        let preds = PredictionRecord::populate_standard_calibration_predictions();

        let (pred_correct, _) = preds.iter().find(|(p, _)| p.prediction_id() == "PRED-CAL-001-CORRECT").unwrap();
        let exp1 = exps.iter().find(|e| e.experiment_id == "CAE-1E-CAL-001").unwrap();

        // Evaluated with prior disclosure = true
        let report = DeterministicPredictionEvaluator::evaluate(exp1, pred_correct, Some(&evidence_list[0]), true);
        assert_eq!(report.scientific_verdict, ScientificVerdict::PostHocRationalization);
        assert!(report.evidence_disclosed_prior_to_prediction);
        assert!(report.discrepancy_summary.contains("Post-hoc rationalization"));
    }

    #[test]
    fn test_evaluator_backedge_discrimination_distinguishes_joins_from_headers() {
        let exps = ExperimentDefinition::populate_standard_calibration_experiments();
        let exp1 = exps.iter().find(|e| e.experiment_id == "CAE-1E-CAL-001").unwrap();

        // Naive debug evidence: 64 loop header backedges, 96 total backward branches (for k=32)
        let ev1 = NativeTraceEvidence {
            target_executable_name: "cae_trace_target.exe".to_string(),
            target_executable_sha256: None,
            compiler_profile: "Debug".to_string(),
            test_inputs_evaluated: vec![0x5555_5555_5555_5555],
            observed_instruction_counts: vec![(0x5555_5555_5555_5555, 4908)],
            loop_header_backedges_observed: Some(64),
            total_backward_branches_observed: Some(96),
            key_register_states_observed: vec!["RAX=32".to_string()],
            trace_artifact_reference: "trace_debug_naive.txt".to_string(),
        };

        // 1. Prediction asserting exactly 64 header backedges
        let mut pred_64 = PredictionRecord::new_draft(
            "PRED-HDR-64",
            "CAE-1E-CAL-001",
            "Model-64",
            "Predicts 64 header backedges",
            StructuredPrediction {
                instruction_count: InstructionCountHypothesis::Linear { intercept: 4652, slope: 8 },
                loop_branch: LoopBranchHypothesis::LoopWithBackedges {
                    loop_header_backedges: "64".to_string(),
                    backward_join_branches: Some("k".to_string()),
                },
                register_roles: vec![],
                confidence_percent: Some(95),
                notes_and_rationale: "Distinguishes 64 header backedges from join branches.".to_string(),
            },
            "2026-11-17T12:00:00Z",
        );
        pred_64.freeze().unwrap();

        let rep_64 = DeterministicPredictionEvaluator::evaluate(exp1, &pred_64, Some(&ev1), false);
        assert_eq!(rep_64.backedge_status, BackedgeEvaluationStatus::ExactMatch);

        // 2. Flawed prediction conflating total backward branches (96) with header backedges
        let mut pred_96 = PredictionRecord::new_draft(
            "PRED-HDR-96",
            "CAE-1E-CAL-001",
            "Model-96",
            "Predicts 96 header backedges (conflating joins with header)",
            StructuredPrediction {
                instruction_count: InstructionCountHypothesis::Linear { intercept: 4652, slope: 8 },
                loop_branch: LoopBranchHypothesis::LoopWithBackedges {
                    loop_header_backedges: "96".to_string(),
                    backward_join_branches: None,
                },
                register_roles: vec![],
                confidence_percent: Some(90),
                notes_and_rationale: "Conflates join jumps with loop header backedges.".to_string(),
            },
            "2026-11-17T12:00:00Z",
        );
        pred_96.freeze().unwrap();

        let rep_96 = DeterministicPredictionEvaluator::evaluate(exp1, &pred_96, Some(&ev1), false);
        assert!(matches!(rep_96.backedge_status, BackedgeEvaluationStatus::Discrepancy { .. }));
    }

    #[test]
    fn test_durable_storage_end_to_end_evaluation_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("cae_e2e_eval_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation must succeed");

        let exps = ExperimentDefinition::populate_standard_calibration_experiments();
        let exp4 = exps.iter().find(|e| e.experiment_id == "CAE-1E-CAL-004").unwrap();
        store.save_experiment(exp4).expect("Save experiment must succeed");

        let mut pred = PredictionRecord::new_draft(
            "PRED-E2E-001",
            "CAE-1E-CAL-004",
            "Evaluation-Lifecycle-Model",
            "Predicts release Kernighan piecewise model 4 for k=0, 5+5k for k>=1",
            StructuredPrediction {
                instruction_count: InstructionCountHypothesis::PiecewisePopcount {
                    zero_case: 4,
                    non_zero_intercept: 5,
                    non_zero_slope: 5,
                },
                loop_branch: LoopBranchHypothesis::LoopWithBackedges {
                    loop_header_backedges: "k-1".to_string(),
                    backward_join_branches: None,
                },
                register_roles: vec![],
                confidence_percent: Some(100),
                notes_and_rationale: "End-to-end evaluation lifecycle verification test.".to_string(),
            },
            "2026-11-17T12:00:00Z",
        );
        pred.freeze().expect("Freeze must succeed");
        let orig_canonical_sha256 = pred.canonical_sha256().to_string();

        // 1. Initial save in Frozen state
        store.save_prediction(&pred).expect("Initial save of frozen prediction must succeed");

        // 2. Evaluate using DeterministicPredictionEvaluator
        let ev4 = NativeTraceEvidence::populate_standard_calibration_evidence().into_iter().find(|e| e.compiler_profile == "Release" && e.observed_instruction_counts.iter().any(|(i, c)| *i == 0 && *c == 4)).unwrap();
        let report = DeterministicPredictionEvaluator::evaluate(exp4, &pred, Some(&ev4), false);
        assert_eq!(report.scientific_verdict, ScientificVerdict::VerifiedPrediction);

        // 3. Mark prediction Verified and update store (Frozen -> Verified)
        pred.mark_verified().expect("Transition to Verified must succeed");
        store.save_prediction(&pred).expect("Saving Verified prediction must succeed");

        // 4. Append Evidence Record to store
        let evidence_record = report.to_evidence_record("EV-E2E-001", "2026-11-17T12:15:00Z", Some(ev4));
        store.append_evidence(&evidence_record).expect("Append evidence must succeed");

        // 5. Mark prediction Archived and update store (Verified -> Archived)
        pred.archive().expect("Transition to Archived must succeed");
        store.save_prediction(&pred).expect("Saving Archived prediction must succeed");

        // 6. Reload from disk and verify immutability and complete preservation
        let reloaded_pred = store.load_prediction("PRED-E2E-001").expect("Reload prediction must succeed");
        assert_eq!(reloaded_pred.state(), PredictionState::Archived);
        assert_eq!(reloaded_pred.canonical_sha256(), orig_canonical_sha256);
        assert!(reloaded_pred.verify_integrity());

        let reloaded_ev = store.load_evidence("EV-E2E-001").expect("Reload evidence must succeed");
        assert_eq!(reloaded_ev.scientific_verdict, ScientificVerdict::VerifiedPrediction);
        assert_eq!(reloaded_ev.prediction_id, "PRED-E2E-001");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }


    // --- CAE-1E Phase 4: Controlled Blind Experiment Protocol Tests ---

    #[test]
    fn test_permitted_view_withholds_all_runtime_execution_evidence() {
        let blind_exps = ExperimentDefinition::populate_standard_blind_experiments();
        assert_eq!(blind_exps.len(), 3, "Must have exactly 3 standard blind experiments");

        let auditor = LeakAuditingMockPredictor {
            model_id: "Evidence-Leak-Auditor".to_string(),
        };

        for exp in &blind_exps {
            assert_eq!(exp.classification, ExperimentClassification::Blind);
            let view = exp.to_permitted_view();

            // Verify view retains only permitted metadata and disassembly text
            assert_eq!(view.experiment_id, exp.experiment_id);
            assert_eq!(view.target_kernel_name, exp.target_kernel_name);
            assert_eq!(view.compiler_profile, exp.compiler_profile);
            assert!(!view.disassembly_input.is_empty());

            // Run leak auditor predictor to assert no execution trace metrics were leaked
            let (resp, pred) = auditor.predict(&view);
            assert!(resp.contains("Audit passed"));
            assert_eq!(pred.confidence_percent, Some(100));
        }
    }

    #[test]
    fn test_controlled_blind_experiment_harness_happy_path() {
        let temp_dir = std::env::temp_dir().join(format!("cae_blind_harness_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation must succeed");

        let blind_exps = ExperimentDefinition::populate_standard_blind_experiments();
        let exp1 = &blind_exps[0]; // CAE-1E-BLD-001: Release Naive (unrolled)

        let predictor = HeuristicDisassemblyMockPredictor {
            model_id: "Heuristic-Disassembly-Mock".to_string(),
        };

        let withheld_evidence = NativeTraceEvidence {
            target_executable_name: "cae_trace_target.exe".to_string(),
            target_executable_sha256: None,
            compiler_profile: "Release".to_string(),
            test_inputs_evaluated: vec![0, 1, 7, 0x5555_5555_5555_5555, u64::MAX],
            observed_instruction_counts: vec![
                (0, 196),
                (1, 196),
                (7, 196),
                (0x5555_5555_5555_5555, 196),
                (u64::MAX, 196),
            ],
            loop_header_backedges_observed: Some(0),
            total_backward_branches_observed: Some(0),
            key_register_states_observed: vec!["EAX=result".to_string()],
            trace_artifact_reference: "trace_release_naive_blind.txt".to_string(),
        };

        let exec = ControlledBlindExperimentHarness::run_controlled_experiment(
            &store,
            exp1,
            &predictor,
            &withheld_evidence,
            "PRED-BLD-001",
            "EV-BLD-001",
            "2026-11-17T12:00:00Z",
            "2026-11-17T12:15:00Z",
        ).expect("Controlled blind experiment execution must succeed");

        assert_eq!(exec.experiment_id, "CAE-1E-BLD-001");
        assert_eq!(exec.prediction_id, "PRED-BLD-001");
        assert_eq!(exec.evidence_id, "EV-BLD-001");
        assert!(exec.pre_disclosure_verification_passed, "Pre-disclosure digest verification must pass");
        assert_eq!(exec.final_prediction_state, PredictionState::Archived);
        assert!(exec.post_archival_integrity_verified, "Post-archival digest must match frozen hash bit-for-bit");
        assert_eq!(exec.evaluation_report.scientific_verdict, ScientificVerdict::VerifiedPrediction);
        assert_eq!(exec.evaluation_report.backedge_status, BackedgeEvaluationStatus::ExactMatch);

        // Verify summary rendering
        let summary = exec.render_summary();
        assert!(summary.contains("Controlled Blind Experiment: CAE-1E-BLD-001"));
        assert!(summary.contains("VerifiedPrediction"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_controlled_blind_experiment_with_abstaining_predictor() {
        let temp_dir = std::env::temp_dir().join(format!("cae_blind_abstain_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation must succeed");

        let blind_exps = ExperimentDefinition::populate_standard_blind_experiments();
        let exp2 = &blind_exps[1]; // CAE-1E-BLD-002: Release Kernighan

        let predictor = AbstainingMockPredictor {
            model_id: "Principled-Abstainer-Mock".to_string(),
            abstention_reason: "Withheld runtime helper costs cannot be inferred from disassembly alone.".to_string(),
        };

        let withheld_evidence = NativeTraceEvidence {
            target_executable_name: "cae_trace_target.exe".to_string(),
            target_executable_sha256: None,
            compiler_profile: "Release".to_string(),
            test_inputs_evaluated: vec![0, 1, 7],
            observed_instruction_counts: vec![(0, 4), (1, 10), (7, 20)],
            loop_header_backedges_observed: Some(2),
            total_backward_branches_observed: Some(2),
            key_register_states_observed: vec!["EAX=result".to_string()],
            trace_artifact_reference: "trace_release_kernighan_blind.txt".to_string(),
        };

        let exec = ControlledBlindExperimentHarness::run_controlled_experiment(
            &store,
            exp2,
            &predictor,
            &withheld_evidence,
            "PRED-BLD-002",
            "EV-BLD-002",
            "2026-11-17T12:00:00Z",
            "2026-11-17T12:15:00Z",
        ).expect("Controlled experiment with abstaining predictor must succeed");

        assert_eq!(exec.final_prediction_state, PredictionState::Archived);
        assert!(exec.post_archival_integrity_verified);
        assert_eq!(exec.evaluation_report.scientific_verdict, ScientificVerdict::UnsupportedEvaluation);
        assert!(exec.evaluation_report.evaluation_points.iter().all(|p| matches!(p.status, InputEvaluationStatus::Abstention { .. })));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_controlled_blind_experiment_with_flawed_predictor() {
        let temp_dir = std::env::temp_dir().join(format!("cae_blind_flawed_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation must succeed");

        let blind_exps = ExperimentDefinition::populate_standard_blind_experiments();
        let exp1 = &blind_exps[0]; // CAE-1E-BLD-001: Release Naive (unrolled)

        let predictor = FlawedSourceLevelMockPredictor {
            model_id: "Flawed-Source-Mock".to_string(),
        };

        let withheld_evidence = NativeTraceEvidence {
            target_executable_name: "cae_trace_target.exe".to_string(),
            target_executable_sha256: None,
            compiler_profile: "Release".to_string(),
            test_inputs_evaluated: vec![0, 1, 7],
            observed_instruction_counts: vec![(0, 196), (1, 196), (7, 196)],
            loop_header_backedges_observed: Some(0),
            total_backward_branches_observed: Some(0),
            key_register_states_observed: vec!["EAX=result".to_string()],
            trace_artifact_reference: "trace_release_naive_blind.txt".to_string(),
        };

        let exec = ControlledBlindExperimentHarness::run_controlled_experiment(
            &store,
            exp1,
            &predictor,
            &withheld_evidence,
            "PRED-BLD-003",
            "EV-BLD-003",
            "2026-11-17T12:00:00Z",
            "2026-11-17T12:15:00Z",
        ).expect("Controlled experiment with flawed predictor must succeed");

        assert_eq!(exec.final_prediction_state, PredictionState::Archived);
        assert!(exec.post_archival_integrity_verified);
        assert_eq!(exec.evaluation_report.scientific_verdict, ScientificVerdict::PlausibleSemanticFailure);
        assert!(matches!(exec.evaluation_report.backedge_status, BackedgeEvaluationStatus::Discrepancy { .. }));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_controlled_blind_experiment_rejects_profile_mismatch_and_premature_evidence() {
        let temp_dir = std::env::temp_dir().join(format!("cae_blind_reject_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation must succeed");

        let blind_exps = ExperimentDefinition::populate_standard_blind_experiments();
        let exp1 = &blind_exps[0]; // Profile: Release

        let predictor = HeuristicDisassemblyMockPredictor {
            model_id: "Heuristic-Mock".to_string(),
        };

        // Evidence with mismatched compiler profile: "Debug" instead of "Release"
        let bad_profile_evidence = NativeTraceEvidence {
            target_executable_name: "cae_trace_target.exe".to_string(),
            target_executable_sha256: None,
            compiler_profile: "Debug".to_string(),
            test_inputs_evaluated: vec![0],
            observed_instruction_counts: vec![(0, 196)],
            loop_header_backedges_observed: Some(0),
            total_backward_branches_observed: Some(0),
            key_register_states_observed: vec![],
            trace_artifact_reference: "trace_debug.txt".to_string(),
        };

        let res = ControlledBlindExperimentHarness::run_controlled_experiment(
            &store,
            exp1,
            &predictor,
            &bad_profile_evidence,
            "PRED-BLD-ERR",
            "EV-BLD-ERR",
            "2026-11-17T12:00:00Z",
            "2026-11-17T12:15:00Z",
        );
        assert!(matches!(res, Err(StorageError::Protocol(PredictionProtocolError::CorruptedRecord { .. }))), "Mismatched compiler profile must be rejected");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }


    // --- CAE-1E Phase 5: Independent Prediction Trial Preparation Tests ---

    #[test]
    fn test_trial_prompt_packet_provenance_and_hash_integrity() {
        let fresh_exps = ExperimentDefinition::populate_fresh_trial_experiments();
        assert_eq!(fresh_exps.len(), 3, "Must define exactly 3 fresh trial experiments");

        let exp1 = &fresh_exps[0]; // CAE-1E-TRL-001 (exp-b)
        let packet = ManualTrialSession::prepare_trial(exp1, "2026-11-17T12:00:00Z");

        assert_eq!(packet.experiment_id, "CAE-1E-TRL-001");
        assert_eq!(packet.schema_version, "CAE-1E-TRIAL-V1");
        assert_eq!(packet.prompt_sha256.len(), 64);
        assert!(packet.verify_integrity(), "Prompt packet must verify its own SHA-256 digest");

        // Verify that mutating the prompt text breaks integrity check
        let mut tampered = packet.clone();
        tampered.prompt_markdown_text.push_str("LEAKED_TRACE_DATA");
        assert!(!tampered.verify_integrity(), "Tampered prompt text must fail hash integrity check");

        // Verify that prompt contains no execution trace metrics
        assert!(!packet.prompt_markdown_text.contains("observed_instruction_counts"));
        assert!(!packet.prompt_markdown_text.contains("loop_header_backedges_observed"));
    }

    #[test]
    fn test_physical_executable_sha256_computation_and_verification() {
        let debug_exe = std::path::Path::new("target/debug/cae_trace_target.exe");
        if !debug_exe.exists() {
            let status = std::process::Command::new("cargo")
                .args(["build", "--bin", "cae_trace_target"])
                .status()
                .expect("Failed to build cae_trace_target");
            assert!(status.success());
        }

        // 1. Compute physical file hash
        let exe_hash = compute_file_sha256(debug_exe).expect("Computing physical file SHA-256 must succeed");
        assert_eq!(exe_hash.len(), 64);

        // 2. Verified match
        let mut ev_matching = NativeTraceEvidence::populate_fresh_trial_evidence().remove(0);
        ev_matching.target_executable_sha256 = Some(exe_hash.clone());
        assert!(ev_matching.verify_executable_identity(debug_exe).expect("Identity check should succeed"));

        // 3. Tampered / mismatched hash
        let mut ev_mismatched = ev_matching.clone();
        ev_mismatched.target_executable_sha256 = Some("0000000000000000000000000000000000000000000000000000000000000000".to_string());
        assert!(!ev_mismatched.verify_executable_identity(debug_exe).expect("Identity check should succeed"));
    }

    #[test]
    fn test_manual_trial_session_complete_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("cae_trial_session_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation must succeed");

        let fresh_exps = ExperimentDefinition::populate_fresh_trial_experiments();
        let exp1 = &fresh_exps[0]; // exp-b
        store.save_experiment(exp1).expect("Save experiment must succeed");

        // Step 1: Prepare trial prompt packet
        let packet = ManualTrialSession::prepare_trial(exp1, "2026-11-17T12:00:00Z");
        assert!(packet.verify_integrity());

        // Step 2: Register independent prediction (manual operator input)
        let structured = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::Constant(4),
            loop_branch: LoopBranchHypothesis::StraightLine,
            register_roles: vec![],
            confidence_percent: Some(95),
            notes_and_rationale: "Predicts 4 instructions for even input path.".to_string(),
        };

        let record = ManualTrialSession::register_prediction(
            &store,
            &packet,
            "PRED-TRL-001",
            "Manual-Human-Expert",
            "Predicted 4 instructions for even input path based solely on static disassembly.",
            structured,
            "2026-11-17T12:05:00Z",
        ).expect("Registering independent prediction must succeed");

        assert_eq!(record.state(), PredictionState::Frozen);
        assert!(record.verify_integrity());
        let frozen_hash = record.canonical_sha256().to_string();

        // Step 3: Disclose evidence and evaluate
        let evidence = NativeTraceEvidence::populate_fresh_trial_evidence().remove(0);
        let exec = ManualTrialSession::disclose_and_evaluate(
            &store,
            exp1,
            &record,
            Some(&evidence),
            "EV-TRL-001",
            "2026-11-17T12:15:00Z",
            None,
        ).expect("Disclose and evaluate must succeed");

        assert_eq!(exec.final_prediction_state, PredictionState::Archived);
        assert!(exec.post_archival_integrity_verified);
        assert_eq!(exec.frozen_canonical_sha256, frozen_hash);

        // Reload from store
        let reloaded = store.load_prediction("PRED-TRL-001").expect("Reload prediction must succeed");
        assert_eq!(reloaded.state(), PredictionState::Archived);
        assert_eq!(reloaded.canonical_sha256(), frozen_hash);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_tracer_capability_audit_detects_unsupported_kernels_without_extrapolation() {
        let debug_exe = std::path::Path::new("target/debug/cae_trace_target.exe");

        // 1. Audit supported kernel (exp-b)
        assert!(TracerCapabilityAudit::assess_kernel_traceability("exp-b", debug_exe).is_ok());

        // 2. Audit unsupported kernel (unsupported_kernel)
        let err = TracerCapabilityAudit::assess_kernel_traceability("unsupported_kernel", debug_exe);
        assert!(matches!(err, Err(TracerLimitation::UnsupportedKernel(_))));

        // 3. End-to-end evaluation with unsupported kernel: must emit UnsupportedEvaluation with limitation explanation
        let temp_dir = std::env::temp_dir().join(format!("cae_tracer_limit_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation must succeed");

        let fresh_exps = ExperimentDefinition::populate_fresh_trial_experiments();
        let exp3 = &fresh_exps[2]; // unsupported_kernel
        store.save_experiment(exp3).expect("Save experiment must succeed");

        let packet = ManualTrialSession::prepare_trial(exp3, "2026-11-17T12:00:00Z");
        let structured = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::Constant(10),
            loop_branch: LoopBranchHypothesis::StraightLine,
            register_roles: vec![],
            confidence_percent: Some(50),
            notes_and_rationale: "Hypothesis for unsupported kernel.".to_string(),
        };

        let record = ManualTrialSession::register_prediction(
            &store,
            &packet,
            "PRED-UNSUPPORTED",
            "Model-Explorer",
            "Speculative prediction for unsupported kernel.",
            structured,
            "2026-11-17T12:05:00Z",
        ).expect("Registering prediction must succeed");

        let exec = ManualTrialSession::disclose_and_evaluate(
            &store,
            exp3,
            &record,
            None,
            "EV-UNSUPPORTED",
            "2026-11-17T12:15:00Z",
            Some(debug_exe),
        ).expect("Disclose and evaluate must succeed with UnsupportedEvaluation");

        assert_eq!(exec.evaluation_report.scientific_verdict, ScientificVerdict::UnsupportedEvaluation);
        assert!(exec.evaluation_report.verdict_explanation.contains("Tracer capability limitation"));
        assert!(exec.evaluation_report.verdict_explanation.contains("unsupported by isolated tracer"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_fresh_trial_experiments_novelty_controls() {
        let fresh_exps = ExperimentDefinition::populate_fresh_trial_experiments();
        let evidence_list = NativeTraceEvidence::populate_fresh_trial_evidence();

        // 1. exp-b (branch parity)
        let exp_b = &fresh_exps[0];
        let ev_b = &evidence_list[0];
        assert_eq!(exp_b.target_kernel_name, "exp-b");
        assert_eq!(ev_b.test_inputs_evaluated, vec![10, 11]);

        // 2. exp-c (bounded loop sum)
        let exp_c = &fresh_exps[1];
        let ev_c = &evidence_list[1];
        assert_eq!(exp_c.target_kernel_name, "exp-c");
        assert_eq!(ev_c.test_inputs_evaluated, vec![0, 1, 5]);
    }

    // --- CAE-1E Phase 6: First Registered Prediction Experiment Tests ---

    #[test]
    #[cfg(windows)]
    fn test_native_trace_exp_d_ctz_vectors() {
        // x = 0: xor, test, jz [taken] -> 3 steps, RAX = 0, backedges = 0
        let r0 = WindowsNativeDebugger::trace_kernel("exp-d", 0, 100)
            .expect("Native trace of exp-d (0) should succeed");
        assert_eq!(r0.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(r0.total_observed_instructions, 3);
        assert_eq!(r0.return_value_rax, 0);
        assert_eq!(r0.count_backward_branches(), 0);

        // x = 1 (t = 0): xor, test, jz [not taken], test, jnz [taken] -> 5 steps, RAX = 0, backedges = 0
        let r1 = WindowsNativeDebugger::trace_kernel("exp-d", 1, 100)
            .expect("Native trace of exp-d (1) should succeed");
        assert_eq!(r1.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(r1.total_observed_instructions, 5);
        assert_eq!(r1.return_value_rax, 0);
        assert_eq!(r1.count_backward_branches(), 0);

        // x = 2 (t = 1): 5 + 7*1 = 12 steps, RAX = 1, backedges = 1
        let r2 = WindowsNativeDebugger::trace_kernel("exp-d", 2, 100)
            .expect("Native trace of exp-d (2) should succeed");
        assert_eq!(r2.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(r2.total_observed_instructions, 12);
        assert_eq!(r2.return_value_rax, 1);
        assert_eq!(r2.count_backward_branches(), 1);

        // x = 8 (t = 3): 5 + 7*3 = 26 steps, RAX = 3, backedges = 3
        let r8 = WindowsNativeDebugger::trace_kernel("exp-d", 8, 100)
            .expect("Native trace of exp-d (8) should succeed");
        assert_eq!(r8.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(r8.total_observed_instructions, 26);
        assert_eq!(r8.return_value_rax, 3);
        assert_eq!(r8.count_backward_branches(), 3);

        // x = 64 (t = 6): 5 + 7*6 = 47 steps, RAX = 6, backedges = 6
        let r64 = WindowsNativeDebugger::trace_kernel("exp-d", 64, 100)
            .expect("Native trace of exp-d (64) should succeed");
        assert_eq!(r64.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(r64.total_observed_instructions, 47);
        assert_eq!(r64.return_value_rax, 6);
        assert_eq!(r64.count_backward_branches(), 6);
    }

    #[test]
    fn test_phase6_piecewise_ctz_hypothesis_and_serialization() {
        let hyp = InstructionCountHypothesis::PiecewiseCTZ {
            zero_input_case: 3,
            zero_trailing_case: 5,
            non_zero_intercept: 5,
            non_zero_slope: 7,
        };

        assert_eq!(hyp.evaluate_input(0), Some(3));
        assert_eq!(hyp.evaluate_input(1), Some(5));
        assert_eq!(hyp.evaluate_input(2), Some(12));
        assert_eq!(hyp.evaluate_input(8), Some(26));
        assert_eq!(hyp.evaluate_input(64), Some(47));

        let pred = PredictionRecord::populate_phase6_ctz_prediction(
            "PRED-CTZ-001",
            "Test-Predictor",
            "2026-11-17T12:00:00Z",
        );
        let serialized = pred.to_durable_text();
        assert!(serialized.contains("instruction_count=PiecewiseCTZ:3:5:5:7"));

        let reloaded = PredictionRecord::from_durable_text(&serialized)
            .expect("Durable text reload must succeed");
        assert_eq!(reloaded.structured_prediction().instruction_count, hyp);
        assert_eq!(reloaded.canonical_sha256(), pred.canonical_sha256());
    }

    #[test]
    fn test_phase6_registered_prediction_experiment_full_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("cae_phase6_trial_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation must succeed");

        // 1. Prepare fresh machine-code task (CAE-1E-EXP-001)
        let exp = ExperimentDefinition::populate_phase6_trial_experiment();
        store.save_experiment(&exp).expect("Save experiment must succeed");

        let prompt_packet = ManualTrialSession::prepare_trial(&exp, "2026-11-17T12:00:00Z");
        assert!(prompt_packet.verify_integrity());
        // Verify prompt withholds physical trace measurements
        assert!(!prompt_packet.prompt_markdown_text.contains("trace_observed_counts"));
        assert!(!prompt_packet.prompt_markdown_text.contains("trace_artifact_reference"));

        // 2. Capture independent predictions before evidence disclosure
        let correct_pred = PredictionRecord::populate_phase6_ctz_prediction(
            "PRED-EXP-001-CORRECT",
            "Expert-Disassembly-Analyst",
            "2026-11-17T12:05:00Z",
        );
        let flawed_pred = PredictionRecord::populate_phase6_flawed_prediction(
            "PRED-EXP-001-FLAWED",
            "Flawed-Heuristic-Analyst",
            "2026-11-17T12:06:00Z",
        );

        // 3. Freeze predictions BEFORE evidence disclosure
        let frozen_correct = ManualTrialSession::register_prediction(
            &store,
            &prompt_packet,
            correct_pred.prediction_id(),
            correct_pred.model_identifier(),
            correct_pred.original_response_text(),
            correct_pred.structured_prediction().clone(),
            correct_pred.registration_timestamp_iso8601(),
        ).expect("Register correct prediction must succeed");
        assert_eq!(frozen_correct.state(), PredictionState::Frozen);

        let frozen_flawed = ManualTrialSession::register_prediction(
            &store,
            &prompt_packet,
            flawed_pred.prediction_id(),
            flawed_pred.model_identifier(),
            flawed_pred.original_response_text(),
            flawed_pred.structured_prediction().clone(),
            flawed_pred.registration_timestamp_iso8601(),
        ).expect("Register flawed prediction must succeed");
        assert_eq!(frozen_flawed.state(), PredictionState::Frozen);

        // 4. Reveal independently verified traces & validate executable identity
        let debug_exe = std::path::Path::new("target/debug/cae_trace_target.exe");
        let exe_sha256 = if debug_exe.exists() {
            Some(compute_file_sha256(debug_exe).unwrap())
        } else {
            None
        };
        let ground_truth_evidence = NativeTraceEvidence::populate_phase6_trial_evidence(exe_sha256);

        // 5. Score and preserve: Deterministic scoring via DeterministicPredictionEvaluator
        let exec_correct = ManualTrialSession::disclose_and_evaluate(
            &store,
            &exp,
            &frozen_correct,
            Some(&ground_truth_evidence),
            "EV-EXP-001-CORRECT",
            "2026-11-17T12:15:00Z",
            if debug_exe.exists() { Some(debug_exe) } else { None },
        ).expect("Disclose and evaluate correct prediction must succeed");

        assert_eq!(exec_correct.final_prediction_state, PredictionState::Archived);
        assert!(exec_correct.post_archival_integrity_verified);
        assert_eq!(exec_correct.evaluation_report.scientific_verdict, ScientificVerdict::VerifiedPrediction);
        assert_eq!(exec_correct.evaluation_report.backedge_status, BackedgeEvaluationStatus::ExactMatch);
        for pt in &exec_correct.evaluation_report.evaluation_points {
            assert!(matches!(pt.status, InputEvaluationStatus::ExactMatch));
        }

        // Flawed prediction evaluation
        let exec_flawed = ManualTrialSession::disclose_and_evaluate(
            &store,
            &exp,
            &frozen_flawed,
            Some(&ground_truth_evidence),
            "EV-EXP-001-FLAWED",
            "2026-11-17T12:16:00Z",
            if debug_exe.exists() { Some(debug_exe) } else { None },
        ).expect("Disclose and evaluate flawed prediction must succeed");

        assert_eq!(exec_flawed.final_prediction_state, PredictionState::Archived);
        assert!(exec_flawed.post_archival_integrity_verified);
        assert_eq!(exec_flawed.evaluation_report.scientific_verdict, ScientificVerdict::PlausibleSemanticFailure);
        assert!(matches!(exec_flawed.evaluation_report.backedge_status, BackedgeEvaluationStatus::Discrepancy { .. }));

        // Check durability and history preservation
        let stored_evs = store.list_evidence_for_prediction(correct_pred.prediction_id()).unwrap();
        assert_eq!(stored_evs.len(), 1);
        assert_eq!(stored_evs[0].scientific_verdict, ScientificVerdict::VerifiedPrediction);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // --- CAE-1E Phase 7: Stereoscopic Code Reasoning Experiment Infrastructure Tests ---

    #[test]
    #[cfg(windows)]
    fn test_native_trace_exp_e_bit_accum_vectors() {
        // x = 0: xor, test, jz [taken] -> 3 steps, RAX = 0, backedges = 0
        let r0 = WindowsNativeDebugger::trace_kernel("exp-e", 0, 100)
            .expect("Native trace of exp-e (0) should succeed");
        assert_eq!(r0.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(r0.total_observed_instructions, 3);
        assert_eq!(r0.return_value_rax, 0);
        assert_eq!(r0.count_backward_branches(), 0);

        // x = 1: k=1, L=1 -> 3 + 7(1) + 1 = 11 steps, RAX = 3, backedges = 1
        let r1 = WindowsNativeDebugger::trace_kernel("exp-e", 1, 100)
            .expect("Native trace of exp-e (1) should succeed");
        assert_eq!(r1.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(r1.total_observed_instructions, 11);
        assert_eq!(r1.return_value_rax, 3);
        assert_eq!(r1.count_backward_branches(), 1);

        // x = 2: k=1, L=2 -> 3 + 7(2) + 1 = 18 steps, RAX = 4, backedges = 2
        let r2 = WindowsNativeDebugger::trace_kernel("exp-e", 2, 100)
            .expect("Native trace of exp-e (2) should succeed");
        assert_eq!(r2.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(r2.total_observed_instructions, 18);
        assert_eq!(r2.return_value_rax, 4);
        assert_eq!(r2.count_backward_branches(), 2);

        // x = 7: k=3, L=3 -> 3 + 7(3) + 3 = 27 steps, RAX = 9, backedges = 3
        let r7 = WindowsNativeDebugger::trace_kernel("exp-e", 7, 100)
            .expect("Native trace of exp-e (7) should succeed");
        assert_eq!(r7.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(r7.total_observed_instructions, 27);
        assert_eq!(r7.return_value_rax, 9);
        assert_eq!(r7.count_backward_branches(), 3);

        // x = 8: k=1, L=4 -> 3 + 7(4) + 1 = 32 steps, RAX = 6, backedges = 4
        let r8 = WindowsNativeDebugger::trace_kernel("exp-e", 8, 100)
            .expect("Native trace of exp-e (8) should succeed");
        assert_eq!(r8.status, NativeTraceStatus::CompletedSuccess);
        assert_eq!(r8.total_observed_instructions, 32);
        assert_eq!(r8.return_value_rax, 6);
        assert_eq!(r8.count_backward_branches(), 4);
    }

    #[test]
    fn test_phase7_five_representation_modes_generation_and_hashing() {
        let exp = ExperimentDefinition::populate_phase7_fresh_experiment();
        let modes = [
            CodeRepresentationMode::LinearDisassembly,
            CodeRepresentationMode::LocalWindows,
            CodeRepresentationMode::GlobalTopology,
            CodeRepresentationMode::StructuredDualView,
            CodeRepresentationMode::SelfReconstructedDualView,
        ];

        let mut hashes = std::collections::HashSet::new();

        for &mode in &modes {
            let packet = StereoscopicPromptGenerator::generate_prompt_packet(
                &exp,
                mode,
                "2026-11-17T13:30:00Z",
                Some("temp=0.0;top_p=1.0"),
            );

            // Assert prompt integrity
            assert!(packet.verify_integrity(), "Prompt packet for mode {:?} must verify against canonical hash", mode);
            assert_eq!(packet.representation_mode, mode);
            assert_eq!(packet.audit.representation_mode, mode);
            assert!(packet.audit.prompt_char_count > 0);
            assert!(packet.audit.estimated_prompt_tokens > 0);
            assert_eq!(packet.audit.model_configuration.as_deref(), Some("temp=0.0;top_p=1.0"));

            // Distinct representations must have distinct canonical hashes
            assert!(hashes.insert(packet.audit.canonical_sha256.clone()), "Mode {:?} must produce a unique prompt hash", mode);
        }

        assert_eq!(hashes.len(), 5, "All 5 representation modes must have distinct canonical digests");
    }

    #[test]
    fn test_phase7_information_disclosure_auditing_invariants() {
        let exp = ExperimentDefinition::populate_phase7_fresh_experiment();

        // Mode A: Linear Disassembly (Information Preserving)
        let pkt_a = StereoscopicPromptGenerator::generate_prompt_packet(&exp, CodeRepresentationMode::LinearDisassembly, "2026-11-17T13:30:00Z", None);
        assert_eq!(pkt_a.audit.information_class, RepresentationInformationClass::InformationPreserving);
        assert!(pkt_a.audit.exact_instruction_text_supplied);
        assert!(!pkt_a.audit.explicit_branch_destinations);
        assert!(!pkt_a.audit.explicit_cfg_edges);
        assert!(!pkt_a.audit.explicit_basic_block_boundaries);

        // Mode B: Local Windows (Information Reducing / Ablation)
        let pkt_b = StereoscopicPromptGenerator::generate_prompt_packet(&exp, CodeRepresentationMode::LocalWindows, "2026-11-17T13:30:00Z", None);
        assert_eq!(pkt_b.audit.information_class, RepresentationInformationClass::InformationReducing);
        assert!(pkt_b.audit.exact_instruction_text_supplied);
        assert!(!pkt_b.audit.explicit_branch_destinations);
        assert!(!pkt_b.audit.explicit_cfg_edges);
        assert!(pkt_b.audit.explicit_basic_block_boundaries);
        assert!(pkt_b.prompt_markdown_text.contains("[REDACTED_BRANCH_TARGET]"));

        // Mode C: Global Topology (Information Reducing / Ablation)
        let pkt_c = StereoscopicPromptGenerator::generate_prompt_packet(&exp, CodeRepresentationMode::GlobalTopology, "2026-11-17T13:30:00Z", None);
        assert_eq!(pkt_c.audit.information_class, RepresentationInformationClass::InformationReducing);
        assert!(!pkt_c.audit.exact_instruction_text_supplied);
        assert!(pkt_c.audit.explicit_branch_destinations);
        assert!(pkt_c.audit.explicit_cfg_edges);
        assert!(pkt_c.audit.explicit_basic_block_boundaries);
        assert!(pkt_c.prompt_markdown_text.contains("Loop Header"));

        // Mode D: Structured Dual View (Structurally Augmented)
        let pkt_d = StereoscopicPromptGenerator::generate_prompt_packet(&exp, CodeRepresentationMode::StructuredDualView, "2026-11-17T13:30:00Z", None);
        assert_eq!(pkt_d.audit.information_class, RepresentationInformationClass::StructurallyAugmented);
        assert!(pkt_d.audit.exact_instruction_text_supplied);
        assert!(pkt_d.audit.explicit_branch_destinations);
        assert!(pkt_d.audit.explicit_cfg_edges);
        assert!(pkt_d.audit.explicit_basic_block_boundaries);
        assert!(pkt_d.prompt_markdown_text.contains("Dual-View Perspective 1"));
        assert!(pkt_d.prompt_markdown_text.contains("Dual-View Perspective 2"));

        // Mode E: Self-Reconstructed Dual View (Information Preserving)
        let pkt_e = StereoscopicPromptGenerator::generate_prompt_packet(&exp, CodeRepresentationMode::SelfReconstructedDualView, "2026-11-17T13:30:00Z", None);
        assert_eq!(pkt_e.audit.information_class, RepresentationInformationClass::InformationPreserving);
        assert!(pkt_e.audit.exact_instruction_text_supplied);
        assert!(!pkt_e.audit.explicit_branch_destinations);
        assert!(!pkt_e.audit.explicit_cfg_edges);
        assert!(!pkt_e.audit.explicit_basic_block_boundaries);
        assert!(pkt_e.prompt_markdown_text.contains("Mandatory Stereoscopic Self-Reconstruction Protocol"));
    }

    #[test]
    fn test_phase7_leakage_audit_strictly_withholds_all_runtime_traces() {
        let exp = ExperimentDefinition::populate_phase7_fresh_experiment();
        let modes = [
            CodeRepresentationMode::LinearDisassembly,
            CodeRepresentationMode::LocalWindows,
            CodeRepresentationMode::GlobalTopology,
            CodeRepresentationMode::StructuredDualView,
            CodeRepresentationMode::SelfReconstructedDualView,
        ];

        for &mode in &modes {
            let pkt = StereoscopicPromptGenerator::generate_prompt_packet(&exp, mode, "2026-11-17T13:30:00Z", None);
            let text = &pkt.prompt_markdown_text;

            assert!(!text.contains("trace_observed_counts"), "Mode {:?} must not leak trace_observed_counts", mode);
            assert!(!text.contains("observed_instruction_counts"), "Mode {:?} must not leak observed_instruction_counts", mode);
            assert!(!text.contains("trace_artifact_reference"), "Mode {:?} must not leak trace_artifact_reference", mode);
            assert!(!text.contains("3 + 7*L + k"), "Mode {:?} must not leak closed-form formula", mode);
            assert!(!text.contains("32 steps"), "Mode {:?} must not leak dynamic vector counts", mode);
            assert!(!text.contains("NativeTraceEvidence"), "Mode {:?} must not leak evidence struct", mode);
        }
    }

    #[test]
    fn test_phase7_prompt_provenance_and_freezing_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("cae_phase7_store_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let store = DurablePredictionStore::new(&temp_dir).expect("Store creation must succeed");

        let exp = ExperimentDefinition::populate_phase7_fresh_experiment();
        store.save_experiment(&exp).expect("Save experiment must succeed");

        // Generate Condition D (Structured Dual View) prompt packet
        let packet_d = StereoscopicPromptGenerator::generate_prompt_packet(
            &exp,
            CodeRepresentationMode::StructuredDualView,
            "2026-11-17T13:35:00Z",
            Some("gpt-4o-2024-08-06;temperature=0.0"),
        );
        assert!(packet_d.verify_integrity());

        // Construct candidate prediction anchored to prompt packet
        let structured = StructuredPrediction {
            instruction_count: InstructionCountHypothesis::PiecewiseGeneral {
                rules: vec![
                    ("x == 0".to_string(), "3 steps".to_string()),
                    ("x > 0".to_string(), "3 + 7*L + k steps (L = bit length, k = popcount)".to_string()),
                ],
            },
            loop_branch: LoopBranchHypothesis::LoopWithBackedges {
                loop_header_backedges: "L backedges".to_string(),
                backward_join_branches: None,
            },
            register_roles: vec![
                RegisterRoleHypothesis { register_name: "EAX".to_string(), hypothesized_role: "Accumulator".to_string() },
                RegisterRoleHypothesis { register_name: "RCX".to_string(), hypothesized_role: "Shift Operand".to_string() },
            ],
            confidence_percent: Some(95),
            notes_and_rationale: "Dual-view synthesis: 1 init + L iterations * (7 steps) + k odd extra steps + 2 exit steps".to_string(),
        };

        let mut record = PredictionRecord::new_draft(
            "PRED-PHASE7-EXP002-D",
            &packet_d.experiment_id,
            "Stereoscopic-Analyst",
            "Synthesized from Condition D dual view.",
            structured,
            "2026-11-17T13:40:00Z",
        );

        // Pre-disclosure freeze
        record.freeze().expect("Record freeze must succeed");
        assert_eq!(record.state(), PredictionState::Frozen);
        assert!(record.verify_integrity());

        // Save to durable store in Frozen state
        store.save_prediction(&record).expect("Save frozen prediction must succeed");

        // Reload and verify frozen hash
        let reloaded = store.load_prediction("PRED-PHASE7-EXP002-D").expect("Reload must succeed");
        assert_eq!(reloaded.state(), PredictionState::Frozen);
        assert_eq!(reloaded.canonical_sha256(), record.canonical_sha256());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

}
