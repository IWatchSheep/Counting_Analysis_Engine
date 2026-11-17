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

    #[test]
    #[cfg(windows)]
    fn test_native_trace_kernighan_budget_exhaustion() {
        let debug_exe = std::path::Path::new("target/debug/cae_trace_target.exe");
        let report = WindowsNativeDebugger::trace_kernel_with_exe(debug_exe, "kernighan", u64::MAX, 50)
            .expect("Native trace of kernighan with budget 50 should cleanly terminate");

        assert_eq!(report.status, NativeTraceStatus::BudgetExhausted(50));
        assert_eq!(report.total_observed_instructions, 50);
    }
}
