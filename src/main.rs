#![allow(non_snake_case)]

use Counting_Analysis_Engine::algorithms::{popcount_kernighan, popcount_naive, popcount_reference};
use Counting_Analysis_Engine::archive::{InterpretationArchive, OptimizationArchive};
use Counting_Analysis_Engine::dynamic_analysis::measure_dynamic_kernel;
use Counting_Analysis_Engine::report::{SingleInputReport, StaticAssemblyReport, UnifiedThreeTierReport};
use Counting_Analysis_Engine::static_analysis::disassemble_function_pointer;
use Counting_Analysis_Engine::verification::{
    generate_standard_test_vectors, verify_exhaustive_16bit_subdomain, verify_input,
    DeterministicRng,
};

fn main() {
    println!("================================================================================");
    println!("           Counting Analysis Engine (CAE) — Milestone CAE-1C Execution          ");
    println!("================================================================================");
    println!("Guiding Philosophy: Discover what is counted, audit how it is counted,");
    println!("critique its efficiency, and synthesize verified improvements.\n");

    // 1. Run Verification across Standard Vectors & 16-bit Exhaustive Subdomain
    println!("--- [Phase 1: Verification Rigor & Boundary Testing] ---");
    let standard_vectors = generate_standard_test_vectors();
    let mut all_standard_passed = true;

    for vec in &standard_vectors {
        let res = verify_input(vec.value);
        if !res.all_agree || res.oracle_result != vec.expected_count {
            eprintln!("Verification failure on {}: {:?}", vec.name, res);
            all_standard_passed = false;
        }
    }

    if all_standard_passed {
        println!("PASSED: All {} standard test vectors produced bit-for-bit identical results", standard_vectors.len());
        println!("across Naive Loop, Kernighan Algorithm, Reference Intrinsic, and Independent Oracle.");
    }

    // Exhaustive Bounded Domain Verification (16-bit space)
    println!("\nExecuting Exhaustive Bounded Domain Check across 16-bit space (65,536 values)...");
    let (exhaustive_pass, count_checked) = verify_exhaustive_16bit_subdomain();
    if exhaustive_pass {
        println!("EXHAUSTIVE BOUNDED VERIFICATION (ExhaustiveBoundedDomain): 100% of 16-bit space ({} inputs) verified identical.", count_checked);
        println!("NOTE: This proves equivalence across the 16-bit sub-domain (2^16 states).");
        println!("      It does NOT constitute a formal mathematical proof across the entire 64-bit domain (2^64 states).\n");
    } else {
        eprintln!("FAILED: Discrepancy detected during exhaustive bounded domain check!\n");
    }

    // 2. Run Verification across 1,000 Pseudorandom Vectors (Empirical Sampling)
    println!("--- [Phase 2: Empirical Sampling Verification (1,000 Random Samples)] ---");
    let mut rng = DeterministicRng::new(0xCAFE_BABE_DEAD_BEEF);
    let mut random_passed = true;

    for _ in 0..1000 {
        let val = rng.next_u64();
        let res = verify_input(val);
        if !res.all_agree {
            eprintln!("Verification failure on random input 0x{:016X}: {:?}", val, res);
            random_passed = false;
            break;
        }
    }

    if random_passed {
        println!("PASSED: 1,000 deterministic pseudorandom samples verified unanimously (EmpiricalSampled).\n");
    }

    // 3. Pre-compute Static Assembly Profiles (Tier 2: iced-x86)
    println!("--- [Phase 3: Static Machine Code Profiling (Tier 2)] ---");
    let naive_static =
        disassemble_function_pointer("popcount_naive", popcount_naive as *const (), 512)
            .expect("Failed to disassemble popcount_naive");
    let kernighan_static =
        disassemble_function_pointer("popcount_kernighan", popcount_kernighan as *const (), 512)
            .expect("Failed to disassemble popcount_kernighan");
    let reference_static =
        disassemble_function_pointer("popcount_reference", popcount_reference as *const (), 512)
            .expect("Failed to disassemble popcount_reference");

    println!("Static assembly profiles generated via iced-x86 with .pdata boundary resolution.\n");

    // 4. Generate Unified Three-Tier Comparison Reports (Tiers 1, 2, and 3)
    println!("--- [Phase 4: Unified Three-Tier Experiment Reports] ---\n");

    let sample_cases = [
        ("Single Bit Set (Sparse: 1 bit)", 0x0000_0000_0000_0001u64),
        ("Alternating Bits (Balanced: 32 bits)", 0x5555_5555_5555_5555u64),
        ("All Bits Set (Dense: 64 bits)", u64::MAX),
    ];

    for (description, val) in sample_cases {
        println!("## Case: {}", description);
        let source_report = SingleInputReport::generate(val);
        let static_report = StaticAssemblyReport::new(
            naive_static.clone(),
            kernighan_static.clone(),
            reference_static.clone(),
        );

        let (_, naive_dyn) = measure_dynamic_kernel("popcount_naive", val, popcount_naive);
        let (_, kern_dyn) = measure_dynamic_kernel("popcount_kernighan", val, popcount_kernighan);
        let (_, ref_dyn) = measure_dynamic_kernel("popcount_reference", val, popcount_reference);

        let unified_report = UnifiedThreeTierReport::new(
            val,
            source_report,
            static_report,
            naive_dyn,
            kern_dyn,
            ref_dyn,
        );

        println!("{}", unified_report.render_markdown_table());
    }

    // 5. Dual-Track Archives: Optimization Archive + Interpretation Archive
    println!("--- [Phase 5: Optimization Archive (Code Transformations)] ---\n");
    let opt_archive = OptimizationArchive::populate_cae1c_findings();
    println!("{}", opt_archive.render_markdown_table());

    println!("--- [Phase 6: Interpretation Archive (Knowledge Base)] ---\n");
    let interp_archive = InterpretationArchive::populate_cae1b_findings();
    println!("{}", interp_archive.render_markdown_table());

    println!("================================================================================");
    println!("CAE-1C Milestone Complete. Ready for review before authorizing the next phase.");
    println!("================================================================================");
}
