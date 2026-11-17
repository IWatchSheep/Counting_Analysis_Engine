#![allow(non_snake_case)]

use Counting_Analysis_Engine::algorithms::{popcount_kernighan, popcount_naive, popcount_reference};
use Counting_Analysis_Engine::archive::InterpretationArchive;
use Counting_Analysis_Engine::report::{SingleInputReport, StaticAssemblyReport};
use Counting_Analysis_Engine::static_analysis::disassemble_function_pointer;
use Counting_Analysis_Engine::verification::{
    generate_standard_test_vectors, verify_exhaustive_16bit_subdomain, verify_input,
    DeterministicRng,
};

fn main() {
    println!("================================================================================");
    println!("           Counting Analysis Engine (CAE) — Milestone CAE-1B Execution          ");
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

    // 3. Generate Comparative Reports for Representative Inputs (Tier 1)
    println!("--- [Phase 3: Tier 1 Source-Level Operation Accounting Reports] ---\n");

    let sample_cases = [
        ("Single Bit Set (Sparse)", 0x0000_0000_0000_0001u64),
        ("Alternating Bits (32 set)", 0x5555_5555_5555_5555u64),
        ("All Bits Set (Dense)", u64::MAX),
    ];

    for (description, val) in sample_cases {
        println!("## Case: {}", description);
        let report = SingleInputReport::generate(val);
        println!("{}", report.render_markdown_table());
    }

    // 4. Static Assembly Analysis (Tier 2: iced-x86)
    println!("--- [Phase 4: Tier 2 Static Compiled Assembly Inspection (iced-x86)] ---\n");

    let naive_profile =
        disassemble_function_pointer("popcount_naive", popcount_naive as *const (), 512)
            .expect("Failed to disassemble popcount_naive");
    let kernighan_profile =
        disassemble_function_pointer("popcount_kernighan", popcount_kernighan as *const (), 512)
            .expect("Failed to disassemble popcount_kernighan");
    let reference_profile =
        disassemble_function_pointer("popcount_reference", popcount_reference as *const (), 512)
            .expect("Failed to disassemble popcount_reference");

    let static_report = StaticAssemblyReport::new(naive_profile, kernighan_profile, reference_profile);
    println!("{}", static_report.render_markdown_table());

    // 5. Interpretation Archive
    println!("--- [Phase 5: Interpretation Archive (Knowledge Base)] ---\n");
    let archive = InterpretationArchive::populate_cae1b_findings();
    println!("{}", archive.render_markdown_table());

    println!("================================================================================");
    println!("CAE-1B Milestone Complete. Ready for review before authorizing CAE-1C.");
    println!("================================================================================");
}
