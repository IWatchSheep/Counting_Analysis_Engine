#![allow(non_snake_case)]

use Counting_Analysis_Engine::report::SingleInputReport;
use Counting_Analysis_Engine::verification::{
    generate_standard_test_vectors, verify_input, DeterministicRng,
};

fn main() {
    println!("================================================================================");
    println!("           Counting Analysis Engine (CAE) — Milestone CAE-1A Execution          ");
    println!("================================================================================");
    println!("Guiding Philosophy: Discover what is counted, audit how it is counted,");
    println!("critique its efficiency, and synthesize verified improvements.\n");

    // 1. Run Verification across Standard Vectors
    println!("--- [Phase 1: Standard Test Vectors Verification] ---");
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
        println!("across Naive Loop, Kernighan Algorithm, Reference Intrinsic, and Independent Oracle.\n");
    } else {
        eprintln!("FAILED: Discrepancy detected in standard test vectors!\n");
    }

    // 2. Run Verification across 1,000 Pseudorandom Vectors
    println!("--- [Phase 2: Pseudorandom Input Verification (1,000 Samples)] ---");
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
        println!("PASSED: 1,000 deterministic pseudorandom samples verified unanimously.\n");
    }

    // 3. Generate Comparative Reports for Representative Inputs
    println!("--- [Phase 3: Source-Level Operation Accounting Reports] ---\n");

    let sample_cases = [
        ("Single Bit Set (Sparse)", 0x0000_0000_0000_0001u64),
        ("Alternating Bits (32 set)", 0x5555_5555_5555_5555u64),
        ("All Bits Set (Dense)", u64::MAX),
        ("Fixed Random Word", 0xCAFE_BABE_DEAD_BEEFu64),
    ];

    for (description, val) in sample_cases {
        println!("## Case: {}", description);
        let report = SingleInputReport::generate(val);
        println!("{}", report.render_markdown_table());
    }

    println!("================================================================================");
    println!("CAE-1A Checkpoint Complete. Ready for review before authorizing CAE-1B.");
    println!("================================================================================");
}
