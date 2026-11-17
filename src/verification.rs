//! # Verification Suite & Reproducible Input Generation
//!
//! Provides deterministic, reproducible test vectors and independent verification oracles
//! to guarantee that all population-counting implementations produce bit-for-bit identical results.
//!
//! ## Architectural Note: Verification Rigor vs. Mathematical Proof
//! - **Empirical Verification** tests sampled finite inputs (standard vectors + pseudorandom fuzzing).
//!   While it provides high empirical confidence, it does NOT constitute a formal mathematical proof
//!   across the entire $2^{64}$ state space.
//! - **Exhaustive Bounded Domain Verification** tests 100% of all possible inputs within a bounded
//!   state space (e.g., all 65,536 possible 16-bit values), providing a complete mathematical proof
//!   for that sub-domain.

use crate::algorithms::{popcount_kernighan, popcount_naive, popcount_reference};

/// Distinct tiers of verification rigor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationRigor {
    /// High-confidence empirical verification over finite sampled test vectors.
    EmpiricalSampled { sample_count: usize },
    /// Exhaustive proof across all possible inputs in a bounded domain (e.g. 16-bit space).
    ExhaustiveBoundedDomain { bit_width: u8, total_states: u64 },
    /// Formal mathematical proof or translation validation (e.g. via symbolic solver or SMT).
    FormalProof { proof_system: &'static str },
}

/// Deterministic 64-bit XorShift pseudorandom generator.
///
/// Ensures test sequences are completely reproducible across all platforms
/// without introducing external dependencies.
#[derive(Debug, Clone)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    /// Seed the generator with a fixed 64-bit constant.
    pub const fn new(seed: u64) -> Self {
        // State must be non-zero for xorshift64
        let state = if seed == 0 { 0xCAFE_BABE_DEAD_BEEF } else { seed };
        Self { state }
    }

    /// Produce the next pseudo-random 64-bit unsigned integer.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

/// A named reproducible test vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestVector {
    pub name: &'static str,
    pub value: u64,
    pub expected_count: u32,
}

/// Generate the standard suite of deterministic test vectors:
/// - Zero
/// - Maximum value (`u64::MAX`)
/// - All 64 single-bit patterns (`1 << 0` to `1 << 63`)
/// - Alternating bit patterns (even bits, odd bits, nibble alternating, byte alternating)
pub fn generate_standard_test_vectors() -> Vec<TestVector> {
    let mut vectors = Vec::new();

    // 1. Boundary cases
    vectors.push(TestVector {
        name: "Zero (No bits set)",
        value: 0,
        expected_count: 0,
    });
    vectors.push(TestVector {
        name: "Max u64 (All 64 bits set)",
        value: u64::MAX,
        expected_count: 64,
    });

    // 2. All 64 single-bit isolated patterns
    for i in 0..64 {
        vectors.push(TestVector {
            name: "Single bit set",
            value: 1u64 << i,
            expected_count: 1,
        });
    }

    // 3. Alternating bit patterns
    vectors.push(TestVector {
        name: "Alternating bits: 0x5555_5555_5555_5555 (32 bits set, even positions)",
        value: 0x5555_5555_5555_5555,
        expected_count: 32,
    });
    vectors.push(TestVector {
        name: "Alternating bits: 0xAAAA_AAAA_AAAA_AAAA (32 bits set, odd positions)",
        value: 0xAAAA_AAAA_AAAA_AAAA,
        expected_count: 32,
    });
    vectors.push(TestVector {
        name: "Alternating pairs: 0x3333_3333_3333_3333 (32 bits set)",
        value: 0x3333_3333_3333_3333,
        expected_count: 32,
    });
    vectors.push(TestVector {
        name: "Alternating nibbles: 0x0F0F_0F0F_0F0F_0F0F (32 bits set)",
        value: 0x0F0F_0F0F_0F0F_0F0F,
        expected_count: 32,
    });
    vectors.push(TestVector {
        name: "Alternating bytes: 0x00FF_00FF_00FF_00FF (32 bits set)",
        value: 0x00FF_00FF_00FF_00FF,
        expected_count: 32,
    });
    vectors.push(TestVector {
        name: "Alternating words: 0x0000_FFFF_0000_FFFF (32 bits set)",
        value: 0x0000_FFFF_0000_FFFF,
        expected_count: 32,
    });
    vectors.push(TestVector {
        name: "Alternating dwords: 0x0000_0000_FFFF_FFFF (32 bits set)",
        value: 0x0000_0000_FFFF_FFFF,
        expected_count: 32,
    });

    vectors
}

/// Independent reference oracle that calculates population count by formatting the integer
/// as a binary string and counting '1' characters.
///
/// This provides a completely independent validation path that relies neither on bitwise
/// arithmetic loops nor the standard library `count_ones()` intrinsic.
pub fn independent_string_oracle(n: u64) -> u32 {
    format!("{:b}", n).chars().filter(|&c| c == '1').count() as u32
}

/// Result of verifying a test input against all three algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    pub input: u64,
    pub naive_result: u32,
    pub kernighan_result: u32,
    pub reference_result: u32,
    pub oracle_result: u32,
    pub all_agree: bool,
}

/// Run an input through all counting implementations and confirm unanimous agreement.
pub fn verify_input(n: u64) -> VerificationResult {
    let naive = popcount_naive(n);
    let kernighan = popcount_kernighan(n);
    let reference = popcount_reference(n);
    let oracle = independent_string_oracle(n);

    let all_agree = (naive == kernighan) && (kernighan == reference) && (reference == oracle);

    VerificationResult {
        input: n,
        naive_result: naive,
        kernighan_result: kernighan,
        reference_result: reference,
        oracle_result: oracle,
        all_agree,
    }
}

/// Exhaustively verify equivalence across all 65,536 possible 16-bit values.
///
/// Because every single state in `0..=65,535` is checked, this constitutes a
/// true exhaustive mathematical proof of equivalence for the 16-bit sub-domain.
pub fn verify_exhaustive_16bit_subdomain() -> (bool, u64) {
    let mut total_checked = 0u64;
    for val in 0..=u16::MAX {
        let n = val as u64;
        let naive = popcount_naive(n);
        let kernighan = popcount_kernighan(n);
        let reference = popcount_reference(n);
        let oracle = independent_string_oracle(n);

        if !(naive == kernighan && kernighan == reference && reference == oracle) {
            return (false, total_checked);
        }
        total_checked += 1;
    }
    (true, total_checked)
}
