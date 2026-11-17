//! # Unified Three-Tier Experiment Reporting
//!
//! Generates structured comparison reports consolidating:
//! - **Tier 1:** Source-level operation accounting (iterations, increments, intrinsic calls).
//! - **Tier 2:** Static compiled machine-code metrics (instructions, bytes, loops, accumulators).
//! - **Tier 3:** Dynamic execution work (model-estimated dynamic instructions, serialized TSC, thread cycles).

use crate::dynamic_analysis::DynamicExecutionMetrics;
use crate::instrumentation::{
    popcount_kernighan_instrumented, popcount_naive_instrumented, popcount_reference_instrumented,
    SourceOperationCounts,
};
use crate::static_analysis::StaticFunctionProfile;
use crate::verification::independent_string_oracle;

/// Comparison record for a single input tested across the three implementations (Tier 1).
#[derive(Debug, Clone)]
pub struct SingleInputReport {
    pub input_hex: String,
    pub input_decimal: u64,
    pub oracle_count: u32,
    pub naive_count: u32,
    pub naive_ops: SourceOperationCounts,
    pub kernighan_count: u32,
    pub kernighan_ops: SourceOperationCounts,
    pub reference_count: u32,
    pub reference_ops: SourceOperationCounts,
    pub verified_correct: bool,
}

impl SingleInputReport {
    /// Generate a comparison report for a specific 64-bit integer input.
    pub fn generate(n: u64) -> Self {
        let oracle = independent_string_oracle(n);
        let (naive_c, naive_ops) = popcount_naive_instrumented(n);
        let (kernighan_c, kernighan_ops) = popcount_kernighan_instrumented(n);
        let (reference_c, reference_ops) = popcount_reference_instrumented(n);

        let verified_correct = (naive_c == oracle)
            && (kernighan_c == oracle)
            && (reference_c == oracle);

        Self {
            input_hex: format!("0x{:016X}", n),
            input_decimal: n,
            oracle_count: oracle,
            naive_count: naive_c,
            naive_ops,
            kernighan_count: kernighan_c,
            kernighan_ops,
            reference_count: reference_c,
            reference_ops,
            verified_correct,
        }
    }

    /// Render human-readable summary table for Tier 1 source operations.
    pub fn render_markdown_table(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("### Input: {} ({})\n\n", self.input_hex, self.input_decimal));
        out.push_str(&format!("- **Independent Reference Oracle Count:** `{}`\n", self.oracle_count));
        out.push_str(&format!(
            "- **All Implementations Agree:** {}\n\n",
            if self.verified_correct { "**PASS** (Bit-for-Bit Identical)" } else { "**FAIL**" }
        ));

        out.push_str("| Metric Category (Tier 1: Source Operations) | Naive Loop | Kernighan | Reference (`count_ones()`) |\n");
        out.push_str("| :--- | :---: | :---: | :---: |\n");
        out.push_str(&format!("| **Returned Count** | `{}` | `{}` | `{}` |\n", self.naive_count, self.kernighan_count, self.reference_count));
        out.push_str(&format!("| **Source Loop Iterations** | `{}` | `{}` | `{}` |\n", self.naive_ops.loop_iterations, self.kernighan_ops.loop_iterations, self.reference_ops.loop_iterations));
        out.push_str(&format!("| **Counter Updates (`count += 1`)** | `{}` | `{}` | `{}` |\n", self.naive_ops.counter_updates, self.kernighan_ops.counter_updates, self.reference_ops.counter_updates));
        out.push_str(&format!("| **Opaque Intrinsic Invocations** | `{}` | `{}` | `{}` |\n", self.naive_ops.opaque_invocations, self.kernighan_ops.opaque_invocations, self.reference_ops.opaque_invocations));
        out.push_str(&format!("| **Condition Evaluations** | `{}` | `{}` | `{}` |\n", self.naive_ops.condition_evaluations, self.kernighan_ops.condition_evaluations, self.reference_ops.condition_evaluations));
        out.push_str(&format!("| **Bitwise ANDs (`&`)** | `{}` | `{}` | `{}` |\n", self.naive_ops.bitwise_ands, self.kernighan_ops.bitwise_ands, self.reference_ops.bitwise_ands));
        out.push_str(&format!("| **Bit Shifts (`>>`)** | `{}` | `{}` | `{}` |\n", self.naive_ops.bit_shifts, self.kernighan_ops.bit_shifts, self.reference_ops.bit_shifts));
        out.push_str(&format!("| **Subtractions (`- 1`)** | `{}` | `{}` | `{}` |\n", self.naive_ops.arithmetic_subtractions, self.kernighan_ops.arithmetic_subtractions, self.reference_ops.arithmetic_subtractions));
        out.push_str(&format!("| **Total Tracked Source Ops** | `{}` | `{}` | `{}` |\n\n", self.naive_ops.total_operations(), self.kernighan_ops.total_operations(), self.reference_ops.total_operations()));

        out
    }
}

/// Comparative Static Assembly Report (Tier 2).
#[derive(Debug, Clone)]
pub struct StaticAssemblyReport {
    pub naive_profile: StaticFunctionProfile,
    pub kernighan_profile: StaticFunctionProfile,
    pub reference_profile: StaticFunctionProfile,
}

impl StaticAssemblyReport {
    pub fn new(
        naive: StaticFunctionProfile,
        kernighan: StaticFunctionProfile,
        reference: StaticFunctionProfile,
    ) -> Self {
        Self {
            naive_profile: naive,
            kernighan_profile: kernighan,
            reference_profile: reference,
        }
    }

    /// Render human-readable summary table comparing the three compiled static profiles.
    pub fn render_markdown_table(&self) -> String {
        let mut out = String::new();
        out.push_str("## Tier 2: Static Compiled Assembly Comparison (iced-x86)\n\n");

        out.push_str("| Metric Category (Tier 2: Static Assembly) | Naive Loop | Kernighan | Reference (`count_ones()`) |\n");
        out.push_str("| :--- | :---: | :---: | :---: |\n");
        out.push_str(&format!(
            "| **Total Static Instructions** | `{}` | `{}` | `{}` |\n",
            self.naive_profile.total_instructions,
            self.kernighan_profile.total_instructions,
            self.reference_profile.total_instructions
        ));
        out.push_str(&format!(
            "| **Total Code Size (Bytes)** | `{} bytes` | `{} bytes` | `{} bytes` |\n",
            self.naive_profile.total_bytes,
            self.kernighan_profile.total_bytes,
            self.reference_profile.total_bytes
        ));
        out.push_str(&format!(
            "| **Boundary Resolution** | `{:?}` | `{:?}` | `{:?}` |\n",
            self.naive_profile.boundary_method,
            self.kernighan_profile.boundary_method,
            self.reference_profile.boundary_method
        ));
        out.push_str(&format!(
            "| **Detected Static Loops** | `{}` | `{}` | `{}` |\n",
            self.naive_profile.loops.len(),
            self.kernighan_profile.loops.len(),
            self.reference_profile.loops.len()
        ));
        out.push_str(&format!(
            "| **Candidate Accumulators** | `{}` | `{}` | `{}` |\n\n",
            self.naive_profile.candidate_accumulators.len(),
            self.kernighan_profile.candidate_accumulators.len(),
            self.reference_profile.candidate_accumulators.len()
        ));

        // Details of Candidate Accumulators with dataflow evidence
        out.push_str("### Candidate Accumulators with Dataflow Evidence\n\n");

        for profile in [&self.naive_profile, &self.kernighan_profile, &self.reference_profile] {
            out.push_str(&format!("#### Routine: `{}`\n", profile.function_name));
            if profile.candidate_accumulators.is_empty() {
                out.push_str("- *No iterative loop accumulators detected (direct / hardware-intrinsic execution).* \n\n");
            } else {
                for cand in &profile.candidate_accumulators {
                    out.push_str(&format!(
                        "- **Register `{}`** — Hypothesis: `{:?}` (Confidence: `{:?}`)\n",
                        cand.register_name, cand.role_hypothesis, cand.confidence
                    ));
                    for ev in &cand.supporting_evidence {
                        out.push_str(&format!("  - [Evidence] {}\n", ev));
                    }
                    for con in &cand.contraindications {
                        out.push_str(&format!("  - [Contraindication] {}\n", con));
                    }
                }
                out.push('\n');
            }
        }

        out
    }
}

/// Unified Three-Tier Comparison Report (Consolidating Tiers 1, 2, and 3).
#[derive(Debug, Clone)]
pub struct UnifiedThreeTierReport {
    pub input_hex: String,
    pub input_decimal: u64,
    pub oracle_count: u32,
    pub source_report: SingleInputReport,
    pub static_report: StaticAssemblyReport,
    pub naive_dynamic: DynamicExecutionMetrics,
    pub kernighan_dynamic: DynamicExecutionMetrics,
    pub reference_dynamic: DynamicExecutionMetrics,
}

impl UnifiedThreeTierReport {
    pub fn new(
        input: u64,
        source: SingleInputReport,
        static_rep: StaticAssemblyReport,
        naive_dyn: DynamicExecutionMetrics,
        kernighan_dyn: DynamicExecutionMetrics,
        ref_dyn: DynamicExecutionMetrics,
    ) -> Self {
        Self {
            input_hex: format!("0x{:016X}", input),
            input_decimal: input,
            oracle_count: source.oracle_count,
            source_report: source,
            static_report: static_rep,
            naive_dynamic: naive_dyn,
            kernighan_dynamic: kernighan_dyn,
            reference_dynamic: ref_dyn,
        }
    }

    /// Render complete unified Markdown report for all three tiers with explicit methodology labels.
    pub fn render_markdown_table(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("### Unified Three-Tier Report: Input {} ({})\n\n", self.input_hex, self.input_decimal));
        out.push_str(&format!("- **Independent Reference Oracle Count:** `{}`\n", self.oracle_count));
        out.push_str(&format!(
            "- **All Implementations Agree:** {}\n\n",
            if self.source_report.verified_correct { "**PASS** (Bit-for-Bit Identical)" } else { "**FAIL**" }
        ));

        out.push_str("| Layer / Measurement Tier | Metric Category | Naive Loop | Kernighan | Reference (`count_ones()`) |\n");
        out.push_str("| :--- | :--- | :---: | :---: | :---: |\n");

        // Correctness
        out.push_str(&format!("| **Correctness** | Returned Population Count | `{}` | `{}` | `{}` |\n",
            self.source_report.naive_count, self.source_report.kernighan_count, self.source_report.reference_count));

        // Tier 1: Source Operations
        out.push_str(&format!("| **Tier 1: Source Operations** | Loop Iterations | `{}` | `{}` | `{}` |\n",
            self.source_report.naive_ops.loop_iterations, self.source_report.kernighan_ops.loop_iterations, self.source_report.reference_ops.loop_iterations));
        out.push_str(&format!("| | Counter Updates (`count += 1`) | `{}` | `{}` | `{}` |\n",
            self.source_report.naive_ops.counter_updates, self.source_report.kernighan_ops.counter_updates, self.source_report.reference_ops.counter_updates));
        out.push_str(&format!("| | Opaque Intrinsic Invocations | `{}` | `{}` | `{}` |\n",
            self.source_report.naive_ops.opaque_invocations, self.source_report.kernighan_ops.opaque_invocations, self.source_report.reference_ops.opaque_invocations));
        out.push_str(&format!("| | Total Tracked Source Ops | `{}` | `{}` | `{}` |\n",
            self.source_report.naive_ops.total_operations(), self.source_report.kernighan_ops.total_operations(), self.source_report.reference_ops.total_operations()));

        // Tier 2: Static Assembly
        out.push_str(&format!("| **Tier 2: Static Assembly** | Total Static Instructions | `{}` | `{}` | `{}` |\n",
            self.static_report.naive_profile.total_instructions, self.static_report.kernighan_profile.total_instructions, self.static_report.reference_profile.total_instructions));
        out.push_str(&format!("| | Total Code Size (Bytes) | `{} B` | `{} B` | `{} B` |\n",
            self.static_report.naive_profile.total_bytes, self.static_report.kernighan_profile.total_bytes, self.static_report.reference_profile.total_bytes));
        out.push_str(&format!("| | Detected Static Loops | `{}` | `{}` | `{}` |\n",
            self.static_report.naive_profile.loops.len(), self.static_report.kernighan_profile.loops.len(), self.static_report.reference_profile.loops.len()));
        out.push_str(&format!("| | Candidate Accumulators | `{}` | `{}` | `{}` |\n",
            self.static_report.naive_profile.candidate_accumulators.len(), self.static_report.kernighan_profile.candidate_accumulators.len(), self.static_report.reference_profile.candidate_accumulators.len()));

        // Tier 3: Dynamic Work (With Explicit Method Names)
        let naive_inst = self.naive_dynamic.dynamic_instructions.map(|n| n.to_string()).unwrap_or_else(|| "N/A".to_string());
        let kern_inst = self.kernighan_dynamic.dynamic_instructions.map(|n| n.to_string()).unwrap_or_else(|| "N/A".to_string());
        let ref_inst = self.reference_dynamic.dynamic_instructions.map(|n| n.to_string()).unwrap_or_else(|| "N/A".to_string());

        out.push_str(&format!("| **Tier 3: Dynamic Work** | Model-Estimated Dynamic Instrs | `{}` | `{}` | `{}` |\n",
            naive_inst, kern_inst, ref_inst));
        out.push_str(&format!("| | Serialized TSC Ticks (_rdtsc) | `{} ticks` | `{} ticks` | `{} ticks` |\n",
            self.naive_dynamic.rdtsc_cycles, self.kernighan_dynamic.rdtsc_cycles, self.reference_dynamic.rdtsc_cycles));
        out.push_str(&format!("| | Harness Baseline Overhead | `{} ticks` | `{} ticks` | `{} ticks` |\n",
            self.naive_dynamic.harness_overhead_cycles, self.kernighan_dynamic.harness_overhead_cycles, self.reference_dynamic.harness_overhead_cycles));
        out.push_str(&format!("| | Win32 Thread Cycles (Median) | `{} cycles` | `{} cycles` | `{} cycles` |\n",
            self.naive_dynamic.thread_cycles, self.kernighan_dynamic.thread_cycles, self.reference_dynamic.thread_cycles));

        // Cross-Tier Ratios
        if let (Some(n_i), Some(k_i), Some(r_i)) = (
            self.naive_dynamic.dynamic_instructions,
            self.kernighan_dynamic.dynamic_instructions,
            self.reference_dynamic.dynamic_instructions,
        ) {
            let k_reduction = if n_i > 0 { ((n_i as f64 - k_i as f64) / n_i as f64) * 100.0 } else { 0.0 };
            let r_reduction = if n_i > 0 { ((n_i as f64 - r_i as f64) / n_i as f64) * 100.0 } else { 0.0 };
            out.push_str(&format!("| **Cross-Tier Analysis** | Dynamic Reduction vs Baseline | Baseline (0.0%) | `{:+.1}%` | `{:+.1}%` |\n\n",
                -k_reduction, -r_reduction));
        } else {
            out.push('\n');
        }

        out.push_str("> [!IMPORTANT]\n");
        out.push_str("> **Measurement Methodology Notes:**\n");
        out.push_str("> 1. **Model-Estimated Instructions:** Dynamic instruction counts are derived from basic-block path execution modeling. They are NOT directly observed from physical hardware PMU counters (RDPMC requires Ring 0 elevation on Windows).\n");
        out.push_str("> 2. **Serialized TSC Cycles:** Measured with `_mm_lfence()` pipeline serialization barriers to prevent out-of-order instruction hoisting. TSC ticks at nominal CPU base frequency.\n");
        out.push_str("> 3. **Win32 Thread Cycles:** Measured via `QueryThreadCycleTime`. Has ~750-cycle API call overhead; identical numbers on fast sub-microsecond routines reflect kernel call granularity.\n");
        out.push_str("> 4. **Core Optimization Principle:** Do not equate fewer instructions with necessarily faster execution. Cache hierarchy, pipeline bubbles, and branch predictability dictate real-world latency.\n\n");

        out
    }
}
