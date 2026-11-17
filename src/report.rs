//! # Experiment Reporting
//!
//! Generates structured comparison reports that capture correctness verification
//! and source-level operation accounting across all implementations.

use crate::instrumentation::{
    popcount_kernighan_instrumented, popcount_naive_instrumented, popcount_reference_instrumented,
    SourceOperationCounts,
};
use crate::verification::independent_string_oracle;

/// Comparison record for a single input tested across the three implementations.
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

    /// Render human-readable summary table.
    pub fn render_markdown_table(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("### Input: {} ({})\n\n", self.input_hex, self.input_decimal));
        out.push_str(&format!("- **Independent Reference Oracle Count:** `{}`\n", self.oracle_count));
        out.push_str(&format!(
            "- **All Implementations Agree:** {}\n\n",
            if self.verified_correct { "**PASS** (Bit-for-Bit Identical)" } else { "**FAIL**" }
        ));

        out.push_str("| Metric Category | Naive Loop | Kernighan | Reference (`count_ones()`) |\n");
        out.push_str("| :--- | :---: | :---: | :---: |\n");
        out.push_str(&format!("| **Returned Count** | `{}` | `{}` | `{}` |\n", self.naive_count, self.kernighan_count, self.reference_count));
        out.push_str(&format!("| **Source Loop Iterations** | `{}` | `{}` | `{}` |\n", self.naive_ops.loop_iterations, self.kernighan_ops.loop_iterations, self.reference_ops.loop_iterations));
        out.push_str(&format!("| **Counter Updates** | `{}` | `{}` | `{}` |\n", self.naive_ops.counter_updates, self.kernighan_ops.counter_updates, self.reference_ops.counter_updates));
        out.push_str(&format!("| **Condition Evaluations** | `{}` | `{}` | `{}` |\n", self.naive_ops.condition_evaluations, self.kernighan_ops.condition_evaluations, self.reference_ops.condition_evaluations));
        out.push_str(&format!("| **Bitwise ANDs (`&`)** | `{}` | `{}` | `{}` |\n", self.naive_ops.bitwise_ands, self.kernighan_ops.bitwise_ands, self.reference_ops.bitwise_ands));
        out.push_str(&format!("| **Bit Shifts (`>>`)** | `{}` | `{}` | `{}` |\n", self.naive_ops.bit_shifts, self.kernighan_ops.bit_shifts, self.reference_ops.bit_shifts));
        out.push_str(&format!("| **Subtractions (`- 1`)** | `{}` | `{}` | `{}` |\n", self.naive_ops.arithmetic_subtractions, self.kernighan_ops.arithmetic_subtractions, self.reference_ops.arithmetic_subtractions));
        out.push_str(&format!("| **Total Tracked Source Ops** | `{}` | `{}` | `{}` |\n\n", self.naive_ops.total_operations(), self.kernighan_ops.total_operations(), self.reference_ops.total_operations()));

        out.push_str("> [!NOTE]\n");
        out.push_str("> **Measurement Tier Notice (CAE-1A):**\n");
        out.push_str("> The metrics above record high-level *source-code operations*, NOT static assembly instructions or dynamic hardware execution cycles.\n");
        out.push_str("> Static assembly inspection (`iced-x86`) and dynamic instruction retirement are scheduled for CAE-1B and CAE-1C.\n");

        out
    }
}
