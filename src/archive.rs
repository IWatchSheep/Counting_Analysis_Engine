//! # Archive Framework & Interpretation Knowledge Base
//!
//! Provides the foundational data contracts for the two archive tracks:
//! 1. **Optimization Archive:** Records attempted code transformations, verification status,
//!    and before-and-after performance comparisons.
//! 2. **Interpretation Archive:** Records the engine's hypotheses regarding what assembly
//!    patterns count, whether those hypotheses were correct, false positives, or unresolved,
//!    and the lessons learned.

/// Status of an attempted code optimization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptimizationVerdict {
    /// Transformation proven mathematically equivalent and yields measurable improvement.
    Accepted,
    /// Transformation rejected due to behavior alteration or lack of improvement.
    Rejected { reason: String },
    /// Transformation awaiting formal equivalence verification.
    PendingVerification,
}

/// An entry in the Optimization Archive.
#[derive(Debug, Clone)]
pub struct OptimizationArchiveEntry {
    pub experiment_id: String,
    pub target_routine: String,
    pub original_algorithm_name: String,
    pub refactored_algorithm_name: String,
    pub verdict: OptimizationVerdict,
    pub verification_notes: String,
}

/// Verdict regarding the engine's interpretation of an assembly pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpretationVerdict {
    /// The analyzer correctly identified a genuine semantic counter or accumulator.
    CorrectClassification,
    /// The analyzer successfully rejected or avoided misclassifying non-counting operations (e.g. pointer math).
    FalsePositiveAvoided { reason: String },
    /// The analyzer misclassified non-counting operations as a count.
    IncorrectClassification { actual_meaning: String },
    /// Pattern purpose cannot be conclusively proven from static local context alone.
    UnresolvedHypothesis { explanation: String },
}

impl InterpretationVerdict {
    pub fn badge(&self) -> &'static str {
        match self {
            Self::CorrectClassification => "CORRECT CLASSIFICATION",
            Self::FalsePositiveAvoided { .. } => "FALSE POSITIVE AVOIDED",
            Self::IncorrectClassification { .. } => "INCORRECT CLASSIFICATION",
            Self::UnresolvedHypothesis { .. } => "UNRESOLVED HYPOTHESIS",
        }
    }
}

/// An entry in the Interpretation Archive.
#[derive(Debug, Clone)]
pub struct InterpretationArchiveEntry {
    pub experiment_id: String,
    pub inspected_symbol: String,
    pub assembly_pattern: String,
    pub analyzer_hypothesis: String,
    pub verdict: InterpretationVerdict,
    pub lesson: String,
}

/// In-memory repository of the Interpretation Archive.
#[derive(Debug, Clone, Default)]
pub struct InterpretationArchive {
    pub entries: Vec<InterpretationArchiveEntry>,
}

impl InterpretationArchive {
    /// Create a new empty interpretation archive.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Add an entry to the archive.
    pub fn record(&mut self, entry: InterpretationArchiveEntry) {
        self.entries.push(entry);
    }

    /// Populate the initial archive with ground-truth findings from CAE-1A and CAE-1B.
    pub fn populate_cae1b_findings() -> Self {
        let mut archive = Self::new();

        archive.record(InterpretationArchiveEntry {
            experiment_id: "CAE-1B-001".to_string(),
            inspected_symbol: "popcount_naive (RAX/EAX)".to_string(),
            assembly_pattern: "ADD EAX, 1 inside loop [header..backedge] guarded by bit test".to_string(),
            analyzer_hypothesis: "ResultAccumulator (Entity count of set bits)".to_string(),
            verdict: InterpretationVerdict::CorrectClassification,
            lesson: "Conditional increment of RAX in a loop with bit-shift dataflow represents a filtered entity counter.".to_string(),
        });

        archive.record(InterpretationArchiveEntry {
            experiment_id: "CAE-1B-002".to_string(),
            inspected_symbol: "popcount_naive (RCX/ECX)".to_string(),
            assembly_pattern: "INC ECX followed by CMP ECX, 64".to_string(),
            analyzer_hypothesis: "LoopTripCounter (Induction variable counting loop passes)".to_string(),
            verdict: InterpretationVerdict::CorrectClassification,
            lesson: "Register compared against fixed constant bound (64) controlling backward jump is a loop trip counter, not a result counter.".to_string(),
        });

        archive.record(InterpretationArchiveEntry {
            experiment_id: "CAE-1B-003".to_string(),
            inspected_symbol: "popcount_kernighan (RAX/EAX)".to_string(),
            assembly_pattern: "ADD EAX, 1 inside while (n != 0) loop".to_string(),
            analyzer_hypothesis: "ResultAccumulator (Entity count of cleared bits)".to_string(),
            verdict: InterpretationVerdict::CorrectClassification,
            lesson: "Unconditional increment within a loop terminated by state depletion (n == 0) counts state transitions.".to_string(),
        });

        archive.record(InterpretationArchiveEntry {
            experiment_id: "CAE-1B-004".to_string(),
            inspected_symbol: "popcount_kernighan (RDX/n)".to_string(),
            assembly_pattern: "LEA RDX, [RAX - 1] followed by AND RAX, RDX".to_string(),
            analyzer_hypothesis: "StateVariable (Bit-clearing state mutation, not scalar counter)".to_string(),
            verdict: InterpretationVerdict::CorrectClassification,
            lesson: "Subtractive AND sequence `n & (n - 1)` modifies loop state; neither operand is an entity counter.".to_string(),
        });

        archive.record(InterpretationArchiveEntry {
            experiment_id: "CAE-1B-005".to_string(),
            inspected_symbol: "synthetic_pointer_stride (RDI)".to_string(),
            assembly_pattern: "LEA RDI, [RDI + 8] followed by MOV RAX, [RDI]".to_string(),
            analyzer_hypothesis: "AddressStride (Advances memory buffer pointer, NOT an entity count)".to_string(),
            verdict: InterpretationVerdict::FalsePositiveAvoided {
                reason: "Subsequent memory dereference [RDI] confirms address stride role".to_string(),
            },
            lesson: "Arithmetic additions on registers subsequently dereferenced as memory base pointers must not be classified as entity counters.".to_string(),
        });

        archive.record(InterpretationArchiveEntry {
            experiment_id: "CAE-1B-006".to_string(),
            inspected_symbol: "popcount_reference (count_ones)".to_string(),
            assembly_pattern: "POPCNT EAX, RCX (single hardware instruction)".to_string(),
            analyzer_hypothesis: "HardwareSpecialized (Dedicated hardware execution, 0 loops)".to_string(),
            verdict: InterpretationVerdict::CorrectClassification,
            lesson: "Dedicated hardware instructions eliminate iterative induction variables and loop state entirely.".to_string(),
        });

        archive
    }

    /// Render human-readable Markdown table of the archive.
    pub fn render_markdown_table(&self) -> String {
        let mut out = String::new();
        out.push_str("| Experiment | Inspected Symbol | Assembly Pattern | Analyzer Hypothesis | Verdict | Lesson Learned |\n");
        out.push_str("| :--- | :--- | :--- | :--- | :---: | :--- |\n");

        for entry in &self.entries {
            out.push_str(&format!(
                "| **{}** | `{}` | `{}` | {} | **{}** | {} |\n",
                entry.experiment_id,
                entry.inspected_symbol,
                entry.assembly_pattern,
                entry.analyzer_hypothesis,
                entry.verdict.badge(),
                entry.lesson
            ));
        }

        out
    }
}
