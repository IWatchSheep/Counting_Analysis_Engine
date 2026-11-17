//! # Archive Framework Foundations
//!
//! Provides the foundational data contracts for the two archive tracks:
//! 1. **Optimization Archive:** Records attempted code transformations, verification status,
//!    and before-and-after performance comparisons.
//! 2. **Interpretation Archive:** Records the engine's hypotheses regarding what assembly
//!    patterns count, whether those hypotheses were correct, and the lessons learned.
//!
//! Full population of these archives begins in CAE-1B and CAE-1C.

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

/// Verdict regarding the engine's interpretation of a code pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpretationVerdict {
    /// The analyzer correctly identified a genuine semantic counter.
    VerifiedCountingPattern,
    /// The analyzer misclassified non-counting operations (e.g. pointer math) as a count.
    IncorrectClassification { actual_meaning: String },
    /// Pattern purpose cannot be conclusively proven from local context alone.
    AmbiguousPattern { explanation: String },
}

/// An entry in the Interpretation Archive.
#[derive(Debug, Clone)]
pub struct InterpretationArchiveEntry {
    pub experiment_id: String,
    pub inspected_symbol: String,
    pub pattern_description: String,
    pub analyzer_hypothesis: String,
    pub verdict: InterpretationVerdict,
    pub lesson: String,
}
