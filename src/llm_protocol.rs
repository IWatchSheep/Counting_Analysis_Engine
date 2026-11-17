//! # CAE-1E: Experimental Protocol and Prediction Archive
//!
//! Provides the foundational scientific recording protocol for evaluating
//! predictions about compiled x86-64 machine-code execution.
//!
//! ## Scientific Principles
//! 1. **Hypothesis Freezing**: Predictions must be immutably registered and hashed
//!    before verification evidence is collected or disclosed.
//! 2. **Canonical Provenance**: Links every hypothesis to the exact disassembly input,
//!    target executable hash, compiler profile, and measurement boundaries.
//! 3. **Non-Binary Classification**: Distinguishes verified models, semantic failures,
//!    architectural assumption mismatches, post-hoc rationalizations, and unresolved discrepancies.
//! 4. **Preregistration Limitation**: Local timestamps and cryptographic digests
//!    guarantee tamper-evident immutability relative to the hash, but do not
//!    independently prove external third-party ordering without an independent ledger.
//! 5. **Lifecycle vs. Scientific Verdict**: The lifecycle state `Verified` denotes that
//!    the verification execution phase has finished and evidence is linked; it does NOT
//!    indicate that the prediction was scientifically correct. Correctness is recorded in
//!    `ScientificVerdict`.

use std::fmt;

/// Cryptographic SHA-256 implementation in standard Rust (FIPS 180-4 compliant).
pub fn compute_sha256(input: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = input.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    #[allow(clippy::chunks_exact_to_as_chunks)]
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_var = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_var.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_var = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_var);
    }

    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
    )
}

/// Experiment classification distinguishing known calibration tests from blind evaluations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExperimentClassification {
    /// Known-answer calibration testbed used to validate recording and scoring tooling.
    Calibration,
    /// Previously unseen testbed where ground-truth execution answers are withheld.
    Blind,
}

impl fmt::Display for ExperimentClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Calibration => write!(f, "Calibration"),
            Self::Blind => write!(f, "Blind"),
        }
    }
}

/// Measurement boundary definitions ensuring standardized instruction and branch accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasurementBoundaries {
    pub entry_delimiter: String,
    pub exit_delimiter: String,
    pub call_ret_accounting: String,
}

/// Predetermined scoring rules governing evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoringRules {
    pub exact_instruction_match_required: bool,
    pub branch_breakdown_scored: bool,
    pub allow_unresolved_investigation: bool,
    pub scoring_criteria_description: String,
}

/// Structured definition of a machine-code interpretation experiment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExperimentDefinition {
    pub experiment_id: String,
    pub target_kernel_name: String,
    pub compiler_profile: String,
    pub classification: ExperimentClassification,
    pub target_executable_name: String,
    pub target_executable_sha256: Option<String>,
    pub disassembly_input: String,
    pub permitted_information: Vec<String>,
    pub measurement_boundaries: MeasurementBoundaries,
    pub expected_response_schema: String,
    pub scoring_rules: ScoringRules,
}

impl ExperimentDefinition {
    /// Populate the 6 standard calibration experiments based on CAE-1D popcount kernels.
    pub fn populate_standard_calibration_experiments() -> Vec<Self> {
        let boundaries = MeasurementBoundaries {
            entry_delimiter: "int 3 immediately preceding function dispatch call rax".to_string(),
            exit_delimiter: "int 3 immediately following ret".to_string(),
            call_ret_accounting: "Function internal steps between call rax and ret, excluding dispatch harness".to_string(),
        };

        let scoring = ScoringRules {
            exact_instruction_match_required: false,
            branch_breakdown_scored: true,
            allow_unresolved_investigation: true,
            scoring_criteria_description: "Matches closed-form instruction count formula and loop backedge topology".to_string(),
        };

        vec![
            Self {
                experiment_id: "CAE-1E-CAL-001".to_string(),
                target_kernel_name: "popcount_naive".to_string(),
                compiler_profile: "Debug".to_string(),
                classification: ExperimentClassification::Calibration,
                target_executable_name: "cae_trace_target.exe".to_string(),
                target_executable_sha256: None,
                disassembly_input: "37 static instructions; Range iterator step helpers inlined/called; 64-step loop.".to_string(),
                permitted_information: vec!["Target: x86_64-pc-windows-msvc".to_string(), "Profile: Debug (dev)".to_string(), "Signature: fn(u64) -> u32".to_string()],
                measurement_boundaries: boundaries.clone(),
                expected_response_schema: "Instruction count scaling model, loop backedge count, accumulator registers".to_string(),
                scoring_rules: scoring.clone(),
            },
            Self {
                experiment_id: "CAE-1E-CAL-002".to_string(),
                target_kernel_name: "popcount_naive".to_string(),
                compiler_profile: "Release".to_string(),
                classification: ExperimentClassification::Calibration,
                target_executable_name: "cae_trace_target.exe".to_string(),
                target_executable_sha256: None,
                disassembly_input: "196 static instructions; fully unrolled straight-line BT/ADC sequences; zero branches.".to_string(),
                permitted_information: vec!["Target: x86_64-pc-windows-msvc".to_string(), "Profile: Release (opt-level 3)".to_string(), "Signature: fn(u64) -> u32".to_string()],
                measurement_boundaries: boundaries.clone(),
                expected_response_schema: "Instruction count scaling model, loop backedge count, accumulator registers".to_string(),
                scoring_rules: scoring.clone(),
            },
            Self {
                experiment_id: "CAE-1E-CAL-003".to_string(),
                target_kernel_name: "popcount_kernighan".to_string(),
                compiler_profile: "Debug".to_string(),
                classification: ExperimentClassification::Calibration,
                target_executable_name: "cae_trace_target.exe".to_string(),
                target_executable_sha256: None,
                disassembly_input: "33 static instructions; stack frame spills; sub/and/add sequence; top-tested loop.".to_string(),
                permitted_information: vec!["Target: x86_64-pc-windows-msvc".to_string(), "Profile: Debug (dev)".to_string(), "Signature: fn(u64) -> u32".to_string()],
                measurement_boundaries: boundaries.clone(),
                expected_response_schema: "Instruction count scaling model, loop backedge count, accumulator registers".to_string(),
                scoring_rules: scoring.clone(),
            },
            Self {
                experiment_id: "CAE-1E-CAL-004".to_string(),
                target_kernel_name: "popcount_kernighan".to_string(),
                compiler_profile: "Release".to_string(),
                classification: ExperimentClassification::Calibration,
                target_executable_name: "cae_trace_target.exe".to_string(),
                target_executable_sha256: None,
                disassembly_input: "10 static instructions; bottom-tested loop; registers RCX/EAX/RDX; no stack spill.".to_string(),
                permitted_information: vec!["Target: x86_64-pc-windows-msvc".to_string(), "Profile: Release (opt-level 3)".to_string(), "Signature: fn(u64) -> u32".to_string()],
                measurement_boundaries: boundaries.clone(),
                expected_response_schema: "Instruction count scaling model, loop backedge count, accumulator registers".to_string(),
                scoring_rules: scoring.clone(),
            },
            Self {
                experiment_id: "CAE-1E-CAL-005".to_string(),
                target_kernel_name: "popcount_reference".to_string(),
                compiler_profile: "Debug".to_string(),
                classification: ExperimentClassification::Calibration,
                target_executable_name: "cae_trace_target.exe".to_string(),
                target_executable_sha256: None,
                disassembly_input: "24 static instructions; software parallel bitwise reduction tree with stack frame.".to_string(),
                permitted_information: vec!["Target: x86_64-pc-windows-msvc (baseline target CPU, popcnt feature disabled)".to_string(), "Profile: Debug (dev)".to_string(), "Signature: fn(u64) -> u32".to_string()],
                measurement_boundaries: boundaries.clone(),
                expected_response_schema: "Instruction count scaling model, loop backedge count, accumulator registers".to_string(),
                scoring_rules: scoring.clone(),
            },
            Self {
                experiment_id: "CAE-1E-CAL-006".to_string(),
                target_kernel_name: "popcount_reference".to_string(),
                compiler_profile: "Release".to_string(),
                classification: ExperimentClassification::Calibration,
                target_executable_name: "cae_trace_target.exe".to_string(),
                target_executable_sha256: None,
                disassembly_input: "20 static instructions; software parallel bitwise reduction tree in registers.".to_string(),
                permitted_information: vec!["Target: x86_64-pc-windows-msvc (baseline target CPU, popcnt feature disabled)".to_string(), "Profile: Release (opt-level 3)".to_string(), "Signature: fn(u64) -> u32".to_string()],
                measurement_boundaries: boundaries,
                expected_response_schema: "Instruction count scaling model, loop backedge count, accumulator registers".to_string(),
                scoring_rules: scoring,
            },
        ]
    }
}

/// Dynamic instruction-count hypothesis models.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstructionCountHypothesis {
    /// Invariant constant dynamic instruction count regardless of input.
    Constant(u64),
    /// Linear scaling: P(k) = intercept + slope * k.
    Linear { intercept: i64, slope: i64 },
    /// Piecewise popcount model: special case for k=0, otherwise linear.
    PiecewisePopcount {
        zero_case: u64,
        non_zero_intercept: i64,
        non_zero_slope: i64,
    },
    /// General piecewise specification.
    PiecewiseGeneral {
        rules: Vec<(String, String)>,
    },
    /// Predictor explicitly notes count cannot be determined from disassembly alone.
    Unknown { reason: String },
    /// Predictor explicitly abstains from predicting instruction count.
    Abstention { reason: String },
}

impl InstructionCountHypothesis {
    /// Evaluate the predicted instruction count for a given Hamming weight k.
    pub fn evaluate_popcount(&self, k: usize) -> Option<u64> {
        match self {
            Self::Constant(c) => Some(*c),
            Self::Linear { intercept, slope } => {
                let count = *intercept + (*slope * k as i64);
                if count >= 0 { Some(count as u64) } else { None }
            }
            Self::PiecewisePopcount { zero_case, non_zero_intercept, non_zero_slope } => {
                if k == 0 {
                    Some(*zero_case)
                } else {
                    let count = *non_zero_intercept + (*non_zero_slope * k as i64);
                    if count >= 0 { Some(count as u64) } else { None }
                }
            }
            Self::PiecewiseGeneral { .. } | Self::Unknown { .. } | Self::Abstention { .. } => None,
        }
    }
}

/// Hypothesized loop and branch structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopBranchHypothesis {
    /// Loop is completely unrolled by the compiler; zero loop backedges.
    Unrolled { explanation: String },
    /// Explicit loop with backedges.
    LoopWithBackedges {
        loop_header_backedges: String,
        backward_join_branches: Option<String>,
    },
    /// Straight-line code with zero loops and zero backward branches.
    StraightLine,
    /// Unknown or cannot be determined.
    Unknown { reason: String },
    /// Explicit abstention.
    Abstention { reason: String },
}

/// Hypothesized register semantic role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRoleHypothesis {
    pub register_name: String,
    pub hypothesized_role: String,
}

/// Structured prediction representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredPrediction {
    pub instruction_count: InstructionCountHypothesis,
    pub loop_branch: LoopBranchHypothesis,
    pub register_roles: Vec<RegisterRoleHypothesis>,
    pub confidence_percent: Option<u8>,
    pub notes_and_rationale: String,
}

/// Prediction record lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredictionState {
    /// Draft prediction under formulation; editable.
    Draft,
    /// Frozen prediction; permanently immutable, canonical hash computed.
    Frozen,
    /// Verification executed against physical evidence (evaluation completed).
    Verified,
    /// Permanently stored in historical archive.
    Archived,
}

impl fmt::Display for PredictionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Draft => write!(f, "Draft"),
            Self::Frozen => write!(f, "Frozen"),
            Self::Verified => write!(f, "Verified (Evaluated)"),
            Self::Archived => write!(f, "Archived"),
        }
    }
}

/// Protocol error for invalid operations or state violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredictionProtocolError {
    FrozenPredictionImmutable { prediction_id: String },
    InvalidStateTransition { from: PredictionState, to: PredictionState },
    MissingRequiredField { field_name: String },
    HashMismatch { expected: String, computed: String },
}

impl fmt::Display for PredictionProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrozenPredictionImmutable { prediction_id } => {
                write!(f, "Prediction '{}' is frozen and immutable", prediction_id)
            }
            Self::InvalidStateTransition { from, to } => {
                write!(f, "Illegal state transition from {} to {}", from, to)
            }
            Self::MissingRequiredField { field_name } => {
                write!(f, "Missing required prediction field: {}", field_name)
            }
            Self::HashMismatch { expected, computed } => {
                write!(f, "Integrity hash mismatch: expected {}, computed {}", expected, computed)
            }
        }
    }
}

impl std::error::Error for PredictionProtocolError {}

/// Full prediction record preserving original response, structured model, and cryptographic digest.
///
/// Fields are encapsulated (private) to enforce that content can only be altered in Draft state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredictionRecord {
    prediction_id: String,
    experiment_id: String,
    model_identifier: String,
    model_configuration: Option<String>,
    original_response_text: String,
    structured_prediction: StructuredPrediction,
    registration_timestamp_iso8601: String,
    state: PredictionState,
    canonical_sha256: String,
}

impl PredictionRecord {
    /// Create a new draft prediction record.
    pub fn new_draft(
        prediction_id: impl Into<String>,
        experiment_id: impl Into<String>,
        model_identifier: impl Into<String>,
        original_response_text: impl Into<String>,
        structured_prediction: StructuredPrediction,
        registration_timestamp_iso8601: impl Into<String>,
    ) -> Self {
        let mut record = Self {
            prediction_id: prediction_id.into(),
            experiment_id: experiment_id.into(),
            model_identifier: model_identifier.into(),
            model_configuration: None,
            original_response_text: original_response_text.into(),
            structured_prediction,
            registration_timestamp_iso8601: registration_timestamp_iso8601.into(),
            state: PredictionState::Draft,
            canonical_sha256: String::new(),
        };
        record.canonical_sha256 = record.compute_canonical_hash();
        record
    }

    // --- Accessor Methods (Getters) ---

    pub fn prediction_id(&self) -> &str {
        &self.prediction_id
    }

    pub fn experiment_id(&self) -> &str {
        &self.experiment_id
    }

    pub fn model_identifier(&self) -> &str {
        &self.model_identifier
    }

    pub fn model_configuration(&self) -> Option<&str> {
        self.model_configuration.as_deref()
    }

    pub fn original_response_text(&self) -> &str {
        &self.original_response_text
    }

    pub fn structured_prediction(&self) -> &StructuredPrediction {
        &self.structured_prediction
    }

    pub fn registration_timestamp_iso8601(&self) -> &str {
        &self.registration_timestamp_iso8601
    }

    pub fn state(&self) -> PredictionState {
        self.state
    }

    pub fn canonical_sha256(&self) -> &str {
        &self.canonical_sha256
    }

    // --- Mutation Methods (Strictly Checked by State) ---

    /// Set optional model configuration (permitted ONLY in Draft state).
    pub fn set_model_configuration(&mut self, config: Option<String>) -> Result<(), PredictionProtocolError> {
        if self.state != PredictionState::Draft {
            return Err(PredictionProtocolError::FrozenPredictionImmutable {
                prediction_id: self.prediction_id.clone(),
            });
        }
        self.model_configuration = config;
        self.canonical_sha256 = self.compute_canonical_hash();
        Ok(())
    }

    /// Update draft content. Permitted ONLY in Draft state.
    pub fn update_draft(
        &mut self,
        new_structured_prediction: StructuredPrediction,
        new_original_text: impl Into<String>,
    ) -> Result<(), PredictionProtocolError> {
        if self.state != PredictionState::Draft {
            return Err(PredictionProtocolError::FrozenPredictionImmutable {
                prediction_id: self.prediction_id.clone(),
            });
        }
        self.structured_prediction = new_structured_prediction;
        self.original_response_text = new_original_text.into();
        self.canonical_sha256 = self.compute_canonical_hash();
        Ok(())
    }

    /// Compute canonical serialization covering EVERY field of the hypothesis.
    pub fn canonical_serialization(&self) -> String {
        let mut s = String::with_capacity(2048);
        s.push_str("prediction_id:");
        s.push_str(&self.prediction_id);
        s.push('\n');

        s.push_str("experiment_id:");
        s.push_str(&self.experiment_id);
        s.push('\n');

        s.push_str("model_identifier:");
        s.push_str(&self.model_identifier);
        s.push('\n');

        s.push_str("model_configuration:");
        if let Some(cfg) = &self.model_configuration {
            s.push_str(cfg);
        } else {
            s.push_str("none");
        }
        s.push('\n');

        s.push_str("registration_timestamp:");
        s.push_str(&self.registration_timestamp_iso8601);
        s.push('\n');

        s.push_str("original_response_sha256:");
        s.push_str(&compute_sha256(self.original_response_text.as_bytes()));
        s.push('\n');

        // Instruction count hypothesis serialization
        s.push_str("instruction_count:");
        match &self.structured_prediction.instruction_count {
            InstructionCountHypothesis::Constant(c) => s.push_str(&format!("constant={}", c)),
            InstructionCountHypothesis::Linear { intercept, slope } => {
                s.push_str(&format!("linear:intercept={},slope={}", intercept, slope))
            }
            InstructionCountHypothesis::PiecewisePopcount { zero_case, non_zero_intercept, non_zero_slope } => {
                s.push_str(&format!("piecewise_popcount:k0={},intercept={},slope={}", zero_case, non_zero_intercept, non_zero_slope))
            }
            InstructionCountHypothesis::PiecewiseGeneral { rules } => {
                s.push_str("piecewise_general:");
                for (cond, form) in rules {
                    s.push_str(&format!("[{} => {}];", cond, form));
                }
            }
            InstructionCountHypothesis::Unknown { reason } => s.push_str(&format!("unknown={}", reason)),
            InstructionCountHypothesis::Abstention { reason } => s.push_str(&format!("abstention={}", reason)),
        }
        s.push('\n');

        // Loop and branch hypothesis serialization
        s.push_str("loop_branch:");
        match &self.structured_prediction.loop_branch {
            LoopBranchHypothesis::Unrolled { explanation } => s.push_str(&format!("unrolled:{}", explanation)),
            LoopBranchHypothesis::LoopWithBackedges { loop_header_backedges, backward_join_branches } => {
                s.push_str(&format!(
                    "backedges:header={},join={}",
                    loop_header_backedges,
                    backward_join_branches.as_deref().unwrap_or("none")
                ))
            }
            LoopBranchHypothesis::StraightLine => s.push_str("straight_line"),
            LoopBranchHypothesis::Unknown { reason } => s.push_str(&format!("unknown:{}", reason)),
            LoopBranchHypothesis::Abstention { reason } => s.push_str(&format!("abstention:{}", reason)),
        }
        s.push('\n');

        // Register roles serialization
        s.push_str("register_roles:");
        for role in &self.structured_prediction.register_roles {
            s.push_str(&format!("[{}={}]", role.register_name, role.hypothesized_role));
        }
        s.push('\n');

        // Confidence serialization
        s.push_str("confidence:");
        if let Some(conf) = self.structured_prediction.confidence_percent {
            s.push_str(&conf.to_string());
        } else {
            s.push_str("none");
        }
        s.push('\n');

        // Notes and rationale serialization
        s.push_str("notes_and_rationale:");
        s.push_str(&self.structured_prediction.notes_and_rationale);
        s.push('\n');

        s
    }

    /// Compute deterministic SHA-256 over canonical serialization.
    pub fn compute_canonical_hash(&self) -> String {
        compute_sha256(self.canonical_serialization().as_bytes())
    }

    /// Transition prediction from Draft to Frozen. Locks content immutably.
    pub fn freeze(&mut self) -> Result<(), PredictionProtocolError> {
        if self.state != PredictionState::Draft {
            return Err(PredictionProtocolError::InvalidStateTransition {
                from: self.state,
                to: PredictionState::Frozen,
            });
        }
        self.canonical_sha256 = self.compute_canonical_hash();
        self.state = PredictionState::Frozen;
        Ok(())
    }

    /// Mark prediction verified (evaluation completed against physical evidence).
    ///
    /// NOTE: This marks that the evaluation phase has been executed and evidence linked.
    /// It does NOT mean the prediction was correct; scientific truth is recorded in `ScientificVerdict`.
    pub fn mark_verified(&mut self) -> Result<(), PredictionProtocolError> {
        if self.state != PredictionState::Frozen {
            return Err(PredictionProtocolError::InvalidStateTransition {
                from: self.state,
                to: PredictionState::Verified,
            });
        }
        self.state = PredictionState::Verified;
        Ok(())
    }

    /// Archive prediction permanently.
    pub fn archive(&mut self) -> Result<(), PredictionProtocolError> {
        if self.state != PredictionState::Verified {
            return Err(PredictionProtocolError::InvalidStateTransition {
                from: self.state,
                to: PredictionState::Archived,
            });
        }
        self.state = PredictionState::Archived;
        Ok(())
    }

    /// Verify that current content strictly matches the locked canonical hash.
    pub fn verify_integrity(&self) -> bool {
        self.canonical_sha256 == self.compute_canonical_hash()
    }
}

/// Provenance of physical execution evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTraceEvidence {
    pub target_executable_name: String,
    pub target_executable_sha256: Option<String>,
    pub compiler_profile: String,
    pub test_inputs_evaluated: Vec<u64>,
    pub observed_instruction_counts: Vec<(u64, u64)>,
    pub loop_header_backedges_observed: Option<u64>,
    pub total_backward_branches_observed: Option<u64>,
    pub key_register_states_observed: Vec<String>,
    pub trace_artifact_reference: String,
}

/// Scientific classification categories for evaluated predictions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScientificVerdict {
    /// Prediction matched physical hardware trace across all tested domains.
    VerifiedPrediction,
    /// Plausible source-level explanation contradicted by compiler-generated machine code.
    PlausibleSemanticFailure,
    /// Assumed architectural features not present in compiler output.
    FeatureAssumptionMismatch,
    /// Modifying hypotheses to fit observed counts after evidence disclosure.
    PostHocRationalization,
    /// Discrepancy observed but root cause not yet established; avoids premature error assignment.
    UnresolvedDiscrepancy,
    /// Cannot be evaluated (e.g. predictor abstained, insufficient disassembly).
    UnsupportedEvaluation,
}

impl fmt::Display for ScientificVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerifiedPrediction => write!(f, "VerifiedPrediction"),
            Self::PlausibleSemanticFailure => write!(f, "PlausibleSemanticFailure"),
            Self::FeatureAssumptionMismatch => write!(f, "FeatureAssumptionMismatch"),
            Self::PostHocRationalization => write!(f, "PostHocRationalization"),
            Self::UnresolvedDiscrepancy => write!(f, "UnresolvedDiscrepancy"),
            Self::UnsupportedEvaluation => write!(f, "UnsupportedEvaluation"),
        }
    }
}

/// Evidence record linking frozen prediction to physical execution trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub experiment_id: String,
    pub prediction_id: String,
    pub collection_timestamp_iso8601: String,
    pub native_trace: Option<NativeTraceEvidence>,
    pub discrepancy_summary: String,
    pub scientific_verdict: ScientificVerdict,
    pub verdict_explanation: String,
    pub evidence_disclosed_prior_to_prediction: bool,
}
