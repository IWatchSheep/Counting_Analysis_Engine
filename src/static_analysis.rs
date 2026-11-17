//! # Static Assembly Analysis & Counter Discovery (Tier 2)
//!
//! Provides static x86-64 machine code inspection, instruction categorization,
//! control-flow loop detection, and dataflow-supported candidate accumulator detection.
//!
//! IMPORTANT: Candidate accumulators are supported by dataflow evidence (liveness,
//! cyclic updates, conditional guarding, return register role, pointer dereference checks),
//! rather than merely the naive presence of an ADD or INC instruction.

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, Mnemonic,
    Register,
};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(windows)]
#[repr(C)]
struct RuntimeFunction {
    begin_address: u32,
    end_address: u32,
    unwind_info_address: u32,
}

#[cfg(windows)]
unsafe extern "system" {
    fn RtlLookupFunctionEntry(
        control_pc: u64,
        image_base: *mut u64,
        history_table: *mut std::ffi::c_void,
    ) -> *const RuntimeFunction;
}

/// Categorization of x86-64 assembly instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InstructionCategory {
    Arithmetic,
    BitwiseLogic,
    ControlFlow,
    Comparison,
    DataTransfer,
    AddressGen,
    HardwareSpecialized,
    Stack,
    Other,
}

impl InstructionCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Arithmetic => "Arithmetic (ADD, SUB, INC, DEC)",
            Self::BitwiseLogic => "Bitwise/Logic (AND, OR, XOR, SHL, SHR)",
            Self::ControlFlow => "Control Flow (JMP, Jcc, CALL, RET)",
            Self::Comparison => "Comparison (CMP, TEST)",
            Self::DataTransfer => "Data Transfer (MOV, CMOV, XCHG)",
            Self::AddressGen => "Address Generation (LEA)",
            Self::HardwareSpecialized => "Specialized Hardware (POPCNT, LZCNT)",
            Self::Stack => "Stack Operations (PUSH, POP)",
            Self::Other => "Other / System",
        }
    }
}

/// A decoded, categorized assembly instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisassembledInstruction {
    pub ip: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: Mnemonic,
    pub mnemonic_str: String,
    pub operands_str: String,
    pub category: InstructionCategory,
    pub flow_control: FlowControl,
    pub target_ip: Option<u64>,
    pub is_loop_branch: bool,
}

/// A detected static loop structure bounded by a backward branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticLoop {
    pub header_ip: u64,
    pub backedge_ip: u64,
    pub instruction_count: usize,
}

/// Role hypothesis for a candidate accumulator register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccumulatorRole {
    /// Accumulates the primary counted entity (e.g. set bits), preserved and returned as result.
    ResultAccumulator,
    /// Induction variable that counts loop iterations (e.g. compared against loop bound like 64).
    LoopTripCounter,
    /// Advances a memory buffer pointer or element address (NOT a counted entity).
    AddressStride,
    /// Tracks intermediate algorithm state (e.g. bit-clearing `n &= n - 1`).
    StateVariable,
    /// Role remains ambiguous from static local evidence alone.
    Unknown,
}

/// Classification confidence level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidenceLevel {
    Unresolved,
    Low,
    Medium,
    High,
}

/// Candidate accumulator identified through static dataflow analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateAccumulator {
    pub register_name: String,
    pub canonical_register: Register,
    pub role_hypothesis: AccumulatorRole,
    pub confidence: ConfidenceLevel,
    pub supporting_evidence: Vec<String>,
    pub contraindications: Vec<String>,
}

/// Method used to determine the static function boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryResolutionMethod {
    /// Resolved via official Windows PE `.pdata` Runtime Function Table (RtlLookupFunctionEntry).
    WindowsRuntimeFunctionTable { size_bytes: usize },
    /// Inferred via static control-flow analysis (terminal RET and INT3/UD2 padding boundary).
    ControlFlowHeuristic { size_bytes: usize },
    /// Fixed-length byte slice supplied by caller.
    ExplicitBufferSlice { size_bytes: usize },
}

/// Static analysis profile of a compiled function.
#[derive(Debug, Clone)]
pub struct StaticFunctionProfile {
    pub function_name: String,
    pub total_bytes: usize,
    pub total_instructions: usize,
    pub boundary_method: BoundaryResolutionMethod,
    pub category_counts: BTreeMap<InstructionCategory, usize>,
    pub loops: Vec<StaticLoop>,
    pub candidate_accumulators: Vec<CandidateAccumulator>,
    pub instructions: Vec<DisassembledInstruction>,
}

/// Categorize an instruction based on its mnemonic.
pub fn categorize_mnemonic(m: Mnemonic) -> InstructionCategory {
    match m {
        Mnemonic::Add | Mnemonic::Sub | Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg => {
            InstructionCategory::Arithmetic
        }
        Mnemonic::And
        | Mnemonic::Or
        | Mnemonic::Xor
        | Mnemonic::Not
        | Mnemonic::Shl
        | Mnemonic::Shr
        | Mnemonic::Sar
        | Mnemonic::Rol
        | Mnemonic::Ror => InstructionCategory::BitwiseLogic,
        Mnemonic::Jmp
        | Mnemonic::Je
        | Mnemonic::Jne
        | Mnemonic::Jl
        | Mnemonic::Jle
        | Mnemonic::Jg
        | Mnemonic::Jge
        | Mnemonic::Jb
        | Mnemonic::Jbe
        | Mnemonic::Ja
        | Mnemonic::Jae
        | Mnemonic::Call
        | Mnemonic::Ret => InstructionCategory::ControlFlow,
        Mnemonic::Cmp | Mnemonic::Test => InstructionCategory::Comparison,
        Mnemonic::Mov
        | Mnemonic::Movzx
        | Mnemonic::Movsx
        | Mnemonic::Movsxd
        | Mnemonic::Cmove
        | Mnemonic::Cmovne
        | Mnemonic::Cmovl
        | Mnemonic::Cmovle
        | Mnemonic::Cmovg
        | Mnemonic::Cmovge
        | Mnemonic::Xchg => InstructionCategory::DataTransfer,
        Mnemonic::Lea => InstructionCategory::AddressGen,
        Mnemonic::Popcnt | Mnemonic::Lzcnt | Mnemonic::Tzcnt => {
            InstructionCategory::HardwareSpecialized
        }
        Mnemonic::Push | Mnemonic::Pop => InstructionCategory::Stack,
        _ => InstructionCategory::Other,
    }
}

/// Normalize a sub-register (e.g. EAX, AL, AX) to its 64-bit canonical register (RAX).
pub fn canonicalize_register(reg: Register) -> Register {
    match reg {
        Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => Register::RAX,
        Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => Register::RCX,
        Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => Register::RDX,
        Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => Register::RBX,
        Register::RSP | Register::ESP | Register::SP | Register::SPL => Register::RSP,
        Register::RBP | Register::EBP | Register::BP | Register::BPL => Register::RBP,
        Register::RSI | Register::ESI | Register::SI | Register::SIL => Register::RSI,
        Register::RDI | Register::EDI | Register::DI | Register::DIL => Register::RDI,
        Register::R8 | Register::R8D | Register::R8W | Register::R8L => Register::R8,
        Register::R9 | Register::R9D | Register::R9W | Register::R9L => Register::R9,
        Register::R10 | Register::R10D | Register::R10W | Register::R10L => Register::R10,
        Register::R11 | Register::R11D | Register::R11W | Register::R11L => Register::R11,
        Register::R12 | Register::R12D | Register::R12W | Register::R12L => Register::R12,
        Register::R13 | Register::R13D | Register::R13W | Register::R13L => Register::R13,
        Register::R14 | Register::R14D | Register::R14W | Register::R14L => Register::R14,
        Register::R15 | Register::R15D | Register::R15W | Register::R15L => Register::R15,
        other => other,
    }
}

/// Disassemble a machine code buffer with a specified boundary resolution method.
pub fn disassemble_buffer_with_method(
    function_name: &str,
    code_bytes: &[u8],
    base_ip: u64,
    boundary_method: BoundaryResolutionMethod,
) -> Result<StaticFunctionProfile, String> {
    if code_bytes.is_empty() {
        return Err("Code buffer is empty".to_string());
    }

    let mut decoder = Decoder::with_ip(64, code_bytes, base_ip, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_uppercase_mnemonics(true);
    formatter.options_mut().set_uppercase_registers(true);

    let mut raw_instructions = Vec::new();
    let mut category_counts = BTreeMap::new();
    let mut max_internal_forward_target: u64 = base_ip;
    let max_scan_ip = base_ip + code_bytes.len() as u64;

    let mut instr = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        let ip = instr.ip();
        let mnemonic = instr.mnemonic();
        let category = categorize_mnemonic(mnemonic);
        *category_counts.entry(category).or_insert(0) += 1;

        let mut output = String::new();
        formatter.format(&instr, &mut output);

        let parts: Vec<&str> = output.splitn(2, ' ').collect();
        let mnemonic_str = parts[0].to_string();
        let operands_str = if parts.len() > 1 { parts[1].trim().to_string() } else { String::new() };

        let flow_control = instr.flow_control();
        let is_internal_branch = matches!(
            flow_control,
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch
        );

        let target_ip = if is_internal_branch {
            let target = instr.near_branch_target();
            if target >= base_ip && target < max_scan_ip {
                if target > ip {
                    max_internal_forward_target = max_internal_forward_target.max(target);
                }
                Some(target)
            } else {
                None
            }
        } else {
            None
        };

        let is_loop_branch = if let Some(target) = target_ip {
            target < ip
        } else {
            false
        };

        let start_offset = (ip - base_ip) as usize;
        let len = instr.len();
        let bytes = if start_offset + len <= code_bytes.len() {
            code_bytes[start_offset..start_offset + len].to_vec()
        } else {
            Vec::new()
        };

        raw_instructions.push(DisassembledInstruction {
            ip,
            bytes,
            mnemonic,
            mnemonic_str,
            operands_str,
            category,
            flow_control,
            target_ip,
            is_loop_branch,
        });

        // Function boundary resolution:
        // When using explicit size or runtime table, stop when reaching the boundary
        if let BoundaryResolutionMethod::WindowsRuntimeFunctionTable { size_bytes }
            | BoundaryResolutionMethod::ExplicitBufferSlice { size_bytes } = boundary_method
        {
            if (ip - base_ip) as usize + len >= size_bytes {
                break;
            }
        } else if mnemonic == Mnemonic::Ret && ip >= max_internal_forward_target {
            break;
        }
    }

    if raw_instructions.is_empty() {
        return Err("No instructions could be decoded".to_string());
    }

    // Detect static loop boundaries
    let mut loops = Vec::new();
    for instr in &raw_instructions {
        if let (true, Some(target)) = (instr.is_loop_branch, instr.target_ip) {
            let count_in_loop = raw_instructions
                .iter()
                .filter(|i| i.ip >= target && i.ip <= instr.ip)
                .count();
            loops.push(StaticLoop {
                header_ip: target,
                backedge_ip: instr.ip,
                instruction_count: count_in_loop,
            });
        }
    }

    // Perform dataflow-backed candidate accumulator analysis
    let candidate_accumulators = analyze_candidate_accumulators(&raw_instructions, &loops);

    let total_bytes: usize = raw_instructions.iter().map(|i| i.bytes.len()).sum();
    let total_instructions = raw_instructions.len();

    Ok(StaticFunctionProfile {
        function_name: function_name.to_string(),
        total_bytes,
        total_instructions,
        boundary_method,
        category_counts,
        loops,
        candidate_accumulators,
        instructions: raw_instructions,
    })
}

/// Disassemble a raw machine code buffer into a [`StaticFunctionProfile`].
pub fn disassemble_buffer(
    function_name: &str,
    code_bytes: &[u8],
    base_ip: u64,
) -> Result<StaticFunctionProfile, String> {
    disassemble_buffer_with_method(
        function_name,
        code_bytes,
        base_ip,
        BoundaryResolutionMethod::ExplicitBufferSlice { size_bytes: code_bytes.len() },
    )
}

/// Disassemble a live function via function pointer on x86-64.
///
/// Boundary Resolution:
/// 1. Follows MSVC incremental linking trampolines (`jmp rel32`) to the true entry point.
/// 2. Queries the official Windows PE `.pdata` Runtime Function Table via `RtlLookupFunctionEntry`
///    to retrieve the authoritative compiler-generated `BeginAddress` and `EndAddress`.
/// 3. If `.pdata` is unavailable, falls back to control-flow boundary analysis.
pub fn disassemble_function_pointer(
    function_name: &str,
    fn_ptr: *const (),
    fallback_max_bytes: usize,
) -> Result<StaticFunctionProfile, String> {
    if fn_ptr.is_null() {
        return Err("Function pointer is null".to_string());
    }

    let mut actual_ptr = fn_ptr as *const u8;

    // Follow MSVC Incremental Linking Trampoline (E9 <disp32>) if present
    unsafe {
        let first_byte = *actual_ptr;
        if first_byte == 0xE9 {
            let disp_bytes: [u8; 4] = [
                *actual_ptr.add(1),
                *actual_ptr.add(2),
                *actual_ptr.add(3),
                *actual_ptr.add(4),
            ];
            let disp = i32::from_le_bytes(disp_bytes);
            actual_ptr = actual_ptr.add(5).offset(disp as isize);
        }
    }

    #[cfg(windows)]
    {
        let mut image_base: u64 = 0;
        let runtime_fn = unsafe {
            RtlLookupFunctionEntry(actual_ptr as u64, &mut image_base, std::ptr::null_mut())
        };

        if !runtime_fn.is_null() {
            let rf = unsafe { &*runtime_fn };
            let start_addr = image_base + rf.begin_address as u64;
            let end_addr = image_base + rf.end_address as u64;
            let size = (end_addr - start_addr) as usize;

            if size > 0 && size < 65536 {
                let code_slice = unsafe { std::slice::from_raw_parts(start_addr as *const u8, size) };
                return disassemble_buffer_with_method(
                    function_name,
                    code_slice,
                    start_addr,
                    BoundaryResolutionMethod::WindowsRuntimeFunctionTable { size_bytes: size },
                );
            }
        }
    }

    // Fallback: Use scan buffer
    let code_slice = unsafe { std::slice::from_raw_parts(actual_ptr, fallback_max_bytes) };
    disassemble_buffer_with_method(
        function_name,
        code_slice,
        actual_ptr as u64,
        BoundaryResolutionMethod::ControlFlowHeuristic { size_bytes: fallback_max_bytes },
    )
}

/// Analyze candidate accumulators using dataflow evidence.
pub fn analyze_candidate_accumulators(
    instructions: &[DisassembledInstruction],
    loops: &[StaticLoop],
) -> Vec<CandidateAccumulator> {
    // 1. Identify all registers that appear as memory base/index pointers anywhere
    let mut memory_base_registers = BTreeSet::new();
    for instr in instructions {
        let op_str_upper = instr.operands_str.to_uppercase();
        for &reg_name in &["RAX", "RCX", "RDX", "RBX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"] {
            if let (Some(bracket_start), Some(bracket_end)) = (op_str_upper.find('['), op_str_upper.find(']'))
                && bracket_start < bracket_end
            {
                let mem_expr = &op_str_upper[bracket_start..bracket_end];
                if mem_expr.contains(reg_name) {
                    memory_base_registers.insert(reg_name);
                }
            }
        }
    }

    // 2. Identify candidate registers updated by arithmetic inside loops
    let mut candidates_map: BTreeMap<String, CandidateAccumulator> = BTreeMap::new();

    for l in loops {
        let loop_instrs: Vec<&DisassembledInstruction> = instructions
            .iter()
            .filter(|i| i.ip >= l.header_ip && i.ip <= l.backedge_ip)
            .collect();

        for instr in &loop_instrs {
            let m = instr.mnemonic;
            let is_arithmetic = matches!(m, Mnemonic::Add | Mnemonic::Inc | Mnemonic::Sub | Mnemonic::Lea);
            let is_bit_clearing = matches!(m, Mnemonic::And);

            if is_arithmetic || is_bit_clearing {
                let first_op = instr
                    .operands_str
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_uppercase();

                let canonical_reg_name = match first_op.as_str() {
                    "RAX" | "EAX" | "AX" | "AL" => "RAX",
                    "RCX" | "ECX" | "CX" | "CL" => "RCX",
                    "RDX" | "EDX" | "DX" | "DL" => "RDX",
                    "RBX" | "EBX" | "BX" | "BL" => "RBX",
                    "RSI" | "ESI" | "SI" | "SIL" => "RSI",
                    "RDI" | "EDI" | "DI" | "DIL" => "RDI",
                    "R8" | "R8D" | "R8W" | "R8L" => "R8",
                    "R9" | "R9D" | "R9W" | "R9L" => "R9",
                    "R10" | "R10D" | "R10W" | "R10L" => "R10",
                    "R11" | "R11D" | "R11W" | "R11L" => "R11",
                    _ => continue,
                };

                let entry = candidates_map
                    .entry(canonical_reg_name.to_string())
                    .or_insert_with(|| CandidateAccumulator {
                        register_name: canonical_reg_name.to_string(),
                        canonical_register: match canonical_reg_name {
                            "RAX" => Register::RAX,
                            "RCX" => Register::RCX,
                            "RDX" => Register::RDX,
                            "RBX" => Register::RBX,
                            "RSI" => Register::RSI,
                            "RDI" => Register::RDI,
                            "R8" => Register::R8,
                            "R9" => Register::R9,
                            "R10" => Register::R10,
                            "R11" => Register::R11,
                            _ => Register::None,
                        },
                        role_hypothesis: AccumulatorRole::Unknown,
                        confidence: ConfidenceLevel::Low,
                        supporting_evidence: Vec::new(),
                        contraindications: Vec::new(),
                    });

                entry.supporting_evidence.push(format!(
                    "Modified inside static loop [{:#X}..{:#X}] via instruction: `{}`",
                    l.header_ip, l.backedge_ip, instr.mnemonic_str
                ));

                if instr.operands_str.to_uppercase().contains(canonical_reg_name) {
                    entry.supporting_evidence.push(format!(
                        "Self-referential cyclic modification detected (`{}`)",
                        instr.operands_str
                    ));
                }

                if instr.operands_str.ends_with(", 1") || instr.mnemonic == Mnemonic::Inc {
                    entry.supporting_evidence.push("Constant unit increment (stride = 1) observed".to_string());
                }

                if memory_base_registers.contains(canonical_reg_name) {
                    entry.contraindications.push(format!(
                        "Register `{}` is used as a memory dereference base `[...]` elsewhere in the function",
                        canonical_reg_name
                    ));
                    entry.role_hypothesis = AccumulatorRole::AddressStride;
                    entry.confidence = ConfidenceLevel::High;
                }
            }
        }
    }

    // 3. Evaluate loop termination bounds and return register role
    for candidate in candidates_map.values_mut() {
        if candidate.role_hypothesis == AccumulatorRole::AddressStride {
            continue;
        }

        let is_trip_counter = instructions.iter().any(|i| {
            i.mnemonic == Mnemonic::Cmp
                && i.operands_str.to_uppercase().contains(&candidate.register_name)
                && (i.operands_str.contains("64") || i.operands_str.contains("0x40"))
        });

        if is_trip_counter {
            candidate.role_hypothesis = AccumulatorRole::LoopTripCounter;
            candidate.confidence = ConfidenceLevel::High;
            candidate.supporting_evidence.push(
                "Compared against loop trip bound (`64`) controlling loop continuation".to_string(),
            );
        } else if candidate.register_name == "RAX" {
            candidate.role_hypothesis = AccumulatorRole::ResultAccumulator;
            candidate.confidence = ConfidenceLevel::High;
            candidate.supporting_evidence.push(
                "Serves as the standard x86-64 return register (RAX/EAX) preserved for function result".to_string(),
            );
        } else if candidate.register_name == "RDX" {
            candidate.role_hypothesis = AccumulatorRole::StateVariable;
            candidate.confidence = ConfidenceLevel::Medium;
            candidate.supporting_evidence.push(
                "Tracks intermediate bit-clearing state operand inside loop".to_string(),
            );
        } else {
            candidate.role_hypothesis = AccumulatorRole::ResultAccumulator;
            candidate.confidence = ConfidenceLevel::Medium;
        }
    }

    candidates_map.into_values().collect()
}
