//! # Machine-Code Instruction Emulation & Tracing (CAE-1D Phase 1)
//!
//! Provides controlled, independent x86-64 machine-code execution and
//! instruction-by-instruction path tracing.
//!
//! ## Architectural Principles
//! 1. **Zero External Native Dependencies:** Implemented in pure Rust using `iced-x86`
//!    for instruction decoding, eliminating unstable native C/C++ build hooks (such as `libclang`).
//! 2. **Explicit Observation:** Every trace step records the exact instruction address,
//!    mnemonic, opcode bytes, and register mutations.
//! 3. **Non-Invasive Execution:** Does not set hardware debug trap flags on live OS threads,
//!    ensuring full compatibility with IDE debuggers (RustRover / LLDB).
//! 4. **Strict Separation:** Tracing records *what* executed. Performance timing records *how fast*.

use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind, Register,
};

/// Snapshot of the 64-bit general-purpose CPU registers and instruction pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuRegisters {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
}

/// Architectural CPU condition flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuFlags {
    pub zf: bool,
    pub cf: bool,
    pub sf: bool,
    pub of: bool,
}

/// Reason for trace termination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationReason {
    /// Returned normally to sentinel return address via RET instruction.
    NormalRet,
    /// Hit the maximum instruction budget (prevents infinite loops).
    BudgetExhausted(usize),
    /// Encountered an instruction opcode not yet implemented in the micro-emulator.
    UnsupportedInstruction(String),
    /// Access to unmapped or invalid virtual memory address.
    MemoryFault(u64),
    /// Invalid instruction byte stream at RIP.
    InvalidOpcode(u64),
}

/// A single step in an observed execution trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmulatedTraceStep {
    pub step_index: usize,
    pub address: u64,
    pub mnemonic: String,
    pub operands_str: String,
    pub bytes: Vec<u8>,
    pub registers_after: CpuRegisters,
}

/// Status of an emulation experiment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmulationStatus {
    CompletedSuccess,
    BudgetExceeded,
    UnsupportedDeferred,
    Faulted,
}

/// Complete report of an independent instruction tracing experiment.
#[derive(Debug, Clone)]
pub struct TraceExperimentReport {
    pub experiment_id: String,
    pub target_name: String,
    pub input_value: u64,
    pub trace_mechanism: &'static str,
    pub initial_registers: CpuRegisters,
    pub steps: Vec<EmulatedTraceStep>,
    pub instruction_count: usize,
    pub return_value: u64,
    pub termination_reason: TerminationReason,
    pub status: EmulationStatus,
}

impl TraceExperimentReport {
    pub fn render_summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "### Experiment {}: {} (Input: 0x{:016X})\n",
            self.experiment_id, self.target_name, self.input_value
        ));
        out.push_str(&format!("- **Mechanism:** {}\n", self.trace_mechanism));
        out.push_str(&format!("- **Total Observed Instructions:** `{}`\n", self.instruction_count));
        out.push_str(&format!("- **Final Return Value (RAX):** `{}` (0x{:X})\n", self.return_value, self.return_value));
        out.push_str(&format!("- **Termination:** `{:?}`\n", self.termination_reason));
        out.push_str(&format!("- **Status:** `{:?}`\n\n", self.status));

        out.push_str("| Step | Address | Machine Code | Instruction | RAX | RCX | RDX | RSP |\n");
        out.push_str("| :---: | :---: | :---: | :--- | :---: | :---: | :---: | :---: |\n");

        for step in self.steps.iter().take(20) {
            let byte_str = step
                .bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&format!(
                "| `{}` | `0x{:04X}` | `{}` | `{} {}` | `0x{:X}` | `0x{:X}` | `0x{:X}` | `0x{:X}` |\n",
                step.step_index,
                step.address,
                byte_str,
                step.mnemonic,
                step.operands_str,
                step.registers_after.rax,
                step.registers_after.rcx,
                step.registers_after.rdx,
                step.registers_after.rsp,
            ));
        }

        if self.steps.len() > 20 {
            out.push_str(&format!(
                "| ... | ... | ... | *[{} intermediate steps omitted for brevity]* | ... | ... | ... | ... |\n",
                self.steps.len() - 20
            ));
            if let Some(last) = self.steps.last() {
                let byte_str = last
                    .bytes
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                out.push_str(&format!(
                    "| `{}` | `0x{:04X}` | `{}` | `{} {}` | `0x{:X}` | `0x{:X}` | `0x{:X}` | `0x{:X}` |\n",
                    last.step_index,
                    last.address,
                    byte_str,
                    last.mnemonic,
                    last.operands_str,
                    last.registers_after.rax,
                    last.registers_after.rcx,
                    last.registers_after.rdx,
                    last.registers_after.rsp,
                ));
            }
        }

        out
    }
}

/// Virtual memory space supporting isolated code and stack execution.
pub struct VirtualMemory {
    pub code_base: u64,
    pub code: Vec<u8>,
    pub stack_base: u64,
    pub stack: Vec<u8>,
}

impl VirtualMemory {
    pub const STACK_CAPACITY: usize = 65_536; // 64 KB
    pub const SENTINEL_RET_ADDR: u64 = 0x0000_DEAD_BEEF_0000;

    pub fn new(code_base: u64, code: &[u8], stack_base: u64) -> Self {
        Self {
            code_base,
            code: code.to_vec(),
            stack_base,
            stack: vec![0u8; Self::STACK_CAPACITY],
        }
    }

    pub fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, TerminationReason> {
        if addr >= self.code_base && addr + len as u64 <= self.code_base + self.code.len() as u64 {
            let offset = (addr - self.code_base) as usize;
            return Ok(self.code[offset..offset + len].to_vec());
        }

        if addr >= self.stack_base && addr + len as u64 <= self.stack_base + self.stack.len() as u64 {
            let offset = (addr - self.stack_base) as usize;
            return Ok(self.stack[offset..offset + len].to_vec());
        }

        Err(TerminationReason::MemoryFault(addr))
    }

    pub fn read_u64(&self, addr: u64) -> Result<u64, TerminationReason> {
        let bytes = self.read_bytes(addr, 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_u32(&self, addr: u64) -> Result<u32, TerminationReason> {
        let bytes = self.read_bytes(addr, 4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_u8(&self, addr: u64) -> Result<u8, TerminationReason> {
        let bytes = self.read_bytes(addr, 1)?;
        Ok(bytes[0])
    }

    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) -> Result<(), TerminationReason> {
        if addr >= self.stack_base && addr + data.len() as u64 <= self.stack_base + self.stack.len() as u64 {
            let offset = (addr - self.stack_base) as usize;
            self.stack[offset..offset + data.len()].copy_from_slice(data);
            return Ok(());
        }

        Err(TerminationReason::MemoryFault(addr))
    }

    pub fn write_u64(&mut self, addr: u64, val: u64) -> Result<(), TerminationReason> {
        self.write_bytes(addr, &val.to_le_bytes())
    }

    pub fn write_u32(&mut self, addr: u64, val: u32) -> Result<(), TerminationReason> {
        self.write_bytes(addr, &val.to_le_bytes())
    }

    pub fn write_u8(&mut self, addr: u64, val: u8) -> Result<(), TerminationReason> {
        self.write_bytes(addr, &[val])
    }
}

/// Pure-Rust x86-64 Micro-Emulator for independent instruction-level tracing.
pub struct X64MicroEmulator {
    pub regs: CpuRegisters,
    pub flags: CpuFlags,
    pub mem: VirtualMemory,
    pub execution_budget: usize,
    pub steps_taken: usize,
}

impl X64MicroEmulator {
    pub const DEFAULT_CODE_BASE: u64 = 0x0001_0000;
    pub const DEFAULT_STACK_BASE: u64 = 0x7FFF_0000;
    pub const INITIAL_RSP_OFFSET: u64 = 0xF000;

    /// Creates an emulator initialized with machine code and argument inputs according
    /// to the Microsoft x64 calling convention (arg1 in RCX, arg2 in RDX).
    pub fn new(code: &[u8], arg1_rcx: u64, arg2_rdx: u64, execution_budget: usize) -> Self {
        let code_base = Self::DEFAULT_CODE_BASE;
        let stack_base = Self::DEFAULT_STACK_BASE;
        let mut mem = VirtualMemory::new(code_base, code, stack_base);

        let initial_rsp = stack_base + Self::INITIAL_RSP_OFFSET;
        // Push sentinel return address to stack:
        let top_rsp = initial_rsp - 8;
        mem.write_u64(top_rsp, VirtualMemory::SENTINEL_RET_ADDR)
            .expect("Stack initialization failed");

        let regs = CpuRegisters {
            rax: 0,
            rcx: arg1_rcx,
            rdx: arg2_rdx,
            rbx: 0,
            rsp: top_rsp,
            rbp: top_rsp,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: code_base,
        };

        Self {
            regs,
            flags: CpuFlags::default(),
            mem,
            execution_budget,
            steps_taken: 0,
        }
    }

    /// Read general register by iced Register enum.
    pub fn get_reg(&self, reg: Register) -> Result<u64, TerminationReason> {
        match reg {
            Register::RAX => Ok(self.regs.rax),
            Register::EAX => Ok(self.regs.rax & 0xFFFF_FFFF),
            Register::AX => Ok(self.regs.rax & 0xFFFF),
            Register::AL => Ok(self.regs.rax & 0xFF),
            Register::AH => Ok((self.regs.rax >> 8) & 0xFF),

            Register::RCX => Ok(self.regs.rcx),
            Register::ECX => Ok(self.regs.rcx & 0xFFFF_FFFF),
            Register::CX => Ok(self.regs.rcx & 0xFFFF),
            Register::CL => Ok(self.regs.rcx & 0xFF),
            Register::CH => Ok((self.regs.rcx >> 8) & 0xFF),

            Register::RDX => Ok(self.regs.rdx),
            Register::EDX => Ok(self.regs.rdx & 0xFFFF_FFFF),
            Register::DX => Ok(self.regs.rdx & 0xFFFF),
            Register::DL => Ok(self.regs.rdx & 0xFF),
            Register::DH => Ok((self.regs.rdx >> 8) & 0xFF),

            Register::RBX => Ok(self.regs.rbx),
            Register::EBX => Ok(self.regs.rbx & 0xFFFF_FFFF),
            Register::BX => Ok(self.regs.rbx & 0xFFFF),
            Register::BL => Ok(self.regs.rbx & 0xFF),
            Register::BH => Ok((self.regs.rbx >> 8) & 0xFF),

            Register::RSP => Ok(self.regs.rsp),
            Register::ESP => Ok(self.regs.rsp & 0xFFFF_FFFF),

            Register::RBP => Ok(self.regs.rbp),
            Register::EBP => Ok(self.regs.rbp & 0xFFFF_FFFF),

            Register::RSI => Ok(self.regs.rsi),
            Register::ESI => Ok(self.regs.rsi & 0xFFFF_FFFF),

            Register::RDI => Ok(self.regs.rdi),
            Register::EDI => Ok(self.regs.rdi & 0xFFFF_FFFF),

            Register::R8 => Ok(self.regs.r8),
            Register::R8D => Ok(self.regs.r8 & 0xFFFF_FFFF),
            Register::R9 => Ok(self.regs.r9),
            Register::R9D => Ok(self.regs.r9 & 0xFFFF_FFFF),
            Register::R10 => Ok(self.regs.r10),
            Register::R10D => Ok(self.regs.r10 & 0xFFFF_FFFF),
            Register::R11 => Ok(self.regs.r11),
            Register::R11D => Ok(self.regs.r11 & 0xFFFF_FFFF),
            Register::R12 => Ok(self.regs.r12),
            Register::R12D => Ok(self.regs.r12 & 0xFFFF_FFFF),
            Register::R13 => Ok(self.regs.r13),
            Register::R13D => Ok(self.regs.r13 & 0xFFFF_FFFF),
            Register::R14 => Ok(self.regs.r14),
            Register::R14D => Ok(self.regs.r14 & 0xFFFF_FFFF),
            Register::R15 => Ok(self.regs.r15),
            Register::R15D => Ok(self.regs.r15 & 0xFFFF_FFFF),

            Register::RIP => Ok(self.regs.rip),
            _ => Err(TerminationReason::UnsupportedInstruction(format!("Unsupported register read: {:?}", reg))),
        }
    }

    /// Write general register by iced Register enum.
    /// In x86-64, writes to 32-bit sub-registers zero the upper 32 bits of the 64-bit register.
    pub fn set_reg(&mut self, reg: Register, val: u64) -> Result<(), TerminationReason> {
        match reg {
            Register::RAX => { self.regs.rax = val; Ok(()) }
            Register::EAX => { self.regs.rax = val & 0xFFFF_FFFF; Ok(()) }
            Register::AX => { self.regs.rax = (self.regs.rax & !0xFFFF) | (val & 0xFFFF); Ok(()) }
            Register::AL => { self.regs.rax = (self.regs.rax & !0xFF) | (val & 0xFF); Ok(()) }

            Register::RCX => { self.regs.rcx = val; Ok(()) }
            Register::ECX => { self.regs.rcx = val & 0xFFFF_FFFF; Ok(()) }
            Register::CX => { self.regs.rcx = (self.regs.rcx & !0xFFFF) | (val & 0xFFFF); Ok(()) }
            Register::CL => { self.regs.rcx = (self.regs.rcx & !0xFF) | (val & 0xFF); Ok(()) }

            Register::RDX => { self.regs.rdx = val; Ok(()) }
            Register::EDX => { self.regs.rdx = val & 0xFFFF_FFFF; Ok(()) }
            Register::DX => { self.regs.rdx = (self.regs.rdx & !0xFFFF) | (val & 0xFFFF); Ok(()) }
            Register::DL => { self.regs.rdx = (self.regs.rdx & !0xFF) | (val & 0xFF); Ok(()) }

            Register::RBX => { self.regs.rbx = val; Ok(()) }
            Register::EBX => { self.regs.rbx = val & 0xFFFF_FFFF; Ok(()) }

            Register::RSP => { self.regs.rsp = val; Ok(()) }
            Register::ESP => { self.regs.rsp = val & 0xFFFF_FFFF; Ok(()) }

            Register::RBP => { self.regs.rbp = val; Ok(()) }
            Register::EBP => { self.regs.rbp = val & 0xFFFF_FFFF; Ok(()) }

            Register::RSI => { self.regs.rsi = val; Ok(()) }
            Register::ESI => { self.regs.rsi = val & 0xFFFF_FFFF; Ok(()) }

            Register::RDI => { self.regs.rdi = val; Ok(()) }
            Register::EDI => { self.regs.rdi = val & 0xFFFF_FFFF; Ok(()) }

            Register::R8 => { self.regs.r8 = val; Ok(()) }
            Register::R8D => { self.regs.r8 = val & 0xFFFF_FFFF; Ok(()) }
            Register::R9 => { self.regs.r9 = val; Ok(()) }
            Register::R9D => { self.regs.r9 = val & 0xFFFF_FFFF; Ok(()) }
            Register::R10 => { self.regs.r10 = val; Ok(()) }
            Register::R10D => { self.regs.r10 = val & 0xFFFF_FFFF; Ok(()) }
            Register::R11 => { self.regs.r11 = val; Ok(()) }
            Register::R11D => { self.regs.r11 = val & 0xFFFF_FFFF; Ok(()) }

            _ => Err(TerminationReason::UnsupportedInstruction(format!("Unsupported register write: {:?}", reg))),
        }
    }

    /// Computes effective memory address for an instruction operand.
    pub fn compute_memory_address(&self, instr: &Instruction) -> Result<u64, TerminationReason> {
        let base_val = if instr.memory_base() != Register::None {
            self.get_reg(instr.memory_base())?
        } else {
            0
        };

        let index_val = if instr.memory_index() != Register::None {
            self.get_reg(instr.memory_index())? * (instr.memory_index_scale() as u64)
        } else {
            0
        };

        let disp = instr.memory_displacement64();
        Ok(base_val.wrapping_add(index_val).wrapping_add(disp))
    }

    /// Evaluates operand value (register, memory, or immediate).
    pub fn read_op_value(&self, instr: &Instruction, op_idx: u32) -> Result<u64, TerminationReason> {
        match instr.op_kind(op_idx) {
            OpKind::Register => self.get_reg(instr.op_register(op_idx)),
            OpKind::Immediate8 => Ok(instr.immediate8() as u64),
            OpKind::Immediate16 => Ok(instr.immediate16() as u64),
            OpKind::Immediate32 => Ok(instr.immediate32() as u64),
            OpKind::Immediate64 => Ok(instr.immediate64()),
            OpKind::Immediate8to16 => Ok(instr.immediate8to16() as u16 as u64),
            OpKind::Immediate8to32 => Ok(instr.immediate8to32() as u32 as u64),
            OpKind::Immediate8to64 => Ok(instr.immediate8to64() as u64),
            OpKind::Immediate32to64 => Ok(instr.immediate32to64() as u64),
            OpKind::Memory => {
                let addr = self.compute_memory_address(instr)?;
                match instr.memory_size().size() {
                    1 => Ok(self.mem.read_u8(addr)? as u64),
                    4 => Ok(self.mem.read_u32(addr)? as u64),
                    8 => Ok(self.mem.read_u64(addr)?),
                    s => Err(TerminationReason::UnsupportedInstruction(format!("Unsupported memory read size: {} bytes", s))),
                }
            }
            k => Err(TerminationReason::UnsupportedInstruction(format!("Unsupported operand kind: {:?}", k))),
        }
    }

    /// Updates CPU condition flags based on arithmetic result.
    fn update_arith_flags(&mut self, res: u64, is_64bit: bool, cf: bool, of: bool) {
        if is_64bit {
            self.flags.zf = res == 0;
            self.flags.sf = (res & (1u64 << 63)) != 0;
        } else {
            let res32 = res as u32;
            self.flags.zf = res32 == 0;
            self.flags.sf = (res32 & (1u32 << 31)) != 0;
        }
        self.flags.cf = cf;
        self.flags.of = of;
    }

    /// Execute the program until completion, budget exhaustion, or error,
    /// recording every instruction step.
    pub fn run_trace(
        &mut self,
        experiment_id: &str,
        target_name: &str,
        input_value: u64,
    ) -> TraceExperimentReport {
        let initial_registers = self.regs;
        let mut steps = Vec::new();
        let mut formatter = IntelFormatter::new();
        let mut output = String::new();

        let termination_reason = loop {
            if self.steps_taken >= self.execution_budget {
                break TerminationReason::BudgetExhausted(self.steps_taken);
            }

            let curr_rip = self.regs.rip;
            if curr_rip == VirtualMemory::SENTINEL_RET_ADDR {
                break TerminationReason::NormalRet;
            }

            // Read instruction bytes at RIP (up to 15 bytes max x86 instruction length):
            let raw_bytes = match self.mem.read_bytes(curr_rip, 15) {
                Ok(b) => b,
                Err(_) => {
                    let remaining = (self.mem.code_base + self.mem.code.len() as u64).saturating_sub(curr_rip) as usize;
                    if remaining == 0 {
                        break TerminationReason::MemoryFault(curr_rip);
                    }
                    match self.mem.read_bytes(curr_rip, remaining) {
                        Ok(b) => b,
                        Err(e) => break e,
                    }
                }
            };

            let mut decoder = Decoder::with_ip(64, &raw_bytes, curr_rip, DecoderOptions::NONE);
            let instr = decoder.decode();
            if instr.is_invalid() {
                break TerminationReason::InvalidOpcode(curr_rip);
            }

            output.clear();
            formatter.format(&instr, &mut output);
            let mnemonic_str = format!("{:?}", instr.mnemonic());
            let operands_str = output.clone();
            let instr_len = instr.len();
            let instr_bytes = raw_bytes[..instr_len].to_vec();

            // Advance RIP past current instruction:
            let next_rip = curr_rip + instr_len as u64;
            self.regs.rip = next_rip;

            // Execute the decoded instruction:
            let step_result = self.execute_instruction(&instr);
            self.steps_taken += 1;

            steps.push(EmulatedTraceStep {
                step_index: self.steps_taken,
                address: curr_rip,
                mnemonic: mnemonic_str,
                operands_str,
                bytes: instr_bytes,
                registers_after: self.regs,
            });

            match step_result {
                Ok(should_continue) => {
                    if !should_continue {
                        break TerminationReason::NormalRet;
                    }
                }
                Err(err) => break err,
            }
        };

        let status = match &termination_reason {
            TerminationReason::NormalRet => EmulationStatus::CompletedSuccess,
            TerminationReason::BudgetExhausted(_) => EmulationStatus::BudgetExceeded,
            TerminationReason::UnsupportedInstruction(_) => EmulationStatus::UnsupportedDeferred,
            _ => EmulationStatus::Faulted,
        };

        TraceExperimentReport {
            experiment_id: experiment_id.to_string(),
            target_name: target_name.to_string(),
            input_value,
            trace_mechanism: "Pure-Rust x86-64 Micro-Emulator (iced-x86 driven)",
            initial_registers,
            steps,
            instruction_count: self.steps_taken,
            return_value: self.regs.rax,
            termination_reason,
            status,
        }
    }

    /// Returns operand size in bytes (1, 2, 4, 8).
    pub fn get_op_size_bytes(&self, instr: &Instruction, op_idx: u32) -> usize {
        match instr.op_kind(op_idx) {
            OpKind::Register => {
                let reg = instr.op_register(op_idx);
                if reg.is_gpr64() {
                    8
                } else if reg.is_gpr32() {
                    4
                } else if reg.is_gpr16() {
                    2
                } else if reg.is_gpr8() {
                    1
                } else {
                    8
                }
            }
            OpKind::Memory => instr.memory_size().size(),
            _ => 8,
        }
    }

    /// Writes value back to register or memory destination operand.
    pub fn write_op_value(&mut self, instr: &Instruction, op_idx: u32, val: u64) -> Result<(), TerminationReason> {
        match instr.op_kind(op_idx) {
            OpKind::Register => self.set_reg(instr.op_register(op_idx), val),
            OpKind::Memory => {
                let addr = self.compute_memory_address(instr)?;
                match instr.memory_size().size() {
                    1 => self.mem.write_u8(addr, val as u8),
                    2 => self.mem.write_bytes(addr, &(val as u16).to_le_bytes()),
                    4 => self.mem.write_u32(addr, val as u32),
                    8 => self.mem.write_u64(addr, val),
                    s => Err(TerminationReason::UnsupportedInstruction(format!("Unsupported memory write size: {}B", s))),
                }
            }
            k => Err(TerminationReason::UnsupportedInstruction(format!("Unsupported destination operand kind: {:?}", k))),
        }
    }

    /// Dispatches and executes an individual instruction.
    /// Returns Ok(true) to continue, Ok(false) upon clean RET termination.
    fn execute_instruction(&mut self, instr: &Instruction) -> Result<bool, TerminationReason> {
        let op0_size = self.get_op_size_bytes(instr, 0);
        let is_64bit = op0_size == 8;


        match instr.mnemonic() {
            Mnemonic::Nop => Ok(true),

            Mnemonic::Mov => {
                let src_val = self.read_op_value(instr, 1)?;
                self.write_op_value(instr, 0, src_val)?;
                Ok(true)
            }

            Mnemonic::Movzx => {
                let src_val = self.read_op_value(instr, 1)?;
                self.write_op_value(instr, 0, src_val)?;
                Ok(true)
            }

            Mnemonic::Lea => {
                let eff_addr = self.compute_memory_address(instr)?;
                self.set_reg(instr.op0_register(), eff_addr)?;
                Ok(true)
            }

            Mnemonic::Add => {
                let op0 = self.read_op_value(instr, 0)?;
                let op1 = self.read_op_value(instr, 1)?;
                let (res, cf) = if is_64bit {
                    let (r, c) = op0.overflowing_add(op1);
                    (r, c)
                } else {
                    let (r, c) = (op0 as u32).overflowing_add(op1 as u32);
                    (r as u64, c)
                };
                self.write_op_value(instr, 0, res)?;
                self.update_arith_flags(res, is_64bit, cf, false);
                Ok(true)
            }

            Mnemonic::Imul => {
                let res = if instr.op_count() == 3 {
                    let src1 = self.read_op_value(instr, 1)?;
                    let src2 = self.read_op_value(instr, 2)?;
                    if is_64bit { src1.wrapping_mul(src2) } else { (src1 as u32).wrapping_mul(src2 as u32) as u64 }
                } else if instr.op_count() == 2 {
                    let op0 = self.read_op_value(instr, 0)?;
                    let op1 = self.read_op_value(instr, 1)?;
                    if is_64bit { op0.wrapping_mul(op1) } else { (op0 as u32).wrapping_mul(op1 as u32) as u64 }
                } else {
                    let op0 = self.read_op_value(instr, 0)?;
                    let rax = self.regs.rax;
                    if is_64bit { rax.wrapping_mul(op0) } else { (rax as u32).wrapping_mul(op0 as u32) as u64 }
                };
                self.write_op_value(instr, 0, res)?;
                self.update_arith_flags(res, is_64bit, false, false);
                Ok(true)
            }

            Mnemonic::Sub => {
                let op0 = self.read_op_value(instr, 0)?;
                let op1 = self.read_op_value(instr, 1)?;
                let (res, cf) = if is_64bit {
                    let (r, c) = op0.overflowing_sub(op1);
                    (r, c)
                } else {
                    let (r, c) = (op0 as u32).overflowing_sub(op1 as u32);
                    (r as u64, c)
                };
                self.write_op_value(instr, 0, res)?;
                self.update_arith_flags(res, is_64bit, cf, false);
                Ok(true)
            }

            Mnemonic::Inc => {
                let op0 = self.read_op_value(instr, 0)?;
                let res = if is_64bit { op0.wrapping_add(1) } else { (op0 as u32).wrapping_add(1) as u64 };
                self.write_op_value(instr, 0, res)?;
                self.update_arith_flags(res, is_64bit, self.flags.cf, false);
                Ok(true)
            }

            Mnemonic::Dec => {
                let op0 = self.read_op_value(instr, 0)?;
                let res = if is_64bit { op0.wrapping_sub(1) } else { (op0 as u32).wrapping_sub(1) as u64 };
                self.write_op_value(instr, 0, res)?;
                self.update_arith_flags(res, is_64bit, self.flags.cf, false);
                Ok(true)
            }

            Mnemonic::And => {
                let op0 = self.read_op_value(instr, 0)?;
                let op1 = self.read_op_value(instr, 1)?;
                let res = op0 & op1;
                self.write_op_value(instr, 0, res)?;
                self.update_arith_flags(res, is_64bit, false, false);
                Ok(true)
            }

            Mnemonic::Or => {
                let op0 = self.read_op_value(instr, 0)?;
                let op1 = self.read_op_value(instr, 1)?;
                let res = op0 | op1;
                self.write_op_value(instr, 0, res)?;
                self.update_arith_flags(res, is_64bit, false, false);
                Ok(true)
            }

            Mnemonic::Xor => {
                let op0 = self.read_op_value(instr, 0)?;
                let op1 = self.read_op_value(instr, 1)?;
                let res = op0 ^ op1;
                self.write_op_value(instr, 0, res)?;
                self.update_arith_flags(res, is_64bit, false, false);
                Ok(true)
            }

            Mnemonic::Shr => {
                let op0 = self.read_op_value(instr, 0)?;
                let shift = (self.read_op_value(instr, 1)? & 0x3F) as u32;
                let res = op0 >> shift;
                self.write_op_value(instr, 0, res)?;
                self.update_arith_flags(res, is_64bit, false, false);
                Ok(true)
            }

            Mnemonic::Shl => {
                let op0 = self.read_op_value(instr, 0)?;
                let shift = (self.read_op_value(instr, 1)? & 0x3F) as u32;
                let res = op0 << shift;
                self.write_op_value(instr, 0, res)?;
                self.update_arith_flags(res, is_64bit, false, false);
                Ok(true)
            }

            Mnemonic::Cmp => {
                let op0 = self.read_op_value(instr, 0)?;
                let op1 = self.read_op_value(instr, 1)?;
                let (res, cf) = if is_64bit {
                    let (r, c) = op0.overflowing_sub(op1);
                    (r, c)
                } else {
                    let (r, c) = (op0 as u32).overflowing_sub(op1 as u32);
                    (r as u64, c)
                };
                self.update_arith_flags(res, is_64bit, cf, false);
                Ok(true)
            }

            Mnemonic::Test => {
                let op0 = self.read_op_value(instr, 0)?;
                let op1 = self.read_op_value(instr, 1)?;
                let res = op0 & op1;
                self.update_arith_flags(res, is_64bit, false, false);
                Ok(true)
            }

            Mnemonic::Jmp => {
                self.regs.rip = instr.near_branch_target();
                Ok(true)
            }

            Mnemonic::Je => {
                if self.flags.zf {
                    self.regs.rip = instr.near_branch_target();
                }
                Ok(true)
            }

            Mnemonic::Jne => {
                if !self.flags.zf {
                    self.regs.rip = instr.near_branch_target();
                }
                Ok(true)
            }

            Mnemonic::Ja => {
                if !self.flags.cf && !self.flags.zf {
                    self.regs.rip = instr.near_branch_target();
                }
                Ok(true)
            }

            Mnemonic::Jae => {
                if !self.flags.cf {
                    self.regs.rip = instr.near_branch_target();
                }
                Ok(true)
            }

            Mnemonic::Jb => {
                if self.flags.cf {
                    self.regs.rip = instr.near_branch_target();
                }
                Ok(true)
            }

            Mnemonic::Jbe => {
                if self.flags.cf || self.flags.zf {
                    self.regs.rip = instr.near_branch_target();
                }
                Ok(true)
            }

            Mnemonic::Push => {
                let val = self.read_op_value(instr, 0)?;
                let new_rsp = self.regs.rsp - 8;
                self.mem.write_u64(new_rsp, val)?;
                self.regs.rsp = new_rsp;
                Ok(true)
            }

            Mnemonic::Pop => {
                let val = self.mem.read_u64(self.regs.rsp)?;
                self.regs.rsp += 8;
                self.set_reg(instr.op0_register(), val)?;
                Ok(true)
            }

            Mnemonic::Popcnt => {
                let src = self.read_op_value(instr, 1)?;
                let count = src.count_ones() as u64;
                self.set_reg(instr.op0_register(), count)?;
                self.flags.zf = count == 0;
                self.flags.cf = false;
                self.flags.sf = false;
                self.flags.of = false;
                Ok(true)
            }

            Mnemonic::Ret => {
                let ret_target = self.mem.read_u64(self.regs.rsp)?;
                self.regs.rsp += 8;
                if ret_target == VirtualMemory::SENTINEL_RET_ADDR {
                    // Clean return to caller sentinel
                    Ok(false)
                } else {
                    self.regs.rip = ret_target;
                    Ok(true)
                }
            }

            m => Err(TerminationReason::UnsupportedInstruction(format!("{:?}", m))),
        }
    }

    /// Attempts to trace a live compiled function pointer.
    pub fn trace_live_function(
        fn_ptr: *const (),
        target_name: &str,
        input_value: u64,
        execution_budget: usize,
    ) -> Result<TraceExperimentReport, String> {
        let code_bytes = extract_function_code_bytes(fn_ptr, 256)?;
        let mut emu = X64MicroEmulator::new(&code_bytes, input_value, 0, execution_budget);
        Ok(emu.run_trace("EXP-LIVE", target_name, input_value))
    }
}

/// The Three Authorized Controlled Micro-Experiments for CAE-1D Phase 1.
pub struct MicroExperiments;

impl MicroExperiments {
    /// Experiment A: Straight-line machine instructions (4 sequential instructions).
    ///
    /// ```x86asm
    /// mov rax, rcx     ; 48 89 C8
    /// add rax, 10      ; 48 83 C0 0A
    /// shl rax, 1       ; 48 D1 E0
    /// ret              ; C3
    /// ```
    ///
    /// Expected formula: `(input + 10) * 2`. Exactly 4 instructions executed.
    #[rustfmt::skip]
    pub const CODE_EXP_A_STRAIGHT: &'static [u8] = &[
        0x48, 0x89, 0xC8,       // mov rax, rcx
        0x48, 0x83, 0xC0, 0x0A, // add rax, 10
        0x48, 0xD1, 0xE0,       // shl rax, 1
        0xC3,                   // ret
    ];

    /// Experiment B: Conditional branches (Taken vs Not-Taken).
    ///
    /// ```x86asm
    /// test rcx, 1          ; 48 F7 C1 01 00 00 00
    /// jnz branch_taken     ; 75 08
    /// ; Path Not-Taken (Even):
    /// mov rax, 100         ; B8 64 00 00 00
    /// ret                  ; C3
    /// ; Path Taken (Odd):
    /// branch_taken:
    /// mov rax, 200         ; B8 C8 00 00 00
    /// ret                  ; C3
    /// ```
    ///
    /// Expected for input = 0 (even): 4 instructions (test, jnz [not taken], mov 100, ret). Result = 100.
    /// Expected for input = 1 (odd): 3 instructions (test, jnz [taken], mov 200, ret). Result = 200.
    #[rustfmt::skip]
    pub const CODE_EXP_B_BRANCH: &'static [u8] = &[
        0x48, 0xF7, 0xC1, 0x01, 0x00, 0x00, 0x00, // test rcx, 1
        0x75, 0x06,                               // jnz +6 -> offset 0x0F
        0xB8, 0x64, 0x00, 0x00, 0x00,             // mov eax, 100
        0xC3,                                     // ret
        0xB8, 0xC8, 0x00, 0x00, 0x00,             // mov eax, 200 (offset 0x0F)
        0xC3,                                     // ret
    ];

    /// Experiment C: Bounded loop (summing n down to 0).
    ///
    /// ```x86asm
    /// xor eax, eax         ; 31 C0 (rax = 0)
    /// loop_header:
    /// test rcx, rcx        ; 48 85 C9 (check n == 0)
    /// jz loop_exit         ; 74 08
    /// add rax, rcx         ; 48 01 C8 (sum += n)
    /// dec rcx              ; 48 FF C9 (n -= 1)
    /// jmp loop_header      ; EB F2 (jump back to test rcx, rcx)
    /// loop_exit:
    /// ret                  ; C3
    /// ```
    ///
    /// Expected:
    /// - For n = 0: 4 instructions (xor, test, jz, ret). Result = 0.
    /// - For n = 1: 8 instructions (xor, [test, jnz, add, dec, jmp] * 1, test, jz, ret). Result = 1.
    /// - For n = 5: 24 instructions (xor, [test, jnz, add, dec, jmp] * 5, test, jz, ret). Result = 15.
    #[rustfmt::skip]
    pub const CODE_EXP_C_LOOP: &'static [u8] = &[
        0x31, 0xC0,                         // xor eax, eax (offset 0x00)
        0x48, 0x85, 0xC9,                   // test rcx, rcx (offset 0x02)
        0x74, 0x08,                         // jz +8 -> offset 0x0F (offset 0x05)
        0x48, 0x01, 0xC8,                   // add rax, rcx (offset 0x07)
        0x48, 0xFF, 0xC9,                   // dec rcx (offset 0x0A)
        0xEB, 0xF3,                         // jmp -14 -> offset 0x02 (offset 0x0D)
        0xC3,                               // ret (offset 0x0F)
    ];

    /// Runs Experiment A (Straight-Line).
    pub fn run_experiment_a(input: u64) -> TraceExperimentReport {
        let mut emu = X64MicroEmulator::new(Self::CODE_EXP_A_STRAIGHT, input, 0, 100);
        emu.run_trace("EXP-A", "Straight-Line Instructions", input)
    }

    /// Runs Experiment B (Branching: Taken vs Not-Taken).
    pub fn run_experiment_b(input: u64) -> TraceExperimentReport {
        let mut emu = X64MicroEmulator::new(Self::CODE_EXP_B_BRANCH, input, 0, 100);
        emu.run_trace("EXP-B", "Conditional Branching", input)
    }

    /// Runs Experiment C (Bounded Loop).
    pub fn run_experiment_c(iterations: u64) -> TraceExperimentReport {
        let mut emu = X64MicroEmulator::new(Self::CODE_EXP_C_LOOP, iterations, 0, 1_000);
        emu.run_trace("EXP-C", "Bounded Loop Counter", iterations)
    }
}

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

/// Safely extracts machine-code bytes for a live Rust function pointer using Windows `.pdata`.
pub fn extract_function_code_bytes(
    fn_ptr: *const (),
    fallback_max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if fn_ptr.is_null() {
        return Err("Function pointer is null".to_string());
    }

    let mut actual_ptr = fn_ptr as *const u8;
    unsafe {
        if *actual_ptr == 0xE9 {
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
                return Ok(code_slice.to_vec());
            }
        }
    }

    let code_slice = unsafe { std::slice::from_raw_parts(actual_ptr, fallback_max_bytes) };
    Ok(code_slice.to_vec())
}

/// Comparison entry between CAE-1C compiled-path model and CAE-1D emulator trace.
#[derive(Debug, Clone)]
pub struct ModelVsEmulatorComparison {
    pub algorithm_name: &'static str,
    pub input_description: &'static str,
    pub input_value: u64,
    pub static_instruction_count: usize,
    pub model_estimated_dynamic_steps: usize,
    pub emulator_observed_instruction_events: Option<usize>,
    pub delta_steps: Option<isize>,
    pub status: &'static str,
    pub notes: &'static str,
}

impl ModelVsEmulatorComparison {
    pub fn render_markdown_table(entries: &[Self]) -> String {
        let mut out = String::new();
        out.push_str("### Model vs. Emulator Dynamic Instruction Comparison (CAE-1C vs CAE-1D)\n\n");
        out.push_str("| Algorithm | Workload | Static Instrs | Model-Estimated (CAE-1C) | Emulator-Observed (CAE-1D) | Delta | Status | Notes |\n");
        out.push_str("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |\n");

        for e in entries {
            let emu_str = match e.emulator_observed_instruction_events {
                Some(n) => format!("`{}`", n),
                None => "`Deferred`".to_string(),
            };
            let delta_str = match e.delta_steps {
                Some(d) => {
                    if d > 0 {
                        format!("`+{}`", d)
                    } else if d == 0 {
                        "`0 (Exact Match)`".to_string()
                    } else {
                        format!("`{}`", d)
                    }
                }
                None => "`N/A`".to_string(),
            };

            out.push_str(&format!(
                "| **{}** | {} | `{}` | `{}` | {} | {} | **{}** | {} |\n",
                e.algorithm_name,
                e.input_description,
                e.static_instruction_count,
                e.model_estimated_dynamic_steps,
                emu_str,
                delta_str,
                e.status,
                e.notes,
            ));
        }

        out
    }
}
