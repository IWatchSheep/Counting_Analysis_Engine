//! # Native Hardware Instruction Tracing (CAE-1D Phase 2)
//!
//! Provides isolated, out-of-process instruction-by-instruction tracing of
//! physical machine-code execution on the host CPU using the Windows Debug API.
//!
//! ## Architectural Principles
//! 1. **Zero In-Process VEH / Trap Hooks:** The main Counting Analysis Engine process
//!    never installs in-process exception handlers or modifies its own Trap Flag.
//! 2. **Process Isolation:** Target micro-kernels execute inside a separate, disposable
//!    child process (`cae_trace_target.exe`) launched with `DEBUG_ONLY_THIS_PROCESS`.
//! 3. **Hardware Trap Flag (TF):** The physical host CPU raises single-step exceptions
//!    after each retired machine instruction between the Entry Trigger (`int 3`) and
//!    Exit Trigger (`int 3`).
//! 4. **Runtime Image Filtering:** Automatically identifies the debuggee's loaded PE image
//!    base and size, ignoring all internal Windows NTDLL/CRT initialization breakpoints.
//! 5. **Safe Termination & Budgets:** Enforces instruction execution limits and timeouts,
//!    ensuring runaways or loops terminate cleanly without hanging.

use std::path::PathBuf;
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};

/// Snapshot of the 64-bit general-purpose CPU registers captured from the debuggee thread context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NativeTraceRegisters {
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
    pub eflags: u32,
}

/// Architectural CPU condition flags captured from physical EFLAGS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NativeTraceFlags {
    pub zf: bool,
    pub cf: bool,
    pub sf: bool,
    pub of: bool,
}

impl NativeTraceFlags {
    pub fn from_eflags(eflags: u32) -> Self {
        Self {
            cf: (eflags & (1 << 0)) != 0,
            zf: (eflags & (1 << 6)) != 0,
            sf: (eflags & (1 << 7)) != 0,
            of: (eflags & (1 << 11)) != 0,
        }
    }
}

/// A single instruction step observed executing on native physical silicon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTraceStep {
    pub step_index: usize,
    pub address: u64,
    pub mnemonic: String,
    pub operands_str: String,
    pub bytes: Vec<u8>,
    pub registers_after: NativeTraceRegisters,
    pub flags_after: NativeTraceFlags,
}

/// Status of the native instruction tracing session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeTraceStatus {
    CompletedSuccess,
    BudgetExhausted(usize),
    TargetProcessFailed(String),
    Timeout,
}

/// Complete report of an independent native instruction tracing experiment.
#[derive(Debug, Clone)]
pub struct NativeTraceReport {
    pub kernel_id: String,
    pub target_name: String,
    pub input_value: u64,
    pub trace_mechanism: &'static str,
    pub total_observed_instructions: usize,
    pub return_value_rax: u64,
    pub final_registers: NativeTraceRegisters,
    pub final_flags: NativeTraceFlags,
    pub status: NativeTraceStatus,
    pub steps: Vec<NativeTraceStep>,
}

impl NativeTraceReport {
    pub fn render_summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "### Native Trace {}: {} (Input: 0x{:016X} / {})\n",
            self.kernel_id, self.target_name, self.input_value, self.input_value
        ));
        out.push_str(&format!("- **Observation Mechanism:** {}\n", self.trace_mechanism));
        out.push_str(&format!("- **Total Hardware Instructions Observed:** `{}`\n", self.total_observed_instructions));
        out.push_str(&format!("- **Final Return Value (RAX):** `{}` (0x{:X})\n", self.return_value_rax, self.return_value_rax));
        out.push_str(&format!("- **Final Condition Flags:** ZF={}, CF={}, SF={}, OF={}\n",
            self.final_flags.zf as u8, self.final_flags.cf as u8, self.final_flags.sf as u8, self.final_flags.of as u8));
        out.push_str(&format!("- **Trace Status:** `{:?}`\n\n", self.status));

        out.push_str("| Step | Address | Machine Code | Instruction | RAX | RCX | RDX | RSP | ZF | CF |\n");
        out.push_str("| :---: | :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |\n");

        for step in self.steps.iter().take(25) {
            let byte_str = step
                .bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&format!(
                "| `{}` | `0x{:08X}` | `{}` | `{} {}` | `0x{:X}` | `0x{:X}` | `0x{:X}` | `0x{:X}` | `{}` | `{}` |\n",
                step.step_index,
                step.address,
                byte_str,
                step.mnemonic,
                step.operands_str,
                step.registers_after.rax,
                step.registers_after.rcx,
                step.registers_after.rdx,
                step.registers_after.rsp,
                step.flags_after.zf as u8,
                step.flags_after.cf as u8,
            ));
        }

        if self.steps.len() > 25 {
            out.push_str(&format!(
                "| ... | ... | ... | *[{} intermediate steps omitted]* | ... | ... | ... | ... | ... | ... |\n",
                self.steps.len() - 25
            ));
            if let Some(last) = self.steps.last() {
                let byte_str = last
                    .bytes
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                out.push_str(&format!(
                    "| `{}` | `0x{:08X}` | `{}` | `{} {}` | `0x{:X}` | `0x{:X}` | `0x{:X}` | `0x{:X}` | `{}` | `{}` |\n",
                    last.step_index,
                    last.address,
                    byte_str,
                    last.mnemonic,
                    last.operands_str,
                    last.registers_after.rax,
                    last.registers_after.rcx,
                    last.registers_after.rdx,
                    last.registers_after.rsp,
                    last.flags_after.zf as u8,
                    last.flags_after.cf as u8,
                ));
            }
        }

        out
    }
}

/// 4-Tier Comparison Record across all analysis tiers.
#[derive(Debug, Clone)]
pub struct FourTierComparison {
    pub experiment_id: &'static str,
    pub workload_name: &'static str,
    pub input_value: u64,
    pub static_instruction_count: usize,
    pub model_estimated_steps: usize,
    pub emulator_observed_steps: Option<usize>,
    pub native_hardware_steps: usize,
    pub hardware_vs_emulator_delta: Option<isize>,
    pub status: &'static str,
    pub structural_notes: &'static str,
}

impl FourTierComparison {
    pub fn render_markdown_table(rows: &[Self]) -> String {
        let mut out = String::new();
        out.push_str("### 4-Tier Execution Comparison: Static vs. Model vs. Emulator vs. Native Silicon\n\n");
        out.push_str("| Experiment | Workload | Input | Static (T2) | Model (T3) | Emulator (1D-P1) | Native Hardware (1D-P2) | Delta (HW vs Emu) | Status | Structural & Boundary Reconciliation |\n");
        out.push_str("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |\n");

        for r in rows {
            let emu_str = match r.emulator_observed_steps {
                Some(s) => format!("`{}`", s),
                None => "`N/A`".to_string(),
            };
            let delta_str = match r.hardware_vs_emulator_delta {
                Some(0) => "`0 (Exact Match)`".to_string(),
                Some(d) if d > 0 => format!("`+{}`", d),
                Some(d) => format!("`{}`", d),
                None => "`N/A`".to_string(),
            };

            out.push_str(&format!(
                "| **{}** | {} | `{}` | `{}` | `{}` | {} | `{}` | {} | **{}** | {} |\n",
                r.experiment_id,
                r.workload_name,
                r.input_value,
                r.static_instruction_count,
                r.model_estimated_steps,
                emu_str,
                r.native_hardware_steps,
                delta_str,
                r.status,
                r.structural_notes,
            ));
        }

        out
    }
}

// =========================================================================
// Win32 Debug API Definitions & Structures
// =========================================================================

#[cfg(windows)]
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct ContextRecord {
    p1_home: u64,
    p2_home: u64,
    p3_home: u64,
    p4_home: u64,
    p5_home: u64,
    p6_home: u64,
    context_flags: u32,
    mx_csr: u32,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    eflags: u32,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    padding: [u8; 1232 - 256],
}

#[cfg(windows)]
impl Default for ContextRecord {
    fn default() -> Self {
        Self {
            p1_home: 0, p2_home: 0, p3_home: 0, p4_home: 0, p5_home: 0, p6_home: 0,
            context_flags: 0x0010001F, // CONTEXT_ALL for AMD64
            mx_csr: 0, seg_cs: 0, seg_ds: 0, seg_es: 0, seg_fs: 0, seg_gs: 0, seg_ss: 0,
            eflags: 0, dr0: 0, dr1: 0, dr2: 0, dr3: 0, dr6: 0, dr7: 0,
            rax: 0, rcx: 0, rdx: 0, rbx: 0, rsp: 0, rbp: 0, rsi: 0, rdi: 0,
            r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0, rip: 0,
            padding: [0u8; 1232 - 256],
        }
    }
}

#[cfg(windows)]
#[repr(C)]
struct DebugEvent {
    dw_debug_event_code: u32,
    dw_process_id: u32,
    dw_thread_id: u32,
    padding: u32,
    u: [u8; 160],
}

#[cfg(windows)]
#[repr(C)]
struct StartupInfoW {
    cb: u32,
    lp_reserved: *mut u16,
    lp_desktop: *mut u16,
    lp_title: *mut u16,
    dw_x: u32,
    dw_y: u32,
    dw_x_size: u32,
    dw_y_size: u32,
    dw_x_count_chars: u32,
    dw_y_count_chars: u32,
    dw_fill_attribute: u32,
    dw_flags: u32,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    h_std_input: *mut std::ffi::c_void,
    h_std_output: *mut std::ffi::c_void,
    h_std_error: *mut std::ffi::c_void,
}

#[cfg(windows)]
#[repr(C)]
struct ProcessInformation {
    h_process: *mut std::ffi::c_void,
    h_thread: *mut std::ffi::c_void,
    dw_process_id: u32,
    dw_thread_id: u32,
}

#[cfg(windows)]
unsafe extern "system" {
    fn CreateProcessW(
        lp_application_name: *const u16,
        lp_command_line: *mut u16,
        lp_process_attributes: *mut std::ffi::c_void,
        lp_thread_attributes: *mut std::ffi::c_void,
        b_inherit_handles: i32,
        dw_creation_flags: u32,
        lp_environment: *mut std::ffi::c_void,
        lp_current_directory: *const u16,
        lp_startup_info: *const StartupInfoW,
        lp_process_information: *mut ProcessInformation,
    ) -> i32;

    fn WaitForDebugEvent(lp_debug_event: *mut DebugEvent, dw_milliseconds: u32) -> i32;
    fn ContinueDebugEvent(dw_process_id: u32, dw_thread_id: u32, dw_continue_status: u32) -> i32;
    fn OpenThread(dw_desired_access: u32, b_inherit_handle: i32, dw_thread_id: u32) -> *mut std::ffi::c_void;
    fn GetThreadContext(h_thread: *mut std::ffi::c_void, lp_context: *mut ContextRecord) -> i32;
    fn SetThreadContext(h_thread: *mut std::ffi::c_void, lp_context: *const ContextRecord) -> i32;
    fn ReadProcessMemory(
        h_process: *mut std::ffi::c_void,
        lp_base_address: u64,
        lp_buffer: *mut u8,
        n_size: usize,
        lp_number_of_bytes_read: *mut usize,
    ) -> i32;
    fn TerminateProcess(h_process: *mut std::ffi::c_void, u_exit_code: u32) -> i32;
    fn CloseHandle(h_object: *mut std::ffi::c_void) -> i32;
}

/// Discovers the path to `cae_trace_target.exe`.
pub fn locate_target_binary() -> Result<PathBuf, String> {
    // 1. Cargo integration test environment variable
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_cae_trace_target") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    // 2. Relative to current executable directory
    if let Ok(curr) = std::env::current_exe()
        && let Some(parent) = curr.parent() {
            let candidate1 = parent.join("cae_trace_target.exe");
            if candidate1.exists() {
                return Ok(candidate1);
            }
            if let Some(grandparent) = parent.parent() {
                let candidate2 = grandparent.join("cae_trace_target.exe");
                if candidate2.exists() {
                    return Ok(candidate2);
                }
            }
        }

    // 3. Known project build directories
    let candidates = [
        "target/debug/cae_trace_target.exe",
        "target/release/cae_trace_target.exe",
        "../target/debug/cae_trace_target.exe",
    ];

    for c in candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Ok(p);
        }
    }

    Err("Could not locate cae_trace_target.exe. Please build it first with: cargo build --bin cae_trace_target".to_string())
}

/// Controller for executing and tracing machine code directly on physical hardware.
pub struct WindowsNativeDebugger;

impl WindowsNativeDebugger {
    /// Traces the given micro-kernel inside a dedicated child process on physical silicon.
    #[cfg(windows)]
    pub fn trace_kernel(
        kernel_name: &str,
        input_value: u64,
        execution_budget: usize,
    ) -> Result<NativeTraceReport, String> {
        let target_exe = locate_target_binary()?;
        let target_path_str = target_exe.to_string_lossy().to_string();

        let cmd_line_str = format!("\"{}\" {} {}", target_path_str, kernel_name, input_value);
        let mut cmd_line_wide: Vec<u16> = cmd_line_str.encode_utf16().chain(std::iter::once(0)).collect();

        let startup_info = StartupInfoW {
            cb: std::mem::size_of::<StartupInfoW>() as u32,
            lp_reserved: std::ptr::null_mut(),
            lp_desktop: std::ptr::null_mut(),
            lp_title: std::ptr::null_mut(),
            dw_x: 0, dw_y: 0, dw_x_size: 0, dw_y_size: 0,
            dw_x_count_chars: 0, dw_y_count_chars: 0,
            dw_fill_attribute: 0, dw_flags: 0, w_show_window: 0,
            cb_reserved2: 0, lp_reserved2: std::ptr::null_mut(),
            h_std_input: std::ptr::null_mut(),
            h_std_output: std::ptr::null_mut(),
            h_std_error: std::ptr::null_mut(),
        };

        let mut proc_info = ProcessInformation {
            h_process: std::ptr::null_mut(),
            h_thread: std::ptr::null_mut(),
            dw_process_id: 0,
            dw_thread_id: 0,
        };

        const DEBUG_ONLY_THIS_PROCESS: u32 = 0x00000002;
        let success = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmd_line_wide.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                DEBUG_ONLY_THIS_PROCESS,
                std::ptr::null_mut(),
                std::ptr::null(),
                &startup_info,
                &mut proc_info,
            )
        };

        if success == 0 {
            return Err(format!("CreateProcessW failed with Windows error: {}", std::io::Error::last_os_error()));
        }

        let h_process = proc_info.h_process;
        let h_initial_thread = proc_info.h_thread;

        let mut image_base: u64 = 0;
        let mut image_size: u64 = 0x2000000; // 32MB default fallback

        let mut in_kernel = false;
        let mut trace_completed = false;
        let mut last_rip: u64 = 0;
        let mut steps = Vec::new();
        let mut final_context = ContextRecord::default();
        let mut status = NativeTraceStatus::CompletedSuccess;

        let mut event: DebugEvent = unsafe { std::mem::zeroed() };
        const DBG_CONTINUE: u32 = 0x00010002;
        const EXCEPTION_DEBUG_EVENT: u32 = 1;
        const CREATE_PROCESS_DEBUG_EVENT: u32 = 3;
        const LOAD_DLL_DEBUG_EVENT: u32 = 6;
        const STATUS_BREAKPOINT: u32 = 0x80000003;
        const STATUS_SINGLE_STEP: u32 = 0x80000004;

        let timeout_ms = 5000; // 5-second safeguard timeout

        while unsafe { WaitForDebugEvent(&mut event, timeout_ms) } != 0 {
            let code = event.dw_debug_event_code;
            let continue_status = DBG_CONTINUE;

            match code {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let offset = 24; // lpBaseOfImage in CREATE_PROCESS_DEBUG_INFO
                    let slice = &event.u[offset..offset + 8];
                    let base_ptr = u64::from_le_bytes(slice.try_into().unwrap());
                    image_base = base_ptr;

                    // Inspect PE header to determine exact SizeOfImage
                    let mut pe_buf = [0u8; 128];
                    let mut read_bytes: usize = 0;
                    if unsafe { ReadProcessMemory(h_process, image_base, pe_buf.as_mut_ptr(), 64, &mut read_bytes) } != 0 {
                        let e_lfanew = i32::from_le_bytes(pe_buf[0x3C..0x40].try_into().unwrap()) as u64;
                        if unsafe { ReadProcessMemory(h_process, image_base + e_lfanew, pe_buf.as_mut_ptr(), 120, &mut read_bytes) } != 0 {
                            // SizeOfImage in PE32+ Optional Header is at offset 24 (PE sig + file hdr) + 56 = 80
                            let size = u32::from_le_bytes(pe_buf[80..84].try_into().unwrap()) as u64;
                            if size > 0 {
                                image_size = size;
                            }
                        }
                    }

                    // Close the initial image file handle delivered in event.u[0..8]
                    let slice = &event.u[0..8];
                    let h_file = u64::from_le_bytes(slice.try_into().unwrap()) as *mut std::ffi::c_void;
                    if !h_file.is_null() {
                        unsafe { CloseHandle(h_file); }
                    }
                }

                LOAD_DLL_DEBUG_EVENT => {
                    // Close file handle for loaded DLL
                    let slice = &event.u[0..8];
                    let h_file = u64::from_le_bytes(slice.try_into().unwrap()) as *mut std::ffi::c_void;
                    if !h_file.is_null() {
                        unsafe { CloseHandle(h_file); }
                    }
                }

                EXCEPTION_DEBUG_EVENT => {
                    let exc_code = u32::from_le_bytes(event.u[0..4].try_into().unwrap());
                    let exc_addr = u64::from_le_bytes(event.u[16..24].try_into().unwrap());

                    let h_thread = unsafe { OpenThread(0x1FFFFF, 0, event.dw_thread_id) };
                    let mut ctx = ContextRecord::default();
                    if !h_thread.is_null() {
                        unsafe { GetThreadContext(h_thread, &mut ctx); }
                    }

                    let is_image_addr = exc_addr >= image_base && exc_addr < image_base + image_size;

                    if exc_code == STATUS_BREAKPOINT {
                        if !is_image_addr {
                            // NTDLL / CRT loader breakpoint. Ignore and continue execution.
                        } else if !in_kernel {
                            // Entry Trigger breakpoint reached inside target image!
                            in_kernel = true;
                            last_rip = ctx.rip; // ctx.rip points right after INT3 to the first instruction

                            // Enable Trap Flag (TF = 0x100) to single-step on physical CPU
                            ctx.eflags |= 0x100;
                            if !h_thread.is_null() {
                                unsafe { SetThreadContext(h_thread, &ctx); }
                            }
                        } else {
                            // Reached Exit Trigger breakpoint
                            trace_completed = true;
                            final_context = ctx;
                        }
                    } else if exc_code == STATUS_SINGLE_STEP && in_kernel {
                        // Physical single-step exception fired by CPU!
                        final_context = ctx;

                        // Decode the instruction that just retired at last_rip
                        let mut instr_buf = [0u8; 15];
                        let mut read_bytes: usize = 0;
                        let success_read = unsafe {
                            ReadProcessMemory(h_process, last_rip, instr_buf.as_mut_ptr(), 15, &mut read_bytes)
                        };

                        if success_read != 0 && read_bytes > 0 {
                            let mut decoder = Decoder::new(64, &instr_buf[..read_bytes], DecoderOptions::NONE);
                            decoder.set_ip(last_rip);
                            let instr = decoder.decode();

                            let mut formatter = IntelFormatter::new();
                            let mut output = String::new();
                            formatter.format(&instr, &mut output);

                            let mnemonic = format!("{:?}", instr.mnemonic()).to_lowercase();
                            let operands = if output.starts_with(&mnemonic) {
                                output[mnemonic.len()..].trim().to_string()
                            } else {
                                output
                            };

                            let bytes_len = instr.len();
                            let instr_bytes = instr_buf[..bytes_len].to_vec();

                            let regs_after = NativeTraceRegisters {
                                rax: ctx.rax, rcx: ctx.rcx, rdx: ctx.rdx, rbx: ctx.rbx,
                                rsp: ctx.rsp, rbp: ctx.rbp, rsi: ctx.rsi, rdi: ctx.rdi,
                                r8: ctx.r8, r9: ctx.r9, r10: ctx.r10, r11: ctx.r11,
                                r12: ctx.r12, r13: ctx.r13, r14: ctx.r14, r15: ctx.r15,
                                rip: ctx.rip,
                                eflags: ctx.eflags,
                            };
                            let flags_after = NativeTraceFlags::from_eflags(ctx.eflags);

                            steps.push(NativeTraceStep {
                                step_index: steps.len() + 1,
                                address: last_rip,
                                mnemonic,
                                operands_str: operands,
                                bytes: instr_bytes,
                                registers_after: regs_after,
                                flags_after,
                            });
                        }

                        // Inspect next instruction byte at ctx.rip
                        let mut next_byte = [0u8; 1];
                        unsafe {
                            ReadProcessMemory(h_process, ctx.rip, next_byte.as_mut_ptr(), 1, &mut read_bytes);
                        }

                        if next_byte[0] == 0xCC {
                            // Next instruction is the Exit Trigger (int 3)! Micro-kernel execution complete.
                            trace_completed = true;
                            ctx.eflags &= !0x100; // Clear TF
                            if !h_thread.is_null() {
                                unsafe { SetThreadContext(h_thread, &ctx); }
                            }
                        } else if steps.len() >= execution_budget {
                            trace_completed = true;
                            status = NativeTraceStatus::BudgetExhausted(execution_budget);
                            ctx.eflags &= !0x100;
                            if !h_thread.is_null() {
                                unsafe { SetThreadContext(h_thread, &ctx); }
                            }
                        } else {
                            // Re-arm hardware Trap Flag for the next step
                            last_rip = ctx.rip;
                            ctx.eflags |= 0x100;
                            if !h_thread.is_null() {
                                unsafe { SetThreadContext(h_thread, &ctx); }
                            }
                        }
                    }

                    if !h_thread.is_null() {
                        unsafe { CloseHandle(h_thread); }
                    }
                }

                _ => {}
            }

            unsafe { ContinueDebugEvent(event.dw_process_id, event.dw_thread_id, continue_status); }

            if trace_completed {
                break;
            }
        }

        // Clean up child process and primary thread
        unsafe {
            TerminateProcess(h_process, 0);
            CloseHandle(h_process);
            CloseHandle(h_initial_thread);
        }

        if !trace_completed && status == NativeTraceStatus::CompletedSuccess {
            status = NativeTraceStatus::Timeout;
        }

        let target_display = match kernel_name {
            "exp-a" => "Straight-Line Instructions",
            "exp-b" => "Conditional Branching",
            "exp-c" => "Bounded Loop Counter",
            other => other,
        };

        Ok(NativeTraceReport {
            kernel_id: kernel_name.to_uppercase(),
            target_name: target_display.to_string(),
            input_value,
            trace_mechanism: "Windows x86-64 Debug API (Physical Trap Flag TF Single-Stepping)",
            total_observed_instructions: steps.len(),
            return_value_rax: final_context.rax,
            final_registers: NativeTraceRegisters {
                rax: final_context.rax, rcx: final_context.rcx, rdx: final_context.rdx, rbx: final_context.rbx,
                rsp: final_context.rsp, rbp: final_context.rbp, rsi: final_context.rsi, rdi: final_context.rdi,
                r8: final_context.r8, r9: final_context.r9, r10: final_context.r10, r11: final_context.r11,
                r12: final_context.r12, r13: final_context.r13, r14: final_context.r14, r15: final_context.r15,
                rip: final_context.rip,
                eflags: final_context.eflags,
            },
            final_flags: NativeTraceFlags::from_eflags(final_context.eflags),
            status,
            steps,
        })
    }

    /// Fallback for non-Windows platforms.
    #[cfg(not(windows))]
    pub fn trace_kernel(
        _kernel_name: &str,
        _input_value: u64,
        _execution_budget: usize,
    ) -> Result<NativeTraceReport, String> {
        Err("Native hardware tracing via Windows Debug API is only supported on Windows".to_string())
    }
}
