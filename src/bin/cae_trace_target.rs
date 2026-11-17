//! # CAE Trace Target Executable
//!
//! Dedicated target binary launched by the CAE Native Tracing Controller
//! under the Windows Debug API (`DEBUG_ONLY_THIS_PROCESS`).
//!
//! Contains isolated x86-64 micro-kernels guarded by software breakpoint triggers:
//! - Entry Trigger: `int 3` (`0xCC`)
//! - Exit Trigger: `int 3` (`0xCC`)

use std::env;

#[inline(never)]
#[cfg(target_arch = "x86_64")]
unsafe fn run_kernel_a(input: u64) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "int 3",            // Entry Trigger
            "mov rax, rcx",     // Step 1
            "add rax, 10",      // Step 2
            "shl rax, 1",       // Step 3
            "int 3",            // Exit Trigger
            in("rcx") input,
            out("rax") result,
            options(nostack)
        );
    }
    result
}

#[inline(never)]
#[cfg(target_arch = "x86_64")]
unsafe fn run_kernel_b(input: u64) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "int 3",            // Entry Trigger
            "test rcx, 1",
            "jnz 2f",
            "mov eax, 100",
            "jmp 3f",
            "2:",
            "mov eax, 200",
            "3:",
            "int 3",            // Exit Trigger
            in("rcx") input,
            out("rax") result,
            options(nostack)
        );
    }
    result
}

#[inline(never)]
#[cfg(target_arch = "x86_64")]
unsafe fn run_kernel_c(input: u64) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "int 3",            // Entry Trigger
            "xor eax, eax",
            "4:",
            "test rcx, rcx",
            "jz 5f",
            "add rax, rcx",
            "dec rcx",
            "jmp 4b",
            "5:",
            "int 3",            // Exit Trigger
            in("rcx") input,
            out("rax") result,
            options(nostack)
        );
    }
    result
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cae_trace_target <kernel_name> [input_value]");
        eprintln!("Available kernels: exp-a, exp-b, exp-c");
        return;
    }

    let kernel = args[1].to_lowercase();
    let input: u64 = if args.len() >= 3 {
        if args[2].starts_with("0x") || args[2].starts_with("0X") {
            u64::from_str_radix(&args[2][2..], 16).unwrap_or(0)
        } else {
            args[2].parse().unwrap_or(0)
        }
    } else {
        0
    };

    #[cfg(target_arch = "x86_64")]
    unsafe {
        match kernel.as_str() {
            "exp-a" => {
                let res = run_kernel_a(input);
                println!("RESULT: {}", res);
            }
            "exp-b" => {
                let res = run_kernel_b(input);
                println!("RESULT: {}", res);
            }
            "exp-c" => {
                let res = run_kernel_c(input);
                println!("RESULT: {}", res);
            }
            other => {
                eprintln!("Unknown kernel: {}", other);
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        eprintln!("cae_trace_target requires x86_64 architecture");
    }
}
