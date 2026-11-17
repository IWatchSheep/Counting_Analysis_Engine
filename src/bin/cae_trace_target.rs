//! # CAE Trace Target Executable
//!
//! Dedicated target binary launched by the CAE Native Tracing Controller
//! under the Windows Debug API (`DEBUG_ONLY_THIS_PROCESS`).
//!
//! Contains isolated x86-64 micro-kernels guarded by software breakpoint triggers:
//! - Entry Trigger: `int 3` (`0xCC`)
//! - Exit Trigger: `int 3` (`0xCC`)

use std::env;
use Counting_Analysis_Engine::algorithms::{
    popcount_kernighan, popcount_naive, popcount_reference,
};

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

#[inline(never)]
#[cfg(target_arch = "x86_64")]
unsafe fn run_kernel_d(input: u64) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "int 3",            // Entry Trigger
            "xor eax, eax",     // Step 1: count = 0
            "6:",
            "test rcx, rcx",    // Step 2: if rcx == 0, exit
            "jz 7f",            // Step 3
            "test rcx, 1",      // Step 4: test lowest bit
            "jnz 7f",           // Step 5: if bit is 1, exit
            "shr rcx, 1",       // Step 6: shift right by 1
            "inc eax",          // Step 7: count++
            "jmp 6b",           // Step 8: backedge
            "7:",
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
unsafe fn run_kernel_e(input: u64) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "int 3",            // Entry Trigger
            "xor eax, eax",     // Step 1: count = 0
            "20:",
            "test rcx, rcx",    // Step 2: if rcx == 0, exit
            "jz 23f",           // Step 3
            "test rcx, 1",      // Step 4: test lowest bit
            "jz 21f",           // Step 5: if even, jump forward
            "add eax, 3",       // Step 6: odd path (+3)
            "jmp 22f",          // Step 7
            "21:",
            "add eax, 1",       // Step 8: even path (+1)
            "22:",
            "shr rcx, 1",       // Step 9: shift right by 1
            "jmp 20b",          // Step 10: backedge
            "23:",
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
unsafe fn run_kernel_f(input: u64) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "int 3",            // Entry Trigger
            "xor eax, eax",     // Step 1: count = 0
            "30:",
            "test rcx, rcx",    // Step 2: if rcx == 0, exit
            "jz 33f",           // Step 3
            "test rcx, 1",      // Step 4: test lowest bit
            "jnz 31f",          // Step 5: if odd, branch forward
            "shr rcx, 1",       // Step 6: even: shift right by 1
            "add eax, 2",       // Step 7: even: add 2
            "jmp 32f",          // Step 8
            "31:",
            "dec rcx",          // Step 9: odd: decrement rcx (making it even)
            "add eax, 5",       // Step 10: odd: add 5
            "32:",
            "jmp 30b",          // Step 11: backedge
            "33:",
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
unsafe fn run_kernel_kernighan(input: u64) -> u32 {
    let result: u32;
    unsafe {
        core::arch::asm!(
            "sub rsp, 40",
            "int 3",            // Entry Trigger
            "call {fn_ptr}",    // Call live compiled popcount_kernighan
            "int 3",            // Exit Trigger
            "add rsp, 40",
            in("rcx") input,
            fn_ptr = in(reg) popcount_kernighan as *const (),
            lateout("eax") result,
            clobber_abi("C"),
        );
    }
    result
}

#[inline(never)]
#[cfg(target_arch = "x86_64")]
unsafe fn run_kernel_naive(input: u64) -> u32 {
    let result: u32;
    unsafe {
        core::arch::asm!(
            "sub rsp, 40",
            "int 3",            // Entry Trigger
            "call {fn_ptr}",    // Call live compiled popcount_naive
            "int 3",            // Exit Trigger
            "add rsp, 40",
            in("rcx") input,
            fn_ptr = in(reg) popcount_naive as *const (),
            lateout("eax") result,
            clobber_abi("C"),
        );
    }
    result
}

#[inline(never)]
#[cfg(target_arch = "x86_64")]
unsafe fn run_kernel_reference(input: u64) -> u32 {
    let result: u32;
    unsafe {
        core::arch::asm!(
            "sub rsp, 40",
            "int 3",            // Entry Trigger
            "call {fn_ptr}",    // Call live compiled popcount_reference
            "int 3",            // Exit Trigger
            "add rsp, 40",
            in("rcx") input,
            fn_ptr = in(reg) popcount_reference as *const (),
            lateout("eax") result,
            clobber_abi("C"),
        );
    }
    result
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cae_trace_target <kernel_name> [input_value]");
        eprintln!("Available kernels: exp-a, exp-b, exp-c, exp-d, exp-e, exp-f, kernighan, naive, reference");
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
            "exp-d" => {
                let res = run_kernel_d(input);
                println!("RESULT: {}", res);
            }
            "exp-e" => {
                let res = run_kernel_e(input);
                println!("RESULT: {}", res);
            }
            "exp-f" => {
                let res = run_kernel_f(input);
                println!("RESULT: {}", res);
            }
            "kernighan" => {
                let res = run_kernel_kernighan(input);
                println!("RESULT: {}", res);
            }
            "naive" => {
                let res = run_kernel_naive(input);
                println!("RESULT: {}", res);
            }
            "reference" => {
                let res = run_kernel_reference(input);
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
