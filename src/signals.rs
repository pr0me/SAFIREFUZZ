#[cfg(feature = "full_trace")]
use crate::engine::TRACE;
use crate::engine::{NUM_CURR_REWRITES, NUM_EXECS, RECOMPILED_CODE, RECOMPILED_CODE_TOP};
use crate::handlers::MALLOC_CHUNK_TOP;

// use libc::ucontext_t; // yea this isn't implemented for arm32
use libc::{c_int, c_ulong, c_void, size_t};
use nix::sys::signal;
use nix::Error;

use std::fs::File;
use std::io::Write;
use std::process;
use std::ptr;

pub struct Stack {
    pub ss_sp: *mut c_void,
    pub ss_flags: c_int,
    pub ss_size: size_t,
}

// sigcontext == mcontext_t for ARM
pub struct SigContext {
    pub trap_no: c_ulong,
    pub error_code: c_ulong,
    pub oldmask: c_ulong,
    pub arm_r0: c_ulong,
    pub arm_r1: c_ulong,
    pub arm_r2: c_ulong,
    pub arm_r3: c_ulong,
    pub arm_r4: c_ulong,
    pub arm_r5: c_ulong,
    pub arm_r6: c_ulong,
    pub arm_r7: c_ulong,
    pub arm_r8: c_ulong,
    pub arm_r9: c_ulong,
    pub arm_r10: c_ulong,
    pub arm_fp: c_ulong,
    pub arm_ip: c_ulong,
    pub arm_sp: c_ulong,
    pub arm_lr: c_ulong,
    pub arm_pc: c_ulong,
    pub arm_cpsr: c_ulong,
    pub fault_address: c_ulong,
}

pub struct UContext {
    pub uc_flags: u32,
    pub uc_link: *mut UContext,
    pub uc_stack: Stack,
    pub uc_mcontext: SigContext,
    pub uc_sigmask: nix::sys::signal::SigSet,
}

pub extern "C" fn handle_sig(
    _: libc::c_int,
    siginfo: *mut libc::siginfo_t,
    context_ptr: *mut libc::c_void,
) {
    unsafe {
        let curr_context = &mut *(context_ptr as *mut UContext);
        let curr_siginfo = &mut *(siginfo as *mut libc::siginfo_t);

        let sig_type = match curr_siginfo.si_signo {
            2 => "SIGINT",
            4 => "SIGILL",
            7 => "SIGBUS",
            11 => "SIGSEGV",
            _ => "UNKNOWN",
        };

        println!(
            "\n[!] {}\n    PC: {:#x}\n    fault at {:#x}\n    BB rewrites: {}",
            sig_type,
            curr_context.uc_mcontext.arm_pc,
            curr_context.uc_mcontext.fault_address,
            NUM_CURR_REWRITES
        );

        println!("[1] Register Contents:");
        println!(
            "    r0: {:#010x} r1: {:#010x}
    r2: {:#010x} r3: {:#010x}
    r4: {:#010x} r5: {:#010x}
    r6: {:#010x} r7: {:#010x}
    r8: {:#010x} r9: {:#010x}
    r10: {:#010x} r11: {:#010x}
    lr: {:#010x}",
            curr_context.uc_mcontext.arm_r0,
            curr_context.uc_mcontext.arm_r1,
            curr_context.uc_mcontext.arm_r2,
            curr_context.uc_mcontext.arm_r3,
            curr_context.uc_mcontext.arm_r4,
            curr_context.uc_mcontext.arm_r5,
            curr_context.uc_mcontext.arm_r6,
            curr_context.uc_mcontext.arm_r7,
            curr_context.uc_mcontext.arm_r8,
            curr_context.uc_mcontext.arm_r9,
            curr_context.uc_mcontext.arm_r10,
            curr_context.uc_mcontext.arm_fp,
            curr_context.uc_mcontext.arm_lr
        );
        println!("    Base Address: {:#x}", RECOMPILED_CODE);
        println!("    Executions:  {}\n", NUM_EXECS);
        println!(
            "    Malloc Area:  {:#x} - {:#x}\n",
            MALLOC_CHUNK_TOP - 32 * 1000000,
            MALLOC_CHUNK_TOP
        );
        #[cfg(feature = "full_trace")]
        {
            let mut f = File::create("trace.dump").expect("Unable to create file");
            for i in &TRACE {
                writeln!(f, "{:#x}", i).unwrap();
            }
        }

        let mut file = File::create("./rewrite.bin").expect("Failed to create output file.");
        let size = (RECOMPILED_CODE_TOP - RECOMPILED_CODE) as usize;
        let mut code: Vec<u8> = Vec::with_capacity(size);
        ptr::copy(RECOMPILED_CODE as _, code.as_mut_ptr(), size);
        code.set_len(size);
        file.write_all(&code).expect("Failed to write to file");

        process::abort();
    }
}

/// Register custom debugging signal handlers
pub unsafe fn init_sig_handlers() -> Result<(), Error> {
    let sig_action = signal::SigAction::new(
        signal::SigHandler::SigAction(handle_sig),
        signal::SaFlags::SA_NODEFER,
        signal::SigSet::empty(),
    );

    signal::sigaction(signal::SIGILL, &sig_action)?;
    signal::sigaction(signal::SIGSEGV, &sig_action)?;
    signal::sigaction(signal::SIGINT, &sig_action)?;
    signal::sigaction(signal::SIGBUS, &sig_action)?;

    Ok(())
}

#[repr(C)]
pub struct SigStack {
    ss_sp: *const libc::c_void,
    ss_onstack: libc::c_int,
}

pub extern "C" fn timeout_handler(
    _: libc::c_int,
    _siginfo: *mut libc::siginfo_t,
    context_ptr: *mut c_void,
) {
    unsafe {
        println!("XYXY");
        (*(context_ptr as *mut libafl::bolts::os::unix_signals::ucontext_t)).uc_link =
            context_ptr as *mut libafl::bolts::os::unix_signals::ucontext_t;
        println!(
            "{:#x?}",
            (*(context_ptr as *mut libafl::bolts::os::unix_signals::ucontext_t)).uc_link
        );

        (*(context_ptr as *mut libafl::bolts::os::unix_signals::ucontext_t))
            .uc_mcontext
            .arm_pc = crate::utils::exit_hook_timeout as *const fn() as c_ulong;
        println!(
            "{:#x}",
            (*(context_ptr as *mut libafl::bolts::os::unix_signals::ucontext_t))
                .uc_mcontext
                .arm_pc
        );
    }
}

extern "C" {
    fn sigstack(stack: *const SigStack, old_stack: *mut SigStack);
}

/// Reset state and continue instead of restarting the whole process on timeout (WIP)
pub unsafe fn continue_on_timeout() -> Result<(), Error> {
    let signal_stack_ptr = libc::mmap(
        // (OFFSET + 0x1000000) as _,
        0 as _,
        4096,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED,
        -1,
        0,
    );
    let new_stack = SigStack {
        ss_sp: signal_stack_ptr,
        ss_onstack: 1,
    };
    let null_stack: *mut SigStack = core::ptr::null_mut();
    sigstack(core::ptr::addr_of!(new_stack), null_stack);

    let sig_action = signal::SigAction::new(
        signal::SigHandler::SigAction(timeout_handler),
        signal::SaFlags::SA_SIGINFO | signal::SaFlags::SA_ONSTACK,
        signal::SigSet::empty(),
    );
    signal::sigaction(signal::SIGALRM, &sig_action)?;

    Ok(())
}
