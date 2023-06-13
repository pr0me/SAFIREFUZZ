#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use core::{arch::asm, ptr::addr_of};

use capstone::arch::arm::{ArmOperand, ArmOperandType};
use capstone_sys::{arm_cc, arm_op_mem};

use crate::engine::{
    Timer, FUZZ_INDEX, FUZZ_INPUT, FUZZ_LEN, HOOKS_AVAIL, IRQ_ENABLED, LR, NUM_CURR_BRANCHES,
    O2N_CACHE, OFFSET, RECOMPILED_CODE, REGISTERED_HOOKS, REGISTERED_TICKS, SP, TIMERS, TRACE,
};

pub struct Hook {
    pub addr: u32,
    pub func_ptr: u32,
    pub does_return: bool,
}

impl PartialEq for Hook {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! sleep {
    ($secs:expr) => {
        let sleep_timer = std::time::Duration::from_secs($secs);
        std::thread::sleep(sleep_timer);
    };
}

pub fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

/// Exits the execution, restores engine's stack pointer and returns into `start_execution`
#[naked]
pub unsafe extern "aapcs" fn exit_hook_ok() {
    asm!(
        "mov r0, 0",
        "mov r7, #0x30000000",
        "ldr sp, [r7, #16]",
        "ldr pc, [r7, #24]",
        options(noreturn)
    )
}

/// Exits the execution, restores engine's stack pointer and returns into `start_execution` while signaling a Timeout
#[cfg(not(feature = "dbg_prints"))]
#[naked]
pub unsafe extern "aapcs" fn exit_hook_timeout() {
    asm!(
        "mov r0, 3",
        "mov r7, #0x30000000",
        "ldr sp, [r7, #16]",
        "ldr pc, [r7, #24]",
        options(noreturn)
    )
}

pub unsafe fn print_args_hook(r0: u32, r1: u32) -> u32 {
    println!("arg0: {:#x} - arg1: {:#x}", r0, r1);
    r0
}

/// Use this version to produce a real crash in order to dump the state in debug mode
#[cfg(feature = "dbg_prints")]
pub unsafe fn exit_hook_timeout() {
    core::ptr::copy_nonoverlapping(0x0 as *const _, 0xfffff432 as *mut u8, 100);
}

pub unsafe fn return_fuzz_byte() -> u8 {
    if FUZZ_INDEX < FUZZ_LEN {
        let val = FUZZ_INPUT[FUZZ_INDEX as usize] as _;
        FUZZ_INDEX += 1;
        val
    } else {
        exit_hook_ok();
        unreachable!();
    }
}

extern "C" {
    fn __clear_cache(ptr0: *const u8, ptr1: *const u8);
}

/// Invalidate the Instruction Cache
pub unsafe extern "aapcs" fn invalidate_icache(_start: u32, _end: u32) {
    __clear_cache(_start as _, _end as _);
}

#[naked]
pub unsafe extern "aapcs" fn imb(_start: u32, _end: u32) {
    asm!("SWI 0xF00001", "bx lr", options(noreturn));
}

/// Hooks the supplied address with a jump into specified function.
/// Does return upon exiting from user hook.
pub unsafe fn register_hook(addr: u32, func_ptr: *const fn()) {
    REGISTERED_HOOKS.insert(
        addr,
        Hook {
            addr,
            func_ptr: func_ptr as u32,
            does_return: true,
        },
    );
    HOOKS_AVAIL += 1;
}

/// Hooks the supplied address with a jump into specified function.
/// Does not return and retains original instructions of the hooked function.
pub unsafe fn register_hook_noreturn(addr: u32, func_ptr: *const fn()) {
    REGISTERED_HOOKS.insert(
        addr,
        Hook {
            addr,
            func_ptr: func_ptr as u32,
            does_return: false,
        },
    );
    HOOKS_AVAIL += 1;
}

/// Registers a new BLX-count based interrupt timer and returns the ID
pub unsafe fn enable_timer(rate: u32, callback: unsafe fn(), max_hits: u32) -> usize {
    let id = TIMERS.len();
    TIMERS.push(Timer {
        rate,
        callback,
        clock: 0,
        hits: 0,
        max_hits,
    });
    id
}

pub unsafe fn disable_timer(id: usize) {
    // check whether the timer even runs
    if id != 0xffffffff {
        TIMERS.remove(id);
    }
}

/// Updates the tick count and triggers registered timers if necessary
pub unsafe fn trigger_tick() {
    #[cfg(feature = "dbg_prints")]
    println!("[i] TICK");

    // disable IRQ to avoid an interrupt inside the ISR
    if IRQ_ENABLED {
        IRQ_ENABLED = false;

        for mut timer in TIMERS.iter_mut() {
            timer.clock += 1;

            if timer.clock > timer.rate {
                (timer.callback)();
                timer.clock = 0;
                timer.hits += 1;

                if timer.max_hits != 0 && timer.hits >= timer.max_hits {
                    crate::utils::exit_hook_ok();
                    unreachable!();
                }
            }
        }

        IRQ_ENABLED = true;
    }
}

#[inline(always)]
pub unsafe fn get_addr(target_addr: u32) -> u32 {
    let cache_index = (target_addr >> 1) as usize;
    O2N_CACHE[cache_index]
}

pub unsafe fn trace(orig_pc: usize, new_pc: u32, r3: u32) {
    #[cfg(feature = "dbg_prints")]
    println!(
        "\n>>> TRACING {:#x} | {:#x} | R3: {}\n",
        orig_pc,
        new_pc - RECOMPILED_CODE,
        r3
    );

    #[cfg(feature = "full_trace")]
    TRACE.push(orig_pc as _);
}

pub fn get_reg_list_str(omit: &[u8]) -> String {
    let mut reg_list = "".to_owned();
    for i in 0..=12 {
        if !omit.contains(&(i as u8)) {
            reg_list = format!("{}r{}, ", reg_list, i);
        }
    }
    // strip last comma + space
    reg_list = format!("{}lr", reg_list);
    reg_list
}

pub fn parse_reg(reg: &str) -> u8 {
    match reg {
        "r0" => 0,
        "r1" => 1,
        "r2" => 2,
        "r3" => 3,
        "r4" => 4,
        "r5" => 5,
        "r6" => 6,
        "r7" => 7,
        "r8" => 8,
        "r9" | "sb" => 9,
        "r10" | "sl" => 10,
        "r11" | "fp" => 11,
        "r12" | "ip" => 12,
        "r14" | "lr" => 13, // not a typo, stack position
        _ => panic!("unexpected register found as argument to dynamic branch"),
    }
}

#[inline(always)]
pub unsafe fn get_cs_op_reg(op: ArmOperand) -> u32 {
    match op.op_type {
        ArmOperandType::Reg(reg_op) => reg_op.0 as u32,
        ArmOperandType::Imm(imm_op)
        | ArmOperandType::Cimm(imm_op)
        | ArmOperandType::Pimm(imm_op) => imm_op as u32,
        _ => unreachable!(),
    }
}

#[inline(always)]
pub unsafe fn get_cs_op_mem(op: ArmOperand) -> capstone::arch::arm::ArmOpMem {
    match op.op_type {
        ArmOperandType::Mem(mem_op) => mem_op,
        _ => unreachable!(),
    }
}

#[inline(always)]
pub fn match_cond(cc: arm_cc) -> &'static str {
    match cc {
        arm_cc::ARM_CC_AL => "al",
        arm_cc::ARM_CC_EQ => "eq",
        arm_cc::ARM_CC_NE => "ne",
        arm_cc::ARM_CC_HS => "hs",
        arm_cc::ARM_CC_LO => "lo",
        arm_cc::ARM_CC_MI => "mi",
        arm_cc::ARM_CC_PL => "pl",
        arm_cc::ARM_CC_VS => "vs",
        arm_cc::ARM_CC_VC => "vc",
        arm_cc::ARM_CC_HI => "hi",
        arm_cc::ARM_CC_LS => "ls",
        arm_cc::ARM_CC_GE => "ge",
        arm_cc::ARM_CC_LT => "lt",
        arm_cc::ARM_CC_GT => "gt",
        arm_cc::ARM_CC_LE => "le",
        _ => unreachable!(),
    }
}

#[inline(always)]
/// Inverts the given condition code
pub fn match_cond_invert(cc: arm_cc) -> &'static str {
    match cc {
        arm_cc::ARM_CC_EQ => "ne",
        arm_cc::ARM_CC_NE => "eq",
        arm_cc::ARM_CC_HS => "lo",
        arm_cc::ARM_CC_LO => "hs",
        arm_cc::ARM_CC_MI => "pl",
        arm_cc::ARM_CC_PL => "mi",
        arm_cc::ARM_CC_VS => "vc",
        arm_cc::ARM_CC_VC => "vs",
        arm_cc::ARM_CC_HI => "ls",
        arm_cc::ARM_CC_LS => "hi",
        arm_cc::ARM_CC_GE => "lt",
        arm_cc::ARM_CC_LT => "ge",
        arm_cc::ARM_CC_GT => "le",
        arm_cc::ARM_CC_LE => "gt",
        _ => unreachable!(),
    }
}
