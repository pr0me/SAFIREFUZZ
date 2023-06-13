use crate::harness::libjpeg_decoding as harness;
#[cfg(feature = "dbg_prints")]
use crate::signals;
use crate::utils::{
    get_addr, get_cs_op_mem, get_cs_op_reg, invalidate_icache, match_cond, match_cond_invert,
    parse_reg, trace, trigger_tick, Hook,
};

extern crate serde_json;

use capstone::{arch::arm::ArmInsn, prelude::*};
use capstone_sys::arm_cc;
use core::{arch::asm, ptr};
use keystone::{Arch, Keystone, Mode};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::io::Error;
use std::time::SystemTime;

// ENGINE GLOBALS
const MAP_SIZE: usize = 8 * 1024;
pub static mut COV_AREA_PTR: [u8; MAP_SIZE] = [0; MAP_SIZE];
static mut PREVIOUS_PC: usize = 0;
pub static mut LR: u32 = 0;
pub static mut SP: u32 = 0;
pub static mut OFFSET: u32 = 0xffffffff;

pub static mut START_TIME: SystemTime = SystemTime::UNIX_EPOCH;
pub static mut NUM_EXECS: u32 = 0;
pub static mut FUZZ_INPUT: Vec<u8> = Vec::new();
pub static mut FUZZ_LEN: u32 = 0;
pub static mut FUZZ_INDEX: u32 = 0;
static mut NEXT_BLOCK_ID: u16 = 0;
pub static mut NUM_CURR_BRANCHES: u32 = 0;

pub static mut IRQ_ENABLED: bool = false;
pub static mut TIMERS: Vec<Timer> = Vec::new();
pub static mut HOOKS_AVAIL: u16 = 0;
pub static mut REGISTERED_HOOKS: BTreeMap<u32, Hook> = BTreeMap::new();
pub static mut REGISTERED_TICKS: Vec<usize> = Vec::new();

pub static mut RECOMPILED_CODE: u32 = 0;
pub static mut RECOMPILED_CODE_TOP: u32 = 0;
pub static mut BINARY: Vec<u8> = Vec::new();
pub static mut ENTRY: u32 = 0;
pub static mut O2N_CACHE: [u32; 1_000_000] = [0; 1_000_000];
pub static mut NUM_CURR_REWRITES: usize = 0;
static mut TRACE_FN_PTR: u32 = 0;
pub static mut REWRITE_FN_PTR: u32 = 0;
static mut REWRITE_FN_PTR_W: u16 = 0;
static mut REWRITE_FN_PTR_T: u16 = 0;
static mut RESOLVE_BRANCH_FN_PTR: u32 = 0;
static mut RESOLVE_BRANCH_FN_PTR_W: u16 = 0;
static mut RESOLVE_BRANCH_FN_PTR_T: u16 = 0;
static mut RESOLVE_BLX_FN_PTR: u32 = 0;
static mut RESOLVE_BLX_FN_PTR_W: u16 = 0;
static mut RESOLVE_BLX_FN_PTR_T: u16 = 0;
static mut RESOLVE_TB_FN_PTR: u32 = 0;
static mut RESOLVE_TB_FN_PTR_W: u16 = 0;
static mut RESOLVE_TB_FN_PTR_T: u16 = 0;
static mut TRIGGER_TICK_FN_PTR: u32 = 0;
static mut CONDITION_CODES: BTreeMap<usize, String> = BTreeMap::new();
static mut CS_ENGINE: RefCell<Option<Capstone>> = RefCell::new(None);
static mut KS_ENGINE: RefCell<Option<Keystone>> = RefCell::new(None);
static mut BW_CACHE: [[u8; 4]; 16_000_000] = [[0, 0, 0, 0]; 16_000_000];
static mut BX_CONT_CACHE: [u32; 1_000_000] = [0; 1_000_000];
static mut TB_INDEX_CACHE: [u32; 100_000] = [0; 100_000];
static mut LD_PAD_CACHE: [u8; 1_000_000] = [0; 1_000_000];
static mut NOP_88_INSN_BYTES: Vec<u8> = Vec::new();
static mut NOP_70_INSN_BYTES: Vec<u8> = Vec::new();
static mut NOP_66_INSN_BYTES: Vec<u8> = Vec::new();
static mut BLX_R7_INSN_BYTES: Vec<u8> = Vec::new();
static mut BRANCH_PREAMBLE_BYTES: Vec<u8> = Vec::new();
static mut BRANCH_POSTAMBLE_BYTES: Vec<u8> = Vec::new();
static mut BLX_PREAMBLE_BYTES: Vec<u8> = Vec::new();
static mut POP_ALL_BYTES: Vec<u8> = Vec::new();
static mut HOOK_RET_BYTES: Vec<u8> = Vec::new();

pub static mut TRACE: Vec<u32> = Vec::new();
pub static mut LAST_TRACE: Vec<u32> = Vec::new();

trait Split {
    fn split(&self) -> (u16, u16);
}

impl Split for u32 {
    #[inline(always)]
    fn split(&self) -> (u16, u16) {
        let w: u16 = (self & 0xffff) as u16;
        let t: u16 = (self >> 16) as u16;
        (w, t)
    }
}

/// Timer / Interrupt, deterministically triggering a callback
#[derive(Debug)]
pub struct Timer {
    pub rate: u32,
    pub callback: unsafe fn(),
    pub clock: u32,
    pub hits: u32,
    pub max_hits: u32,
}

/// Describes context of IT-block
#[derive(Debug)]
struct ITBlock {
    /// are we currently inside an IT block?
    pub is_open: bool,
    /// condition code of original IT insn
    pub cc: arm_cc,
    /// encodes number and cond of insns (e.g., `ITTE eq` => ['eq', 'eq', 'ne'])
    pub conditions: Vec<String>,
    /// current position in multi-instruction IT block
    pub counter: usize,
}

/// Lift PC-dependent instructions to be executed at new code site and insert user hooks
pub unsafe fn rewrite_bb(target_bb_addr: u32) -> u32 {
    let begin_recompiled_block = RECOMPILED_CODE_TOP;
    {
        let cache_index = (target_bb_addr >> 1) as usize;
        if O2N_CACHE[cache_index] == 0 {
            // get this from cmd args at some point in the future
            let base = 0;
            let offset = target_bb_addr - base;

            #[cfg(feature = "dbg_prints")]
            println!(
                "[!] NEW BASIC BLOCK TO BE LOCATED AT {:#x} (orig: {:#x})",
                begin_recompiled_block - RECOMPILED_CODE,
                target_bb_addr
            );

            let cs_ref = CS_ENGINE.borrow();
            let cs = cs_ref.as_ref().unwrap();

            let ks_ref = KS_ENGINE.borrow();
            let ks = ks_ref.as_ref().unwrap();

            let mut is_first_insn: bool;

            let mut block_offset = offset as usize;
            'outer: loop {
                let insn = cs
                    .disasm_count(&BINARY[block_offset..], block_offset as _, 8)
                    .unwrap();

                let mut curr_it_block: ITBlock = ITBlock {
                    is_open: false,
                    cc: arm_cc::ARM_CC_AL,
                    conditions: Vec::new(),
                    counter: 0,
                };
                is_first_insn = true;

                for i in insn.as_ref() {
                    let insn_id = i.id().0;

                    let detail: InsnDetail = cs.insn_detail(i).expect("Failed to get insn detail");

                    let curr_addr: usize = i.address() as _;
                    let (curr_addr_w, curr_addr_t) = (curr_addr as u32).split();
                    let op = i.op_str().unwrap();
                    let arch_detail = detail.arch_detail();
                    let arm_detail = arch_detail.arm().unwrap();
                    let mut ops = arm_detail.operands();
                    let cc = arm_detail.cc();
                    let cond = match_cond(cc);

                    // handle hooks
                    if HOOKS_AVAIL > 0 {
                        match REGISTERED_HOOKS.get(&(curr_addr as u32)) {
                            Some(curr_hook) => {
                                let mut shell_code: Vec<u8> = Vec::new();

                                let (target_fn_ptr_w, target_fn_ptr_t) = curr_hook.func_ptr.split();

                                if curr_hook.does_return {
                                    shell_code.append(
                                        &mut ks
                                            .asm(
                                                format!(
                                                    "push {{r1-r11, lr}}
                                                    movw r7, {}
                                                    movt r7, {}
                                                    add r9, sp, 48",
                                                    target_fn_ptr_w, target_fn_ptr_t
                                                ),
                                                0,
                                            )
                                            .unwrap()
                                            .bytes,
                                    );

                                    shell_code.extend(&BLX_R7_INSN_BYTES);
                                    // pop {r1-r11, lr}
                                    shell_code.extend(&[0xbd, 0xe8, 0xfe, 0x4f]);

                                    // return: BX LR
                                    shell_code.extend(&[0x70, 0x47]);

                                    let len = shell_code.len();
                                    ptr::copy_nonoverlapping(
                                        shell_code.as_ptr() as *const u8,
                                        RECOMPILED_CODE_TOP as *mut u8,
                                        len,
                                    );
                                    RECOMPILED_CODE_TOP += len as u32;

                                    O2N_CACHE[cache_index] = begin_recompiled_block;

                                    break 'outer;
                                } else {
                                    shell_code.append(
                                        &mut ks
                                            .asm(
                                                format!(
                                                    "push {{r0-r12, lr}}
                                                    movw r7, {}
                                                    movt r7, {}
                                                    add r9, sp, 48",
                                                    target_fn_ptr_w, target_fn_ptr_t
                                                ),
                                                0,
                                            )
                                            .unwrap()
                                            .bytes,
                                    );

                                    shell_code.extend(&BLX_R7_INSN_BYTES);
                                    // pop {r0-r12, lr}
                                    shell_code.extend(&[0xbd, 0xe8, 0xff, 0x5f]);

                                    // no-return hook: do not close block, copy original instructions
                                    let len = shell_code.len();
                                    ptr::copy_nonoverlapping(
                                        shell_code.as_ptr() as *const u8,
                                        RECOMPILED_CODE_TOP as *mut u8,
                                        len,
                                    );
                                    RECOMPILED_CODE_TOP += len as u32;
                                }

                                HOOKS_AVAIL -= 1;
                            }
                            None => (),
                        }
                    }

                    // if conditional block is commencing, disassemble again to capture full scope
                    if insn_id == ArmInsn::ARM_INS_IT as u32 {
                        if !is_first_insn {
                            break;
                        } else {
                            curr_it_block.is_open = true;
                            curr_it_block.cc = cc;
                            curr_it_block.conditions.clear();
                            for c in i.mnemonic().unwrap_unchecked().chars() {
                                if c == 't' {
                                    curr_it_block.conditions.push(cond.to_string());
                                } else if c == 'e' {
                                    let inverse_cond = match_cond_invert(cc);
                                    curr_it_block.conditions.push(inverse_cond.to_string());
                                }
                            }
                            // skip original IT instruction
                            block_offset += i.bytes().len();
                            continue;
                        }
                    }

                    block_offset += i.bytes().len();
                    is_first_insn = false;

                    // lift instructions
                    if insn_id == ArmInsn::ARM_INS_LDR as u32
                        || insn_id == ArmInsn::ARM_INS_VLDR as u32
                    {
                        let tmp_op = ops.next().unwrap();
                        let rt_op = get_cs_op_reg(tmp_op);
                        let tmp_op = ops.next().unwrap();
                        let mem_op = get_cs_op_mem(tmp_op);

                        // rewrite PC(Reg(11))-relative loads
                        if mem_op.base() == 11_u32.try_into().unwrap_unchecked() {
                            #[cfg(feature = "dbg_prints")]
                            println!("[i] patching insn: {}", i);
                            let rt = &op[0..2];

                            // decode offset
                            let index: i32 = mem_op.disp() * mem_op.scale();

                            // word-align offset
                            let mut target = (curr_addr as i64 + 4 + index as i64) as u32;
                            target = target - (target % 4);
                            let (target_w, target_t) = target.split();

                            let mut shell_code: Vec<u8> = Vec::new();
                            // handle conditional ldr ('it' insn)
                            if curr_it_block.is_open {
                                let asm_str = if insn_id == ArmInsn::ARM_INS_VLDR as u32 {
                                    format!(
                                        "push {{r0}}
                                        itt {0}
                                        mov r0, {2}
                                        vldr {1}, [r0]
                                        pop {{r0}}",
                                        curr_it_block.conditions[curr_it_block.counter], rt, target
                                    )
                                } else {
                                    format!(
                                        "itt {0}
                                        mov {1}, {2}
                                        ldr {1}, [{1}]",
                                        curr_it_block.conditions[curr_it_block.counter], rt, target
                                    )
                                };

                                shell_code.append(&mut ks.asm(asm_str, 0).unwrap().bytes);

                                curr_it_block.counter += 1;
                                if curr_it_block.counter == curr_it_block.conditions.len() {
                                    curr_it_block.is_open = false;
                                }

                                let len = shell_code.len();
                                ptr::copy_nonoverlapping(
                                    shell_code.as_ptr() as *const u8,
                                    (RECOMPILED_CODE_TOP) as *mut u8,
                                    len,
                                );

                                RECOMPILED_CODE_TOP += len as u32;
                            } else {
                                let asm_str = if insn_id == ArmInsn::ARM_INS_VLDR as u32 {
                                    format!(
                                        "push {{r0}}
                                        movw r0, {1}
                                        movt r0, {2}
                                        vldr {0}, [r0]
                                        pop {{r0}}",
                                        rt, target_w, target_t
                                    )
                                } else {
                                    if target > 65535 {
                                        format!(
                                            "movw {0}, {1}
                                            movt {0}, {2}
                                            ldr {0}, [{0}]",
                                            rt, target_w, target_t
                                        )
                                    } else {
                                        format!(
                                            "mov {0}, {1}
                                            ldr {0}, [{0}]",
                                            rt, target
                                        )
                                    }
                                };

                                shell_code.append(&mut ks.asm(asm_str, 0).unwrap().bytes);
                                let len = shell_code.len();
                                ptr::copy_nonoverlapping(
                                    shell_code.as_ptr() as *const u8,
                                    RECOMPILED_CODE_TOP as *mut u8,
                                    len,
                                );
                                RECOMPILED_CODE_TOP += len as u32;
                            }
                        } else if rt_op == 11
                            && mem_op.base() != 12_u32.try_into().unwrap_unchecked()
                        {
                            // [r2, r3, lsl #2]
                            let ld_addr_op = &op[4..];
                            // r2, r3, lsl #2
                            let ld_addr_op_raw = &op[5..(op.len() - 1)];

                            let (resolve_ld_pc_ptr_w, resolve_ld_pc_ptr_t) =
                                (resolve_ld_pc as *const fn() as u32).split();

                            let mut shell_code: Vec<u8> = Vec::new();

                            shell_code.append(
                                &mut ks
                                    .asm(
                                        format!(
                                            "push {{r0-r12, lr}}
                                            add r0, {}
                                            ldr r1, [r0]
                                            mrs r2, APSR
                                            push {{r2}}
                                            mov r2, pc
                                            movw r7, {}
                                            movt r7, {}
                                            blx r7
                                            pop {{r0}}
                                            msr APSR_nzcvq, r0
                                            pop {{r0-r12, lr}}
                                            ldr pc, {}",
                                            ld_addr_op_raw,
                                            resolve_ld_pc_ptr_w,
                                            resolve_ld_pc_ptr_t,
                                            ld_addr_op
                                        ),
                                        0,
                                    )
                                    .unwrap()
                                    .bytes,
                            );

                            let len = shell_code.len();
                            ptr::copy_nonoverlapping(
                                shell_code.as_ptr() as *const u8,
                                RECOMPILED_CODE_TOP as *mut u8,
                                len,
                            );
                            RECOMPILED_CODE_TOP += len as u32 + 32;

                            O2N_CACHE[cache_index] = begin_recompiled_block;

                            break 'outer;
                        } else {
                            if curr_it_block.is_open {
                                let it_insn = &mut ks
                                    .asm(
                                        format!(
                                            "it {}",
                                            curr_it_block.conditions[curr_it_block.counter]
                                        ),
                                        0,
                                    )
                                    .unwrap()
                                    .bytes;

                                ptr::copy_nonoverlapping(
                                    it_insn.as_ptr() as *const u8,
                                    RECOMPILED_CODE_TOP as *mut u8,
                                    2,
                                );
                                RECOMPILED_CODE_TOP += 2_u32;

                                curr_it_block.counter += 1;

                                if curr_it_block.counter == curr_it_block.conditions.len() {
                                    curr_it_block.is_open = false;
                                }
                            }

                            let len = i.bytes().len();
                            ptr::copy_nonoverlapping(
                                i.bytes().as_ptr() as *const u8,
                                RECOMPILED_CODE_TOP as *mut u8,
                                len,
                            );
                            RECOMPILED_CODE_TOP += len as u32;
                        }
                    } else if insn_id == ArmInsn::ARM_INS_ADR as u32 {
                        #[cfg(feature = "dbg_prints")]
                        println!("[i] patching insn: {}", i);

                        let operands = &op
                            .split(|c: char| !(c.is_alphanumeric()))
                            .collect::<Vec<&str>>();
                        let rd = operands[0];

                        let tmp_op = ops.nth(1).unwrap();
                        let mut addr_offset = get_cs_op_reg(tmp_op) as i32 + 4;

                        // label must be word-aligned (based on initial pc) for 16bit instruction
                        if i.bytes().len() == 2 && (curr_addr + addr_offset as usize) % 4 != 0 {
                            addr_offset -= 2;
                        }

                        let mut shell_code: Vec<u8> = Vec::new();
                        shell_code.append(
                            &mut ks
                                .asm(
                                    format!(
                                        "movw {0}, {1}
                                        movt {0}, {2}
                                        add {0}, #{3}",
                                        rd, curr_addr_w, curr_addr_t, addr_offset
                                    ),
                                    0,
                                )
                                .unwrap()
                                .bytes,
                        );

                        let len = shell_code.len();
                        ptr::copy_nonoverlapping(
                            shell_code.as_ptr() as *const u8,
                            RECOMPILED_CODE_TOP as *mut u8,
                            len,
                        );
                        RECOMPILED_CODE_TOP += len as u32;
                    } else if insn_id == ArmInsn::ARM_INS_MOV as u32 && &op[0..2] == "pc" {
                        let mut shell_code: Vec<u8> = Vec::new();
                        let blx_reg = &i.op_str().unwrap()[4..];
                        let reg_idx = parse_reg(blx_reg);

                        // save target reg
                        shell_code.append(
                            &mut ks
                                .asm(
                                    format!(
                                        "push {{r0-r12, lr}}
                                        push {{{}}}",
                                        blx_reg
                                    ),
                                    0,
                                )
                                .unwrap()
                                .bytes,
                        );

                        shell_code.extend(&BLX_PREAMBLE_BYTES);

                        shell_code.append(
                            &mut ks
                                .asm(
                                    format!(
                                        "movw r1, {}
                                        movt r1, {}
                                        mov r2, pc
                                        movw r7, {}
                                        movt r7, {}",
                                        curr_addr_w,
                                        curr_addr_t,
                                        RESOLVE_BLX_FN_PTR_W,
                                        RESOLVE_BLX_FN_PTR_T
                                    ),
                                    0,
                                )
                                .unwrap()
                                .bytes,
                        );

                        shell_code.extend(&BLX_R7_INSN_BYTES);

                        let stack_offset = 4 + reg_idx * 4;
                        shell_code.append(
                            &mut ks
                                .asm(format!("str r0, [sp, #{}]", stack_offset), 0)
                                .unwrap()
                                .bytes,
                        );

                        shell_code.extend(&BRANCH_POSTAMBLE_BYTES);

                        let len = shell_code.len();
                        ptr::copy_nonoverlapping(
                            shell_code.as_ptr() as *const u8,
                            RECOMPILED_CODE_TOP as *mut u8,
                            len,
                        );

                        RECOMPILED_CODE_TOP += len as u32;

                        let len = i.bytes().len();
                        ptr::copy_nonoverlapping(
                            i.bytes().as_ptr() as *const u8,
                            RECOMPILED_CODE_TOP as *mut u8,
                            len,
                        );
                        RECOMPILED_CODE_TOP += len as u32 + 16;

                        O2N_CACHE[cache_index] = begin_recompiled_block;

                        break 'outer;
                    } else if insn_id == ArmInsn::ARM_INS_B as u32
                        || insn_id == ArmInsn::ARM_INS_CBZ as u32
                        || insn_id == ArmInsn::ARM_INS_CBNZ as u32
                    {
                        #[cfg(feature = "dbg_prints")]
                        println!("[i] patching insn: {}", i);

                        // we need at least 4 for an unconditional B
                        let mut num_patch_bytes_required = 4;
                        let mut shell_code: Vec<u8> = Vec::new();

                        // save cond flags from APSR
                        shell_code.extend(&BRANCH_PREAMBLE_BYTES);

                        let branch_target: u32 = if insn_id == ArmInsn::ARM_INS_B as u32 {
                            let tmp_op = ops.next().unwrap();
                            get_cs_op_reg(tmp_op) as u32
                        } else {
                            u32::from_str_radix(&i.op_str().unwrap()[7..], 16).unwrap()
                        };

                        let (branch_target_w, branch_target_t) = branch_target.split();

                        shell_code.append(
                            &mut ks
                                .asm(
                                    format!(
                                        "movw r0, {}
                                        movt r0, {}
                                        movw r7, {}
                                        movt r7, {}",
                                        branch_target_w,
                                        branch_target_t,
                                        REWRITE_FN_PTR_W,
                                        REWRITE_FN_PTR_T
                                    ),
                                    0,
                                )
                                .unwrap()
                                .bytes,
                        );
                        shell_code.extend(&BLX_R7_INSN_BYTES);

                        let mut tmp_branch_target = branch_target;
                        // if we are not dealing with unconditional branch, also rewrite successive basic block
                        if !(insn_id == ArmInsn::ARM_INS_B as u32 && cc == arm_cc::ARM_CC_AL) {
                            // encode the fact that the insn is conditional (through `IT`) in LSB
                            if curr_it_block.is_open {
                                tmp_branch_target += 1;
                                CONDITION_CODES.insert(
                                    curr_addr,
                                    curr_it_block.conditions[curr_it_block.counter].clone(),
                                );
                            }

                            let (tmp_addr_w, tmp_addr_t) =
                                ((curr_addr + i.bytes().len()) as u32).split();

                            shell_code.append(
                                &mut ks
                                    .asm(
                                        format!(
                                            "movw r0, {}
                                            movt r0, {}
                                            movw r7, {}
                                            movt r7, {}",
                                            tmp_addr_w,
                                            tmp_addr_t,
                                            REWRITE_FN_PTR_W,
                                            REWRITE_FN_PTR_T
                                        ),
                                        0,
                                    )
                                    .unwrap()
                                    .bytes,
                            );

                            shell_code.extend(&BLX_R7_INSN_BYTES);

                            // upper bound: 8 for CBZ, 4 for branch to direct successor, 24 for cov map update
                            num_patch_bytes_required += 8 + 4 + 24;
                            #[cfg(feature = "dbg_prints")]
                            {
                                // 52 total for trace() call
                                num_patch_bytes_required += 28;
                            }
                        }

                        let (b_target_w, b_target_t) = tmp_branch_target.split();
                        shell_code.append(
                            &mut ks
                                .asm(
                                    format!(
                                        "movw r0, {}
                                        movt r0, {}
                                        movw r1, {}
                                        movt r1, {}
                                        mov r2, pc
                                        movw r7, {}
                                        movt r7, {}",
                                        b_target_w,
                                        b_target_t,
                                        curr_addr_w,
                                        curr_addr_t,
                                        RESOLVE_BRANCH_FN_PTR_W,
                                        RESOLVE_BRANCH_FN_PTR_T
                                    ),
                                    0,
                                )
                                .unwrap()
                                .bytes,
                        );

                        shell_code.extend(&BLX_R7_INSN_BYTES);

                        // trap in GDB
                        if cfg!(feature = "trap") {
                            shell_code.push(0xf0_u8);
                            shell_code.push(0xf7_u8);
                            shell_code.push(0x00_u8);
                            shell_code.push(0xa0_u8);
                        } else {
                            shell_code.push(0x00_u8);
                            shell_code.push(0xbf_u8);
                            shell_code.push(0x00_u8);
                            shell_code.push(0xbf_u8);
                        }

                        // restore cond flags to APSR
                        shell_code.extend(&BRANCH_POSTAMBLE_BYTES);

                        let len = shell_code.len();

                        ptr::copy_nonoverlapping(
                            shell_code.as_ptr() as *const u8,
                            RECOMPILED_CODE_TOP as *mut u8,
                            len,
                        );
                        // leave space for when we patch in resolved jumps
                        RECOMPILED_CODE_TOP += len as u32 + num_patch_bytes_required;

                        O2N_CACHE[cache_index] = begin_recompiled_block;

                        break 'outer;
                    } else if insn_id == ArmInsn::ARM_INS_BL as u32 {
                        #[cfg(feature = "dbg_prints")]
                        println!("[i] patching insn: {}", i);

                        let mut shell_code: Vec<u8> = Vec::new();

                        // save cond flags from APSR
                        shell_code.extend(&BRANCH_PREAMBLE_BYTES);

                        let tmp_op = ops.next().unwrap();
                        let branch_target = get_cs_op_reg(tmp_op) as u32;

                        let (branch_target_w, branch_target_t) = branch_target.split();

                        // OPT TODO: check whether mov can be done in one insn
                        shell_code.append(
                            &mut ks
                                .asm(
                                    format!(
                                        "movw r0, {}
                                        movt r0, {}
                                        movw r7, {}
                                        movt r7, {}",
                                        branch_target_w,
                                        branch_target_t,
                                        REWRITE_FN_PTR_W,
                                        REWRITE_FN_PTR_T
                                    ),
                                    0,
                                )
                                .unwrap()
                                .bytes,
                        );
                        shell_code.extend(&BLX_R7_INSN_BYTES);

                        shell_code.append(
                            &mut ks
                                .asm(
                                    format!(
                                        "movw r0, {}
                                        movt r0, {}
                                        movw r1, {}
                                        movt r1, {}
                                        mov r2, pc
                                        movw r7, {}
                                        movt r7, {}",
                                        branch_target_w,
                                        branch_target_t,
                                        curr_addr_w,
                                        curr_addr_t,
                                        RESOLVE_BRANCH_FN_PTR_W,
                                        RESOLVE_BRANCH_FN_PTR_T
                                    ),
                                    0,
                                )
                                .unwrap()
                                .bytes,
                        );

                        shell_code.extend(&BLX_R7_INSN_BYTES);

                        // restore cond flags to APSR
                        shell_code.extend(&BRANCH_POSTAMBLE_BYTES);

                        // log PC
                        shell_code.append(
                            &mut ks
                                .asm(
                                    format!(
                                        "push {{r6, r7}}
                                        mov r7, {}
                                        movw r6, {}
                                        movt r6, {}
                                        str r6, [r7]
                                        pop {{r6, r7}}",
                                        RECOMPILED_CODE, curr_addr_w, curr_addr_t
                                    ),
                                    0,
                                )
                                .unwrap()
                                .bytes,
                        );

                        let len = shell_code.len();
                        ptr::copy_nonoverlapping(
                            shell_code.as_ptr() as *const u8,
                            RECOMPILED_CODE_TOP as *mut u8,
                            len,
                        );
                        // leave space for when we patch in resolved jumps
                        RECOMPILED_CODE_TOP += len as u32 + 4;
                    } else if insn_id == ArmInsn::ARM_INS_BLX as u32
                        || (insn_id == ArmInsn::ARM_INS_BX as u32 && !op.contains("lr"))
                    {
                        #[cfg(feature = "dbg_prints")]
                        println!("[i] patching insn: {}", i);

                        let mut shell_code: Vec<u8> = Vec::new();
                        let blx_reg = i.op_str().unwrap();
                        let reg_idx = parse_reg(blx_reg);

                        // save BLX operand
                        shell_code.append(
                            &mut ks
                                .asm(
                                    format!(
                                        "push {{r0-r12, lr}}
                                        push {{{}}}",
                                        blx_reg
                                    ),
                                    0,
                                )
                                .unwrap()
                                .bytes,
                        );

                        shell_code.extend(&BLX_PREAMBLE_BYTES);

                        shell_code.append(
                            &mut ks
                                .asm(
                                    format!(
                                        "movw r1, {}
                                        movt r1, {}
                                        mov r2, pc
                                        movw r7, {}
                                        movt r7, {}",
                                        curr_addr_w,
                                        curr_addr_t,
                                        RESOLVE_BLX_FN_PTR_W,
                                        RESOLVE_BLX_FN_PTR_T
                                    ),
                                    0,
                                )
                                .unwrap()
                                .bytes,
                        );

                        // returns address of target basic block
                        shell_code.extend(&BLX_R7_INSN_BYTES);

                        // manipulate blx target register on stack before we pop
                        let stack_offset = 4 + reg_idx * 4;
                        shell_code.append(
                            &mut ks
                                .asm(format!("str r0, [sp, #{}]", stack_offset), 0)
                                .unwrap()
                                .bytes,
                        );

                        shell_code.extend(&BRANCH_POSTAMBLE_BYTES);

                        if insn_id == ArmInsn::ARM_INS_BLX as u32 {
                            shell_code
                                .append(&mut ks.asm(format!("blx {}", blx_reg), 0).unwrap().bytes);

                            let len = shell_code.len();
                            ptr::copy_nonoverlapping(
                                shell_code.as_ptr() as *const u8,
                                RECOMPILED_CODE_TOP as *mut u8,
                                len,
                            );
                            RECOMPILED_CODE_TOP += len as u32;
                        } else {
                            shell_code
                                .append(&mut ks.asm(format!("bx {}", blx_reg), 0).unwrap().bytes);

                            let len = shell_code.len();
                            ptr::copy_nonoverlapping(
                                shell_code.as_ptr() as *const u8,
                                RECOMPILED_CODE_TOP as *mut u8,
                                len,
                            );
                            RECOMPILED_CODE_TOP += len as u32;

                            O2N_CACHE[cache_index] = begin_recompiled_block;

                            break 'outer;
                        }
                    } else if (insn_id == ArmInsn::ARM_INS_BX as u32 && op.contains("lr"))
                        || (insn_id == ArmInsn::ARM_INS_POP as u32 && op.contains("pc"))
                    {
                        #[cfg(feature = "dbg_prints")]
                        println!("[i] patching insn: {}", i);

                        // retain original insn
                        let len = i.bytes().len();
                        ptr::copy_nonoverlapping(
                            i.bytes().as_ptr() as *const u8,
                            RECOMPILED_CODE_TOP as *mut u8,
                            len,
                        );

                        RECOMPILED_CODE_TOP += len as u32;

                        // do not close block if there is the possibility of the instruction not being executed
                        if cc == arm_cc::ARM_CC_AL {
                            O2N_CACHE[cache_index] = begin_recompiled_block;

                            break 'outer;
                        }
                    } else if insn_id == ArmInsn::ARM_INS_TBB as u32
                        || insn_id == ArmInsn::ARM_INS_TBH as u32
                    {
                        #[cfg(feature = "dbg_prints")]
                        println!("[i] patching insn: {}", i);

                        let index_reg = &i.op_str().unwrap()[5..7];
                        let mut shell_code: Vec<u8> = Vec::new();
                        let reg_idx = parse_reg(index_reg);

                        // param0 = table_index
                        shell_code.append(
                            &mut ks
                                .asm(
                                    format!(
                                        "push {{r0-r12, lr}}
                                        mov r0, {}",
                                        index_reg
                                    ),
                                    0,
                                )
                                .unwrap()
                                .bytes,
                        );

                        // param3 = is_byte_index (as opposed to half)
                        if insn_id == ArmInsn::ARM_INS_TBB as u32 {
                            shell_code
                                .append(&mut ks.asm("mov r3, 0".to_string(), 0).unwrap().bytes);
                        } else {
                            shell_code
                                .append(&mut ks.asm("mov r3, 1".to_string(), 0).unwrap().bytes);
                        }

                        shell_code.append(
                            &mut ks
                                .asm(
                                    format!(
                                        "movw r1, {}
                                        movt r1, {}
                                        mov r2, pc
                                        movw r7, {}
                                        movt r7, {}",
                                        curr_addr_w,
                                        curr_addr_t,
                                        RESOLVE_TB_FN_PTR_W,
                                        RESOLVE_TB_FN_PTR_T
                                    ),
                                    0,
                                )
                                .unwrap()
                                .bytes,
                        );

                        shell_code.extend(&BLX_R7_INSN_BYTES);

                        let stack_offset = reg_idx * 4;
                        shell_code.append(
                            &mut ks
                                .asm(format!("str r0, [sp, #{}]", stack_offset), 0)
                                .unwrap()
                                .bytes,
                        );

                        shell_code.extend(&POP_ALL_BYTES);
                        shell_code.append(
                            &mut ks.asm(format!("mov pc, {}", index_reg), 0).unwrap().bytes,
                        );

                        let len = shell_code.len();
                        ptr::copy_nonoverlapping(
                            shell_code.as_ptr() as *const u8,
                            RECOMPILED_CODE_TOP as *mut u8,
                            len,
                        );

                        // leave space for resolved jump
                        RECOMPILED_CODE_TOP += len as u32 + 16;
                    } else {
                        if curr_it_block.is_open {
                            let it_insn = &mut ks
                                .asm(
                                    format!(
                                        "it {}",
                                        curr_it_block.conditions[curr_it_block.counter]
                                    ),
                                    0,
                                )
                                .unwrap()
                                .bytes;

                            ptr::copy_nonoverlapping(
                                it_insn.as_ptr() as *const u8,
                                RECOMPILED_CODE_TOP as *mut u8,
                                2,
                            );
                            RECOMPILED_CODE_TOP += 2_u32;

                            curr_it_block.counter += 1;

                            if curr_it_block.counter == curr_it_block.conditions.len() {
                                curr_it_block.is_open = false;
                            }
                        }

                        let len = i.bytes().len();
                        ptr::copy_nonoverlapping(
                            i.bytes().as_ptr() as *const u8,
                            RECOMPILED_CODE_TOP as *mut u8,
                            len,
                        );
                        RECOMPILED_CODE_TOP += len as u32;
                    }
                }
            }
        } else {
            #[cfg(feature = "dbg_prints")]
            println!(
                "[!] Not patching {:#x}, already in cache ({:#x})",
                target_bb_addr,
                get_addr(target_bb_addr)
            );
            return get_addr(target_bb_addr);
        }
    }
    #[cfg(feature = "dbg_prints")]
    {
        NUM_CURR_REWRITES += 1;
    }
    invalidate_icache(begin_recompiled_block, RECOMPILED_CODE_TOP);
    begin_recompiled_block
}

/// Resolves new target address and calculates branch offsets at runtime once
unsafe fn resolve_branch(mut target: u32, orig_addr: u32, pc: u32) {
    let mut is_conditional = false;
    let mut is_it_cond = false;

    if target & 1 == 1 {
        is_it_cond = true;
        is_conditional = true;
        target -= 1;
    }

    let target_bb = get_addr(target);
    let mut offset: i64;

    #[cfg(feature = "dbg_prints")]
    println!(
        "[i] RESOLVING {:#x} -> {:#x} [from {:#x}/{:#x}]",
        target,
        target_bb,
        pc - RECOMPILED_CODE,
        orig_addr
    );

    // disassemble original instruction
    let cs_ref = CS_ENGINE.borrow();
    let cs = cs_ref.as_ref().unwrap();
    let disas = cs
        .disasm_count(&BINARY[orig_addr as usize..], orig_addr as _, 1)
        .unwrap();
    let insn = &disas.as_ref()[0];
    let insn_size = insn.bytes().len();
    let insn_id = insn.id().0;
    let mut mnemonic = insn.mnemonic().unwrap().to_owned();

    let ks_ref = KS_ENGINE.borrow();
    let ks = ks_ref.as_ref().unwrap();

    let mut x: u32 = 0;
    if insn_id == ArmInsn::ARM_INS_BL as u32 {
        x = 14;
    }

    let cond_branch_bytes_len: usize;

    // replace call to this fn with static, resolved branch
    if insn_id == ArmInsn::ARM_INS_CBZ as u32 {
        let cov_block_offset = RECOMPILED_CODE_TOP as i64 - (pc + 22) as i64 - 6;
        is_conditional = true;

        let cond_branch_bytes = &mut ks
            .asm(
                format!(
                    "CMP {}, #0
                    BEQ.W #{}",
                    &insn.op_str().unwrap()[..2],
                    cov_block_offset as i32
                ),
                0,
            )
            .unwrap()
            .bytes;
        cond_branch_bytes_len = cond_branch_bytes.len();
        ptr::copy_nonoverlapping(
            cond_branch_bytes.as_ptr() as *const u8,
            (pc + 22) as *mut u8,
            cond_branch_bytes_len,
        );
    } else if insn_id == ArmInsn::ARM_INS_CBNZ as u32 {
        let cov_block_offset = RECOMPILED_CODE_TOP as i64 - (pc + 22) as i64 - 6;
        is_conditional = true;

        let cond_branch_bytes = &mut ks
            .asm(
                format!(
                    "CMP {}, #0
                    BNE.W #{}",
                    &insn.op_str().unwrap()[..2],
                    cov_block_offset as i32
                ),
                0,
            )
            .unwrap()
            .bytes;

        cond_branch_bytes_len = cond_branch_bytes.len();
        ptr::copy_nonoverlapping(
            cond_branch_bytes.as_ptr() as *const u8,
            (pc + 22) as *mut u8,
            cond_branch_bytes_len,
        );
    } else {
        let mut has_cond_suffix = false;
        if mnemonic.len() > 2 && &mnemonic[1..2] != "." {
            offset = RECOMPILED_CODE_TOP as i64 - (pc + 22 + x) as i64;
            is_conditional = true;
            has_cond_suffix = true;
        } else {
            offset = target_bb as i64 - (pc + 22 + x) as i64;
        }

        // if wide insn, adjust offset to consider prefetch
        if insn_id == ArmInsn::ARM_INS_B as u32 {
            if is_conditional && (offset > 255 || offset < -252) {
                // handle edge case
                if offset < 260 && insn_size != 4 {
                    mnemonic.push_str(".w");
                }
                offset -= 4;
            } else if (is_conditional && insn_size == 4)
                || ((offset > 2052 || offset < -2043) && mnemonic != "b.w" && mnemonic != "b")
            {
                offset -= 4;
            } else if (offset > 2052 || offset < -2043) && mnemonic != "b.w" {
                mnemonic.push_str(".w");
            }
        } else if insn_id == ArmInsn::ARM_INS_BL as u32 {
            offset = target_bb as i64 - (pc + 22 + x) as i64;
            if (offset > 4 * 1_000_000_i64 || offset < -4 * 1_000_000_i64)
                || mnemonic.contains(".w")
            {
                offset -= 4;
            }
        }

        let cond_branch_bytes: Vec<u8> = if !is_it_cond || has_cond_suffix {
            ks.asm(format!("{} #{}", mnemonic, offset as i32), 0)
                .unwrap()
                .bytes
        } else {
            ks.asm(
                format!(
                    "{}{} #{}",
                    mnemonic,
                    CONDITION_CODES.get(&(orig_addr as usize)).unwrap(),
                    offset as i32
                ),
                0,
            )
            .unwrap()
            .bytes
        };

        cond_branch_bytes_len = cond_branch_bytes.len();
        ptr::copy_nonoverlapping(
            cond_branch_bytes.as_ptr() as *const u8,
            (pc + 22 + x) as *mut u8,
            cond_branch_bytes_len,
        );
    }

    invalidate_icache(pc + 20, pc + 26 + x);

    // insert coverage tracking block(s)
    if is_conditional {
        let block_true_id = NEXT_BLOCK_ID;
        let block_false_id = NEXT_BLOCK_ID + 1;
        NEXT_BLOCK_ID += 2;

        offset = target_bb as i64 - (RECOMPILED_CODE_TOP) as i64;

        if cfg!(feature = "dbg_prints") || cfg!(feature = "full_trace") {
            let (w0, t0) = target.split();
            let (w1, t1) = pc.split();
            let (w2, t2) = TRACE_FN_PTR.split();
            let cov_block_bytes = &mut ks
                .asm(
                    format!(
                        "push {{r0-r12, lr}}
                        mrs r0, APSR
                        push {{r0}}
                        movw r0, {}
                        movt r0, {}
                        movw r1, {}
                        movt r1, {}
                        mov r2, r3
                        movw r7, {}
                        movt r7, {}
                        blx r7
                        pop {{r0}}
                        msr APSR_nzcvq, r0
                        pop {{r0-r12, lr}}
                        b.w #{}
                        ",
                        w0, t0, w1, t1, w2, t2, offset
                    ),
                    0,
                )
                .unwrap()
                .bytes;

            let code_len = cov_block_bytes.len();

            ptr::copy_nonoverlapping(
                cov_block_bytes.as_ptr() as *const u8,
                RECOMPILED_CODE_TOP as *mut u8,
                code_len,
            );

            invalidate_icache(RECOMPILED_CODE_TOP, RECOMPILED_CODE_TOP + code_len as u32);
            RECOMPILED_CODE_TOP += code_len as u32;

            // add tracing block for not-taken (slow path in debug, low prio optimization)
            let (w0, t0) = (orig_addr + insn_size as u32).split();

            let cov_block_bytes = &mut ks
                .asm(
                    format!(
                        "push {{r0-r12, lr}}
                        mrs r0, APSR
                        push {{r0}}
                        movw r0, {}
                        movt r0, {}
                        movw r1, {}
                        movt r1, {}
                        mov r2, r3
                        movw r7, {}
                        movt r7, {}
                        blx r7
                        pop {{r0}}
                        msr APSR_nzcvq, r0
                        pop {{r0-r12, lr}}
                        ",
                        w0, t0, w1, t1, w2, t2
                    ),
                    0,
                )
                .unwrap()
                .bytes;

            let code_len = cov_block_bytes.len();

            ptr::copy_nonoverlapping(
                cov_block_bytes.as_ptr() as *const u8,
                (pc + 22 + x + cond_branch_bytes_len as u32) as *mut u8,
                code_len,
            );

            invalidate_icache(
                pc + 22 + x + cond_branch_bytes_len as u32,
                (pc + 22 + x + cond_branch_bytes_len as u32) + code_len as u32,
            );
            x += code_len as u32;
        } else {
            let (w, t) = (&mut COV_AREA_PTR as *mut u8 as u32).split();

            let cov_block_bytes = &mut ks
                .asm(
                    format!(
                        "push {{r0, r1}}
                        movw r0, {0}
                        movt r0, {1}
                        mov r1, 1
                        strb r1, [r0, #{2}]
                        pop {{r0, r1}}
                        b.w #{3}
                        ",
                        w, t, block_true_id, offset
                    ),
                    0,
                )
                .unwrap()
                .bytes;

            let code_len = cov_block_bytes.len();

            ptr::copy_nonoverlapping(
                cov_block_bytes.as_ptr() as *const u8,
                RECOMPILED_CODE_TOP as *mut u8,
                code_len,
            );

            invalidate_icache(RECOMPILED_CODE_TOP, RECOMPILED_CODE_TOP + code_len as u32);
            RECOMPILED_CODE_TOP += code_len as u32;

            let cov_block_bytes = &mut ks
                .asm(
                    format!(
                        "push {{r0, r1}}
                        movw r0, {0}
                        movt r0, {1}
                        mov r1, 1
                        strb r1, [r0, #{2}]
                        pop {{r0, r1}}
                        ",
                        w, t, block_false_id,
                    ),
                    0,
                )
                .unwrap()
                .bytes;

            let code_len = cov_block_bytes.len();

            ptr::copy_nonoverlapping(
                cov_block_bytes.as_ptr() as *const u8,
                (pc + 22 + x + cond_branch_bytes_len as u32) as *mut u8,
                code_len,
            );

            invalidate_icache(
                pc + 22 + x + cond_branch_bytes_len as u32,
                (pc + 22 + x + cond_branch_bytes_len as u32) + code_len as u32,
            );
            x += code_len as u32;
        }
    }

    // branch to successor
    if is_conditional {
        let cache_index = ((orig_addr + insn_size as u32) >> 1) as usize;
        let branch_not_taken_target_bb = O2N_CACHE[cache_index];
        offset =
            branch_not_taken_target_bb as i64 - (pc + 22 + x + cond_branch_bytes_len as u32) as i64;

        // all offsets are even => one 16MB array allows us to cover +/- 16MB branch range
        let mut cache_index = offset.unsigned_abs() as usize;
        // use even indices to encode positive offsets and odd ones for negative values
        if offset < 0 {
            cache_index += 1;
        }
        if BW_CACHE[cache_index] == [0, 0, 0, 0] {
            // always returns 4 bytes or UB (i.e., keystone fckd up)
            let asm_output = ks.asm(format!("b.w #{}", offset as i32), 0).unwrap().bytes;
            BW_CACHE[cache_index] = asm_output[..].try_into().unwrap();
        }
        let branch_bytes: &[u8; 4] = &BW_CACHE[cache_index];
        ptr::copy_nonoverlapping(
            branch_bytes.as_ptr() as *const u32,
            (pc + 22 + x + cond_branch_bytes_len as u32) as *mut u32,
            1,
        );

        // NOP out rewrite calls, keep trace call
        ptr::copy_nonoverlapping(
            NOP_88_INSN_BYTES.as_ptr() as *const u8,
            (pc - 66) as *mut u8,
            2,
        );

        invalidate_icache(pc - 66, pc + 22 + x + cond_branch_bytes_len as u32 + 4);
    } else if insn_id == ArmInsn::ARM_INS_BL as u32 {
        ptr::copy_nonoverlapping(
            NOP_66_INSN_BYTES.as_ptr() as *const u8,
            (pc - 48) as *mut u8,
            2,
        );

        invalidate_icache(pc - 48, pc - 44);
    } else {
        ptr::copy_nonoverlapping(
            NOP_70_INSN_BYTES.as_ptr() as *const u8,
            (pc - 48) as *mut u8,
            2,
        );

        invalidate_icache(pc - 48, pc - 44);
    }
}

/// ```
/// r0 = 0x1000
/// blx r0
/// resolve_blx(target=0x1000)
/// target_bb = resolved_addr
/// offset = target_bb - curr_pc
/// b #offset
/// ```
/// Resolves dynamic (register-absolute) jump
unsafe fn resolve_blx(mut target: u32, orig_addr: u32, _pc: u32) -> u32 {
    #[cfg(feature = "dbg_prints")]
    println!(
        "[i] BLX DYN [{:#x} | {:#x}] -> {:#x}",
        orig_addr, _pc, target
    );

    NUM_CURR_BRANCHES += 1;

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

    // log LR
    ptr::copy_nonoverlapping(&orig_addr as *const u32, RECOMPILED_CODE as *mut u32, 1);

    // assume thumb
    target &= 0xfffffffe;

    // BLX target is in our lifted code-range (i.e., it's probably a tailcall)
    if target > RECOMPILED_CODE && target < RECOMPILED_CODE_TOP {
        return target | 1;
    }
    let target_offset = target - OFFSET;

    // caching
    let blx_cache_entry = BX_CONT_CACHE[target_offset as usize];
    if blx_cache_entry == 0 {
        let rewritten_addr = rewrite_bb(target_offset) | 1;
        BX_CONT_CACHE[target_offset as usize] = rewritten_addr;
        rewritten_addr
    } else {
        blx_cache_entry
    }

    // no NOP sled, we need to dynamically resolve the jump every time
}

/// Resolves table branch at runtime.
/// Calculates the table offset and adds coverage tracking blocks.
unsafe fn resolve_tb(index: u32, orig_addr: u32, pc: u32, is_byte: u32) -> u32 {
    let mut table_offset: u32;

    if is_byte == 0 {
        asm!("ldrb {}, [{}, {}]",
            out(reg) table_offset,
            in(reg) orig_addr + 4,
            in(reg) index);
    } else {
        asm!("ldrh {}, [{}, {}]",
            out(reg) table_offset,
            in(reg) orig_addr + 4,
            // LSL #1 as part of TBH insn
            in(reg) index << 1);
    }

    // the branch length is twice the value of the byte/halfword
    let target_offset = orig_addr + 4 + table_offset * 2;

    #[cfg(feature = "dbg_prints")]
    println!(
        "[i] TABLE BRANCH: offset {}, from {:#x} to {:#x} [PC: {:#x}]\n",
        table_offset,
        orig_addr,
        target_offset + OFFSET,
        pc
    );

    let target_bb: u32;
    let cache_index = (target_offset >> 1) as usize;

    if TB_INDEX_CACHE[cache_index] != 0 {
        TB_INDEX_CACHE[cache_index]
    } else {
        target_bb = rewrite_bb(target_offset);

        let ks_ref = KS_ENGINE.borrow();
        let ks = ks_ref.as_ref().unwrap();

        let block_id = NEXT_BLOCK_ID;
        NEXT_BLOCK_ID += 1;

        let cov_offset = target_bb as i64 - RECOMPILED_CODE_TOP as i64;

        let resolved_addr: u32;
        // add coverage tracking
        if cfg!(feature = "dbg_prints") || cfg!(feature = "full_trace") {
            let (w0, t0) = table_offset.split();
            let (w1, t1) = pc.split();
            let (w2, t2) = TRACE_FN_PTR.split();
            let cov_block_bytes = &mut ks
                .asm(
                    format!(
                        "push {{r0-r12, lr}}
                        mrs r0, APSR
                        push {{r0}}
                        movw r0, {}
                        movt r0, {}
                        movw r1, {}
                        movt r1, {}
                        mov r2, r3
                        movw r7, {}
                        movt r7, {}
                        blx r7
                        pop {{r0}}
                        msr APSR_nzcvq, r0
                        pop {{r0-r12, lr}}
                        b.w #{}
                        ",
                        w0, t0, w1, t1, w2, t2, cov_offset
                    ),
                    0,
                )
                .unwrap()
                .bytes;

            let code_len = cov_block_bytes.len();

            ptr::copy_nonoverlapping(
                cov_block_bytes.as_ptr() as *const u8,
                RECOMPILED_CODE_TOP as *mut u8,
                code_len,
            );

            invalidate_icache(RECOMPILED_CODE_TOP, RECOMPILED_CODE_TOP + code_len as u32);
            resolved_addr = RECOMPILED_CODE_TOP;
            TB_INDEX_CACHE[cache_index] = resolved_addr;
            RECOMPILED_CODE_TOP += code_len as u32;
        } else {
            let (w, t) = (&mut COV_AREA_PTR as *mut u8 as u32 + block_id as u32).split();

            let cov_block_bytes = &mut ks
                .asm(
                    format!(
                        "push {{r0, r1}}
                        movw r0, {0}
                        movt r0, {1}
                        mov r1, #1
                        strb r1, [r0]
                        pop {{r0, r1}}
                        b.w #{2}
                        ",
                        w, t, cov_offset
                    ),
                    0,
                )
                .unwrap()
                .bytes;

            let code_len = cov_block_bytes.len();

            ptr::copy_nonoverlapping(
                cov_block_bytes.as_ptr() as *const u8,
                RECOMPILED_CODE_TOP as *mut u8,
                code_len,
            );

            invalidate_icache(RECOMPILED_CODE_TOP, RECOMPILED_CODE_TOP + code_len as u32);
            resolved_addr = RECOMPILED_CODE_TOP;
            TB_INDEX_CACHE[cache_index] = resolved_addr;
            RECOMPILED_CODE_TOP += code_len as u32;
        }

        resolved_addr
    }
}

/// Resolves occurences of `LDR PC, [...]` by patching the jump table entry
unsafe fn resolve_ld_pc(jump_table_entry: u32, mut target: u32, _pc: u32) {
    if LD_PAD_CACHE[jump_table_entry as usize] != 0x13_u8 {
        target -= 1;
        let target_offset = target - OFFSET;
        let target_bb: u32;
        let cache_index = (target_offset >> 1) as usize;
        if O2N_CACHE[cache_index] != 0 {
            target_bb = O2N_CACHE[cache_index] + 1;
        } else {
            target_bb = RECOMPILED_CODE_TOP + 1;
            rewrite_bb(target_offset);
        }

        #[cfg(feature = "dbg_prints")]
        println!(
            "[i] LOAD PC: target address {:#x}, curr_pc {:#x}.\n    Inserting {:#x} at jump table {:#x}.",
            target, _pc, target_bb, jump_table_entry as usize
        );

        ptr::copy_nonoverlapping((&target_bb) as *const u32, jump_table_entry as *mut u32, 1);

        invalidate_icache(jump_table_entry, jump_table_entry + 8);
        LD_PAD_CACHE[jump_table_entry as usize] = 0x13;
    }
}

/// Resets the state and jumps into target code. Gets called each fuzzing iteration.
pub unsafe fn start_execution(entry_point: u32, input: &[u8]) -> u32 {
    harness::reset();

    FUZZ_INPUT = (*input).to_vec();
    FUZZ_LEN = FUZZ_INPUT.len() as _;
    FUZZ_INDEX = 0;

    #[cfg(feature = "full_trace")]
    {
        LAST_TRACE = TRACE.to_owned();
        TRACE.clear();
    }

    let ret: u32;
    let entry_rewritten = (RECOMPILED_CODE + 32) | 1;
    asm!("push {{r4-r12}}",
        "mov lr, {0}",
        "mov r0, #0x30000000",
        "str sp, [r0, #16]",
        "mov sp, #0x30000000",
        "add r0, pc, 12",
        "str r0, [sp, #24]",
        "mov r0, {1}",
        "mov sp, {2}",
        "mov pc, r1",
        "pop {{r4-r12}}",
        in(reg) entry_rewritten,
        in(reg) entry_point,
        in(reg) harness::EMU_SP,
        in("r1") REWRITE_FN_PTR,
        out("r0") ret);
    ret
}

/// Initializes the engine state, e.g., by mapping memory regions and populating global vars.
pub unsafe fn init(code: &[u8]) -> Result<(), String> {
    harness::set_hooks();

    // init static ptrs
    TRACE_FN_PTR = trace as *const fn() as u32;
    REWRITE_FN_PTR = rewrite_bb as *const fn() as u32;
    (REWRITE_FN_PTR_W, REWRITE_FN_PTR_T) = REWRITE_FN_PTR.split();
    RESOLVE_BRANCH_FN_PTR = resolve_branch as *const fn() as u32;
    (RESOLVE_BRANCH_FN_PTR_W, RESOLVE_BRANCH_FN_PTR_T) = RESOLVE_BRANCH_FN_PTR.split();
    RESOLVE_BLX_FN_PTR = resolve_blx as *const fn() as u32;
    (RESOLVE_BLX_FN_PTR_W, RESOLVE_BLX_FN_PTR_T) = RESOLVE_BLX_FN_PTR.split();
    RESOLVE_TB_FN_PTR = resolve_tb as *const fn() as u32;
    (RESOLVE_TB_FN_PTR_W, RESOLVE_TB_FN_PTR_T) = RESOLVE_TB_FN_PTR.split();
    TRIGGER_TICK_FN_PTR = trigger_tick as *const fn() as u32;

    let code_len = code.len();
    harness::setup(code, OFFSET)?;

    if harness::EMU_SP == 0xffffffff {
        panic!("[X] Please set Stack Pointer in your harness::setup")
    } else if OFFSET == 0xffffffff {
        panic!("[X] Please set Offset/Base in your harness::setup")
    }

    RECOMPILED_CODE = libc::mmap(
        0x30000000 as _,
        code_len * 10,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    ) as u32;

    libc::memset(RECOMPILED_CODE as _, 0xff, code_len * 10);

    // first 4 byte store callsite PC for bl(x); 8-12 carry rust-context SP, 16-20 PC/LR
    RECOMPILED_CODE_TOP = RECOMPILED_CODE + 32;
    ptr::copy_nonoverlapping(
        &REWRITE_FN_PTR as *const u32,
        (RECOMPILED_CODE + 4) as *mut u32,
        1,
    );

    if RECOMPILED_CODE as i64 == 0xffffffff {
        Err(format!("mmap error: {:?}", Error::last_os_error()))
    } else {
        #[cfg(feature = "dbg_prints")]
        signals::init_sig_handlers().expect("Failed to initialize SIG handlers");

        // init global capstone/keystone objects
        CS_ENGINE = RefCell::new(Some(
            Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Thumb)
                .extra_mode([arch::arm::ArchExtraMode::MClass].iter().copied())
                .detail(true)
                .build()
                .expect("failed to create Capstone engine for thumb mode"),
        ));
        KS_ENGINE = RefCell::new(Some(
            Keystone::new(Arch::ARM, Mode::THUMB)
                .expect("Could not initialize Keystone engine for thumb mode"),
        ));

        let ks_ref = KS_ENGINE.borrow();
        let ks = ks_ref.as_ref().unwrap();

        // assemble a bunch of instructions once for later reuse
        NOP_66_INSN_BYTES = ks.asm("b #66".to_string(), 0).unwrap().bytes;
        NOP_70_INSN_BYTES = ks.asm("b #70".to_string(), 0).unwrap().bytes;
        NOP_88_INSN_BYTES = ks.asm("b #88".to_string(), 0).unwrap().bytes;
        BLX_R7_INSN_BYTES = ks.asm("blx r7".to_string(), 0).unwrap().bytes;
        BRANCH_PREAMBLE_BYTES = ks
            .asm(
                "push {r0-r12, lr}
                    mrs r0, APSR
                    push {r0}"
                    .to_string(),
                0,
            )
            .unwrap()
            .bytes;

        BRANCH_POSTAMBLE_BYTES = ks
            .asm(
                "pop {r0}
                    msr APSR_nzcvq, r0
                    pop {r0-r12, lr}"
                    .to_string(),
                0,
            )
            .unwrap()
            .bytes;

        BLX_PREAMBLE_BYTES = ks
            .asm(
                "mrs r1, APSR
                    pop {r0}
                    push {r1}"
                    .to_string(),
                0,
            )
            .unwrap()
            .bytes;

        POP_ALL_BYTES = ks.asm("pop {r0-r12, lr}".to_string(), 0).unwrap().bytes;

        HOOK_RET_BYTES = ks
            .asm(
                "pop {r1-r11, lr}
                bx lr"
                    .to_string(),
                0,
            )
            .unwrap()
            .bytes;

        ENTRY = harness::ENTRY;
        START_TIME = SystemTime::now();
        PREVIOUS_PC = ENTRY as _;

        Ok(())
    }
}
