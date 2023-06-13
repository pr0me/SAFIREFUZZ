use crate::engine::{rewrite_bb, FUZZ_INDEX, FUZZ_LEN, O2N_CACHE};
use crate::utils;

use core::{arch::asm, mem::size_of, slice};

use std::collections::BTreeMap;
use std::{convert::TryInto, ptr};

pub static mut IEEE802_MODEL: IEEE802Model = IEEE802Model::new();

pub static mut RF233_REGS: BTreeMap<u32, u32> = BTreeMap::new();

static RF233_REG_IRQ_STATUS: u32 = 0x0F;
static RF233_REG_TRX_STATE: u32 = 0x02;
static RF233_REG_TRX_STATUS: u32 = 0x01;
static IRQ_TRX_END: u32 = 8;

static mut PACKET_TIMER_ID: usize = 0;

pub fn uip_chksum_fake() -> u32 {
    0xFFFF
}

pub struct IEEE802Model {
    frame_queue: Vec<Vec<u8>>,
    frame_head: usize,
}

impl Default for IEEE802Model {
    fn default() -> Self {
        Self::new()
    }
}

impl IEEE802Model {
    pub const fn new() -> Self {
        Self {
            frame_queue: Vec::new(),
            frame_head: 0,
        }
    }

    /// 'pops' the front element (memory is free and VecDeque::new is not const)
    pub fn pop_frame(&mut self) -> &Vec<u8> {
        let top_frame = &self.frame_queue[self.frame_head];
        self.frame_head += 1;
        top_frame
    }

    pub unsafe fn get_frame_info(&mut self) -> (usize, usize) {
        // if !self.has_frame() {
        //     self.get_fuzz_frames();
        // }
        if !self.has_frame() {
            return (0, 0);
        }
        (
            self.frame_queue.len(),
            self.frame_queue[self.frame_head].len(),
        )
    }

    /// Fill up queue with eth frames populated by fuzzer
    pub unsafe fn get_fuzz_frames(&mut self) {
        if FUZZ_INDEX >= FUZZ_LEN {
            #[cfg(feature = "dbg_prints")]
            dbg!(0, FUZZ_INDEX);

            utils::exit_hook_ok();
        }

        let mut curr_len: usize = 0;

        let eof_marker = [0xbe, 0xef, 0xfa, 0xce];

        while FUZZ_INDEX < FUZZ_LEN {
            let mut frame: Vec<u8> = Vec::with_capacity(256);
            while FUZZ_INDEX < FUZZ_LEN {
                curr_len = frame.len();

                // check whether we produced EOFrame marker
                if curr_len > 4 && frame[curr_len - 4..] == eof_marker {
                    frame = frame[..curr_len - 4].to_vec();
                    break;
                }
                frame.push(utils::return_fuzz_byte());
            }
            if curr_len > 255 {
                #[cfg(feature = "dbg_prints")]
                dbg!(1, curr_len);

                utils::exit_hook_ok();
            }

            self.frame_queue.push(frame);
        }
    }

    pub unsafe fn get_rx_frame(&mut self) -> &Vec<u8> {
        if !self.has_frame() {
            self.get_fuzz_frames();
        }

        let frame = self.pop_frame();

        #[cfg(feature = "dbg_prints")]
        println!("[>] RX frame: {:x?}", frame);

        frame
    }

    pub unsafe fn has_frame(&self) -> bool {
        self.frame_head < self.frame_queue.len()
    }
}

pub unsafe fn rf233_on() -> u32 {
    #[cfg(feature = "dbg_prints")]
    println!("[*] RF233: on");
    PACKET_TIMER_ID = utils::enable_timer(16, packet_irq, 256);
    0
}

pub unsafe fn rf233_off() -> u32 {
    #[cfg(feature = "dbg_prints")]
    println!("[*] RF233: off");
    utils::disable_timer(PACKET_TIMER_ID);
    0
}

pub unsafe fn rf233_send(_ptr: u32, _len: u32) -> u32 {
    #[cfg(feature = "dbg_prints")]
    {
        let len = (_len & 0xff) as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(_len);
        ptr::copy_nonoverlapping(_ptr as *const u8, buf.as_mut_ptr(), _len);
        buf.set_len(_len);
        println!("[<] TX frame: {:x?}", buf);
    }
    0
}

pub unsafe fn trx_sram_read(_: u32, addr: u32, size: u32) {
    if IEEE802_MODEL.has_frame() {
        let frame = IEEE802_MODEL.pop_frame();
        if frame.len() <= size as _ {
            #[cfg(feature = "dbg_prints")]
            println!(
                "[+] SRAM READ: writing {:x?} to {:#x} (len: {})",
                frame,
                addr,
                frame.len()
            );
            ptr::copy_nonoverlapping(frame.as_ptr() as *const u8, addr as *mut u8, frame.len());
        }
    }
}

pub unsafe fn trx_frame_read(buf: u32, size: u32) {
    assert!(size == 1);
    if !IEEE802_MODEL.has_frame() {
        ptr::write_unaligned(buf as *mut u8, 0_u8);
    } else {
        let (_, mut frame_len) = IEEE802_MODEL.get_frame_info();

        #[cfg(feature = "dbg_prints")]
        println!("[*] FRAME READ: curr_frame length: {frame_len}");

        frame_len += 2;
        ptr::copy_nonoverlapping(&frame_len as *const usize as *const u8, buf as *mut u8, 1);
    }
}

pub unsafe fn trx_frame_write(_buf: u32, _r1: u32) -> u32 {
    #[cfg(feature = "dbg_prints")]
    {
        let len = (_r1 & 0xff) as usize;
        let frame = slice::from_raw_parts(_buf as *mut u8, len as usize);

        println!("[<] TX frame: {frame:#x?}");
    }
    0
}

pub unsafe fn trx_reg_read(reg: u32) -> u32 {
    let mut ret_val: u32 = 0;
    if reg == RF233_REG_IRQ_STATUS {
        if IEEE802_MODEL.has_frame() {
            ret_val = IRQ_TRX_END;
        }
    } else if reg == RF233_REG_TRX_STATUS {
        ret_val = *RF233_REGS.entry(RF233_REG_TRX_STATE).or_insert(0);
    } else if let Some(val) = RF233_REGS.get(&reg) {
        ret_val = *val;
    }
    ret_val
}

pub unsafe fn trx_reg_write(reg: u32, val: u32) {
    RF233_REGS.insert(reg, val);
}

unsafe fn read_u32_le(loc: u32) -> u32 {
    let ptr_slice = slice::from_raw_parts(loc as *const u8, size_of::<u32>());
    u32::from_le_bytes(ptr_slice.try_into().unwrap())
}

unsafe fn read_u16_le(loc: u32) -> u16 {
    let ptr_slice = slice::from_raw_parts(loc as *const u8, size_of::<u16>());
    u16::from_le_bytes(ptr_slice.try_into().unwrap())
}

pub unsafe fn get_edbg_eui64(_: u32, packet_ptr: u32) -> u32 {
    let packet_len = read_u16_le(packet_ptr + 2);
    let packet_addr = read_u32_le(packet_ptr + 4);

    // Ask https://github.com/ucsb-seclab/hal-fuzz/blob/1446408e64b25aa77971226b764d1db65fe8ba09/hal_fuzz/hal_fuzz/handlers/rf233.py#L113
    let packet = slice::from_raw_parts_mut(packet_addr as *mut u8, packet_len as usize);
    for i in 0..packet_len {
        packet[i as usize] = 0o55;
    }
    0
}

pub unsafe fn packet_irq() {
    #[cfg(feature = "dbg_prints")]
    println!("[IRQ] New Packet");

    if !IEEE802_MODEL.has_frame() {
        IEEE802_MODEL.get_fuzz_frames();
    }

    let nvic_exti_num: u8 = 20;
    let eic_handler_addr: u16 = 0x37c;
    let nvic_isr_addr: u32 = 0xE000ED08_u32 + 4 * nvic_exti_num as u32;
    ptr::write(nvic_isr_addr as *mut u16, eic_handler_addr);
    ptr::write(0x40001810 as *mut u32, 1_u32);

    // resolve EIC_Handler
    let fn_addr: u32 = if O2N_CACHE[430] != 0 {
        O2N_CACHE[430]
    } else {
        rewrite_bb(0x35c)
    };

    // jump into callback
    asm!(
        "push {{r0-r12, lr}}
        mov r7, {}
        blx r7
        pop {{r0-r12, lr}}",
        in(reg) fn_addr | 1,
    );
}
