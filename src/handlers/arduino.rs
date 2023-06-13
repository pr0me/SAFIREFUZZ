#![allow(dead_code)]
#![allow(unused_variables)]

use crate::engine::{FUZZ_INDEX, FUZZ_LEN};
use crate::utils::{self, exit_hook_ok, exit_hook_timeout};
#[cfg(feature = "dbg_prints")]
use std::ptr;

pub static mut TICKS: u32 = 0;
pub static mut SERIAL_AVAILABLE_ROUND: u32 = 0;
pub static mut LAST_BYTES_AVAIL: u32 = 0;
// exponentially increasing modifier to avoid costly loops
pub static mut TICK_MOD: u32 = 2;
pub static mut COLLECTED_PKT: bool = false;
pub static mut SERIAL_LINE: SerialModel = SerialModel::new();
static EOF_MARKER: [u8; 4] = [0x3c, 0x4c, 0x46, 0x3e];

pub struct SerialModel {
    curr_frame: Vec<u8>,
    rx_isr_enabled: bool,
}

impl Default for SerialModel {
    fn default() -> Self {
        Self::new()
    }
}

impl SerialModel {
    pub const fn new() -> Self {
        Self {
            curr_frame: Vec::new(),
            rx_isr_enabled: false,
        }
    }

    pub fn tx() {}

    /// Receives one byte from currently queued frame
    pub unsafe fn rx(&mut self) -> u32 {
        COLLECTED_PKT = true;
        if self.curr_frame.is_empty() {
            self.queue_frame();
            u32::MAX
        } else {
            let ret = self.curr_frame[0];
            self.curr_frame = self.curr_frame[1..self.curr_frame.len()].to_vec();
            ret as _
        }
    }

    pub unsafe fn queue_frame(&mut self) {
        if FUZZ_INDEX >= FUZZ_LEN {
            exit_hook_ok();
        }
        let mut frame: Vec<u8> = Vec::new();
        while FUZZ_INDEX < FUZZ_LEN {
            // #[cfg(feature = "dbg_prints")]
            // println!("{}", String::from_utf8_lossy(&frame));
            let curr_len = frame.len();
            if curr_len > 3 && frame[curr_len - 4..] == EOF_MARKER {
                frame = frame[..curr_len - 4].to_vec();
                break;
            }
            frame.push(utils::return_fuzz_byte());
        }
        self.curr_frame = frame;
    }
}

pub unsafe fn loop_detection_heuristic() {
    if COLLECTED_PKT {
        COLLECTED_PKT = false;
    } else {
        utils::exit_hook_ok();
    }
}

pub fn hardware_timer_typedef(timer_obj: u32, timer_num: u32) -> u32 {
    timer_obj
}

pub unsafe fn millis() -> u32 {
    TICKS += 32;
    TICKS
}

pub unsafe fn serial_read() -> u32 {
    let byte = SERIAL_LINE.rx();
    #[cfg(feature = "dbg_prints")]
    println!("[>] transmitting 1 byte from fuzz input: {:#x}", byte);
    byte
}

pub unsafe fn hardware_serial_available() -> u32 {
    let num_bytes_avail = SERIAL_LINE.curr_frame.len() as u32;
    // exit early if we don't consume
    if num_bytes_avail == LAST_BYTES_AVAIL {
        SERIAL_AVAILABLE_ROUND += 1;
    } else {
        SERIAL_AVAILABLE_ROUND = 0;
    }
    LAST_BYTES_AVAIL = num_bytes_avail;
    if SERIAL_AVAILABLE_ROUND >= 64 {
        exit_hook_ok();
    }
    // println!("{num_bytes_rdy}");
    // println!("Current packet {:?}", SERIAL_LINE.curr_frame);
    if num_bytes_avail == 0 {
        SERIAL_LINE.queue_frame();
    }
    num_bytes_avail
}

pub unsafe fn puts(_obj: u32, mut _s_ptr: u32) {
    #[cfg(feature = "dbg_prints")]
    {
        let mut c: [u8; 1] = [0x0];
        loop {
            ptr::copy_nonoverlapping(_s_ptr as *const u8, c.as_mut_ptr() as *mut u8, 1);
            if c[0] == 0x0 {
                println!();
                break;
            }
            print!("{}", c[0] as char);
            _s_ptr += 1;
        }
    }
}

pub unsafe fn __println(_obj: u32, mut _s_ptr: u32) {
    #[cfg(feature = "dbg_prints")]
    {
        puts(_obj, _s_ptr);
        println!();
    }
}

pub unsafe fn calc_crc(r0: u32) -> u32 {
    // detect common stack overflow due to NULL ptr dereference
    if *(*(r0 as *const u32) as *const u32) == 0x20030000 {
        exit_hook_timeout();
        unreachable!()
    }
    0
}
