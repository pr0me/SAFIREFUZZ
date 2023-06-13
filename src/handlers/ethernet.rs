#![allow(dead_code)]

use crate::engine::{FUZZ_INDEX, FUZZ_LEN};
use crate::utils;

pub struct EthernetModel {
    frame_queue: Vec<Vec<u8>>,
    frame_head: usize,
    calc_crc: bool,
    rx_isr_enabled: bool,
}

impl Default for EthernetModel {
    fn default() -> Self {
        Self::new()
    }
}

impl EthernetModel {
    pub const fn new() -> Self {
        Self {
            frame_queue: Vec::new(),
            frame_head: 0,
            calc_crc: true,
            rx_isr_enabled: false,
        }
    }

    /// 'pops' the front element (memory is free and VecDeque::new is not const)
    pub fn pop_frame(&mut self) -> &Vec<u8> {
        let top_frame = &self.frame_queue[self.frame_head];
        self.frame_head += 1;
        top_frame
    }

    pub unsafe fn get_frame_info(&mut self) -> (usize, usize) {
        let queue_len = self.frame_queue.len();
        if queue_len == 0 || self.frame_head >= queue_len {
            self.get_fuzz_frames();
        }
        let queue_len = self.frame_queue.len();
        if queue_len == 0 || self.frame_head >= queue_len {
            return (0, 0);
        }
        (
            self.frame_queue.len() - self.frame_head,
            self.frame_queue[self.frame_head].len(),
        )
    }

    /// Fill up queue with eth frames populated by fuzzer
    pub unsafe fn get_fuzz_frames(&mut self) {
        if FUZZ_INDEX == FUZZ_LEN {
            #[cfg(feature = "dbg_prints")]
            dbg!(FUZZ_INDEX);

            utils::exit_hook_ok();
        }

        let eof_marker = [0xbe, 0xef, 0xfa, 0xce];

        let mut curr_len: usize = 0;
        while FUZZ_INDEX < FUZZ_LEN {
            let mut frame: Vec<u8> = Vec::new();
            while FUZZ_INDEX < FUZZ_LEN {
                frame.push(utils::return_fuzz_byte());

                curr_len = frame.len();
                // check whether we produced EOFrame marker
                if curr_len > 3 && frame[curr_len - 4..] == eof_marker {
                    frame = frame[..curr_len - 4].to_vec();
                    break;
                }
            }

            if curr_len - eof_marker.len() > 1514 {
                #[cfg(feature = "dbg_prints")]
                dbg!(curr_len);

                utils::exit_hook_ok();
            }

            self.frame_queue.push(frame);
        }
    }

    pub unsafe fn get_rx_frame(&mut self) -> &Vec<u8> {
        if self.frame_queue.is_empty() || self.frame_head >= self.frame_queue.len() {
            self.get_fuzz_frames();
        }

        let frame = self.pop_frame();

        #[cfg(feature = "dbg_prints")]
        println!("[>] ETH Frame IN: {:?} :: {} bytes", frame, frame.len());

        frame
    }
}
