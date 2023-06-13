use crate::engine::{rewrite_bb, FUZZ_INDEX, FUZZ_LEN, O2N_CACHE, RECOMPILED_CODE_TOP};
use crate::handlers::stm32;
use crate::utils;

use core::{arch::asm, ptr};

const RX_DATA_BUF: u32 = 0x200f0000;

/// These need to be set by the user in the harness.
pub static mut IND_WIFI_CONNECTED_ADDR: u32 = 0;
pub static mut IND_SOCKET_SERVER_CLIENT_JOINED_ADDR: u32 = 0;
pub static mut IND_SOCKET_SERVER_CLIENT_LEFT_ADDR: u32 = 0;
pub static mut IND_WIFI_SOCKET_DATA_RECEIVED_ADDR: u32 = 0;

pub static mut TCP_MODEL: TCPModel = TCPModel::new();

#[derive(PartialEq)]
pub enum WifiState {
    OFF,
    IDLE,
    CONNECTED,
}

pub struct TCPModel {
    packet_queue: Vec<Vec<u8>>,
    queue_head: usize,
    port: u32,
    state: WifiState,
}

impl Default for TCPModel {
    fn default() -> Self {
        Self::new()
    }
}

impl TCPModel {
    pub const fn new() -> Self {
        Self {
            packet_queue: Vec::new(),
            queue_head: 0,
            port: 0,
            state: WifiState::OFF,
        }
    }

    pub fn listen(&mut self, port: u32) {
        self.port = port;
    }

    pub fn tx_packet(&self, payload: &Vec<u8>) {
        println!("{:?}", payload);
    }

    pub fn has_rx_packet(&self) -> bool {
        let queue_len = self.packet_queue.len();

        !(queue_len == 0 || self.queue_head >= queue_len)
    }

    pub fn enqueue_packet(&mut self, payload: Vec<u8>) {
        self.packet_queue.push(payload);
    }

    /// Fill up queue with TCP packets populated by fuzzer
    pub unsafe fn get_fuzz_frames(&mut self) {
        if FUZZ_INDEX == FUZZ_LEN {
            #[cfg(feature = "dbg_prints")]
            dbg!(FUZZ_INDEX);

            utils::exit_hook_ok();
        }

        let mut curr_len: usize;
        while FUZZ_INDEX < FUZZ_LEN {
            let mut packet: Vec<u8> = Vec::new();
            while FUZZ_INDEX < FUZZ_LEN {
                packet.push(utils::return_fuzz_byte());

                curr_len = packet.len();
                if curr_len > 0 && packet[curr_len - 1] == 0x0_u8 {
                    packet = packet[..curr_len - 1].to_vec();
                    break;
                }
            }

            self.enqueue_packet(packet);
        }
    }

    pub fn get_rx_packet(&mut self) -> &Vec<u8> {
        #[cfg(feature = "dbg_prints")]
        println!("[>] TCP RX: Returning Packet");

        self.pop_packet()
    }

    /// 'pops' the front element (memory is free and VecDeque::new is not const)
    fn pop_packet(&mut self) -> &Vec<u8> {
        let top_frame = &self.packet_queue[self.queue_head];
        self.queue_head += 1;
        top_frame
    }
}

pub unsafe fn wifi_init() -> u32 {
    #[cfg(feature = "dbg_prints")]
    println!("[i] wifi_init: Starting timer");

    utils::enable_timer(32, stm32::tim3_irq_handler, 0);

    0
}

pub unsafe fn wifi_socket_server_open(port: u32) -> u32 {
    #[cfg(feature = "dbg_prints")]
    println!("[i] `wifi_socket_server_open` called :: PORT {}", port);

    TCP_MODEL.listen(port);
    0
}

pub unsafe fn wifi_socket_server_write(_len: u32, _data_ptr: u32) {
    #[cfg(feature = "dbg_prints")]
    {
        let len = _len as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(len);
        ptr::copy_nonoverlapping(_data_ptr as *const u8, buf.as_mut_ptr() as *mut u8, len);
        buf.set_len(len);
        TCP_MODEL.tx_packet(&buf);
    }
}

#[naked]
unsafe extern "aapcs" fn _invoke_zero_args(_: u32, target_addr: u32) -> u32 {
    asm!("mov pc, r1", options(noreturn))
}

#[naked]
unsafe extern "aapcs" fn _invoke_four_args(
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    target_addr: u32,
) -> u32 {
    asm!("ldr pc, [sp]", options(noreturn))
}

/// Emulate connections over wifi
pub unsafe fn wifi_tim_handler(r0: u32) {
    if TCP_MODEL.state == WifiState::OFF {
        TCP_MODEL.state = WifiState::IDLE;

        #[cfg(feature = "dbg_prints")]
        println!("[i] Setting `wifi_connected` State");

        if IND_WIFI_CONNECTED_ADDR == 0 {
            panic!("[X] Aborting. Please set the address of `ind_wifi_connected` in your harness")
        }

        let cb_resolved_addr: u32;
        let cache_index = (IND_WIFI_CONNECTED_ADDR >> 1) as usize;
        if O2N_CACHE[cache_index] != 0 {
            cb_resolved_addr = O2N_CACHE[cache_index];
        } else {
            cb_resolved_addr = RECOMPILED_CODE_TOP;
            rewrite_bb(IND_WIFI_CONNECTED_ADDR);
        }

        _invoke_zero_args(r0, cb_resolved_addr | 1);
    } else if TCP_MODEL.state == WifiState::IDLE {
        #[cfg(feature = "dbg_prints")]
        println!("[i] Starting WiFi: loading fuzz");
        TCP_MODEL.get_fuzz_frames();

        TCP_MODEL.state = WifiState::CONNECTED;

        if IND_SOCKET_SERVER_CLIENT_JOINED_ADDR == 0 {
            panic!(
                "[X] Aborting. Please set the address of `ind_socket_server_client_joined` in your harness"
            )
        }

        let cb_resolved_addr: u32;
        let cache_index = (IND_SOCKET_SERVER_CLIENT_JOINED_ADDR >> 1) as usize;
        if O2N_CACHE[cache_index] != 0 {
            cb_resolved_addr = O2N_CACHE[cache_index];
        } else {
            cb_resolved_addr = RECOMPILED_CODE_TOP;
            rewrite_bb(IND_SOCKET_SERVER_CLIENT_JOINED_ADDR);
        }

        _invoke_zero_args(r0, cb_resolved_addr | 1);
    } else if TCP_MODEL.state == WifiState::CONNECTED {
        if TCP_MODEL.has_rx_packet() {
            let data = TCP_MODEL.get_rx_packet();

            #[cfg(feature = "dbg_prints")]
            println!("[>] Wifi New Packet: {:?}", data);

            ptr::copy_nonoverlapping(
                data.as_ptr() as *const u8,
                RX_DATA_BUF as *mut u8,
                data.len(),
            );
            ptr::write_unaligned((RX_DATA_BUF + data.len() as u32) as *mut u8, 0_u8);

            if IND_WIFI_SOCKET_DATA_RECEIVED_ADDR == 0 {
                panic!(
                    "[X] Aborting. Please set the address of `ind_wifi_socket_data_received` in your harness"
                )
            }

            let cb_resolved_addr: u32;
            let cache_index = (IND_WIFI_SOCKET_DATA_RECEIVED_ADDR >> 1) as usize;
            if O2N_CACHE[cache_index] != 0 {
                cb_resolved_addr = O2N_CACHE[cache_index];
            } else {
                cb_resolved_addr = RECOMPILED_CODE_TOP;
                rewrite_bb(IND_WIFI_SOCKET_DATA_RECEIVED_ADDR);
            }

            let len = data.len() as u32;
            _invoke_four_args(0, RX_DATA_BUF, len, len, cb_resolved_addr | 1);
        } else {
            #[cfg(feature = "dbg_prints")]
            println!("[i] Wifi: Client left");

            TCP_MODEL.state = WifiState::IDLE;

            if IND_SOCKET_SERVER_CLIENT_LEFT_ADDR == 0 {
                panic!(
                    "[X] Aborting. Please set the address of `ind_socket_server_client_left` in your harness"
                )
            }

            let cb_resolved_addr: u32;
            let cache_index = (IND_SOCKET_SERVER_CLIENT_LEFT_ADDR >> 1) as usize;
            if O2N_CACHE[cache_index] != 0 {
                cb_resolved_addr = O2N_CACHE[cache_index];
            } else {
                cb_resolved_addr = RECOMPILED_CODE_TOP;
                rewrite_bb(IND_SOCKET_SERVER_CLIENT_LEFT_ADDR);
            }

            _invoke_zero_args(r0, cb_resolved_addr | 1);
        }
    }
}
