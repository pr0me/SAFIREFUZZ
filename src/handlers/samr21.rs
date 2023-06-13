#![allow(dead_code)]
#![allow(unused_variables)]

use crate::engine::{rewrite_bb, O2N_CACHE};
use crate::handlers::ethernet::EthernetModel;
use core::{arch::asm, ptr};
use std::convert::TryInto;

pub static mut SYSTEM_START_TIME: u32 = 0;
pub static mut LAST_TIME: u32 = 12345678;

// ETHERNET
pub static mut ETHERNET_MODEL: EthernetModel = EthernetModel::new();
pub static mut ETHERNET_DEV_PTR: u32 = 0;
pub static mut ETHERNET_ORIG_PTR: u32 = 0;
pub static mut ETHERNET_NETIF_PTR: u32 = 0;

// netif Offsets
static NETIF_STATE: u8 = 32;
static NETIF_INPUT: u8 = 16;

// struct ksz8851snl_device Offsets
static NUM_RX_BUFFS: u8 = 2;
static NUM_TX_BUFFS: u8 = 2;

static DEVICE_RX_DESC: u8 = 0;
static DEVICE_TX_DESC: u8 = 4 * NUM_RX_BUFFS;
static DEVICE_RX_PBUF: u8 = DEVICE_TX_DESC + (4 * NUM_TX_BUFFS);
static DEVICE_TX_PBUF: u8 = DEVICE_RX_PBUF + (4 * NUM_RX_BUFFS);
static DEVICE_RX_HEAD: u8 = DEVICE_TX_PBUF + (4 * NUM_TX_BUFFS);
static DEVICE_RX_TAIL: u8 = DEVICE_RX_HEAD + 4;
static DEVICE_TX_HEAD: u8 = DEVICE_RX_TAIL + 4;
static DEVICE_TX_TAIL: u8 = DEVICE_TX_HEAD + 4;
static DEVICE_NETIF: u8 = DEVICE_TX_TAIL + 4;

// pbuf offsets
static PBUF_NEXT: u8 = 0;
static PBUF_PAYLOAD: u8 = 4;
static PBUF_TOT_LEN: u8 = 8;
static PBUF_LEN: u8 = 10;
static PBUF_TYPE: u8 = 12;
static PBUF_FLAGS: u8 = 13;
static PBUF_REF: u8 = 14;

// Ethernet Types
static ETHTYPE_ARP: u16 = 0x0806;
static ETHTYPE_IP: u16 = 0x0800;

static MTU_SIZE: u16 = 1520;
static PADDING: u8 = 2;

unsafe fn is_supported_frame_type(frame: &[u8]) -> bool {
    if frame.len() < 14 {
        false
    } else {
        let eth_type = u16::from_be_bytes(frame[12..14].try_into().unwrap());
        matches!(eth_type, 0x0806_u16 | 0x0800_u16)
    }
}

pub unsafe fn usart_write_wait(_: u32, buf: u32) -> u32 {
    #[cfg(feature = "dbg_prints")]
    {
        println!("{:#x}", buf & 0xff);
    }
    0
}

/// Call ksz8851snl_rx_populate_queue
#[naked]
unsafe extern "aapcs" fn _call_populate_queues(
    _ethernet_dev_ptr: u32,
    ksz8851snl_rx_populate_queue_addr: u32,
) -> u32 {
    asm!("mov pc, r1", options(noreturn))
}

#[naked]
unsafe extern "aapcs" fn _call_netif_input(
    _rx_pbuf_ptr: u32,
    _ethernet_netif_ptr: u32,
    _netif_input_cb_addr: u32,
) -> u32 {
    asm!("mov pc, r2", options(noreturn))
}

/// Construct ethernet frames from fuzzing input and populate RX queue
pub unsafe fn ethernetif_input(_ethernet_netif_ptr: u32) -> u32 {
    let (num_frames, size_1st_frame) = ETHERNET_MODEL.get_frame_info();
    if num_frames > 0 {
        if ETHERNET_NETIF_PTR == 0 {
            ETHERNET_NETIF_PTR = _ethernet_netif_ptr;
            ETHERNET_DEV_PTR = *((ETHERNET_NETIF_PTR + NETIF_STATE as u32) as *const u32);
        } else {
            // uc.reg_write(UC_ARM_REG_LR, ethernet_orig_lr)
        }

        let rx_pbuf_ptr: u32 = *((ETHERNET_DEV_PTR + DEVICE_RX_PBUF as u32) as *const u32);
        if rx_pbuf_ptr == 0 {
            // value for atmel http firmware
            let cache_index = (0x6f24 >> 1) as usize;
            let fn_addr: u32 = if O2N_CACHE[cache_index] != 0 {
                O2N_CACHE[cache_index]
            } else {
                rewrite_bb(0x6f24)
            };

            return _call_populate_queues(ETHERNET_DEV_PTR, fn_addr + 1);
        }

        let frame = ETHERNET_MODEL.get_rx_frame();
        if is_supported_frame_type(frame) {
            ptr::write_unaligned(
                (ETHERNET_DEV_PTR + DEVICE_RX_PBUF as u32) as *mut u32,
                0_u32,
            );

            let payload_ptr: u32 = *((rx_pbuf_ptr + PBUF_PAYLOAD as u32) as *const u32);

            // write frame to memory
            let frame_len: u16 = frame.len() as u16;
            for i in 0..frame_len {
                ptr::write_unaligned(
                    (payload_ptr + PADDING as u32 + i as u32) as *mut u8,
                    frame[i as usize],
                );
            }
            ptr::write_unaligned((rx_pbuf_ptr + PBUF_LEN as u32) as *mut u16, frame_len);
            ptr::write_unaligned((rx_pbuf_ptr + PBUF_TOT_LEN as u32) as *mut u16, frame_len);

            let netif_input_cb: u32 =
                *((ETHERNET_NETIF_PTR + NETIF_INPUT as u32) as *const u32) - 1;
            let cache_index = (netif_input_cb >> 1) as usize;
            let fn_addr: u32 = if O2N_CACHE[cache_index] != 0 {
                O2N_CACHE[cache_index]
            } else {
                rewrite_bb(netif_input_cb)
            };
            return _call_netif_input(rx_pbuf_ptr, ETHERNET_NETIF_PTR, fn_addr + 1);
        }
    }

    0 // ERR_OK
}

/// Construct full frame for debug output
pub unsafe fn ksz8851snl_low_level_output(_: u32, pbuf_ptr: u32) -> u32 {
    let mut padding = PADDING;
    let mut curr_pbuf_next = pbuf_ptr;
    let mut curr_len: u16 = 0;
    let mut curr_payload_ptr: u32 = 0;
    let mut frame_bytes: Vec<u8> = Vec::new();
    while curr_pbuf_next != 0 {
        ptr::copy_nonoverlapping(
            (curr_pbuf_next + PBUF_LEN as u32) as *const u16,
            &mut curr_len as *mut u16,
            1,
        );
        ptr::copy_nonoverlapping(
            (curr_pbuf_next + PBUF_PAYLOAD as u32) as *const u32,
            &mut curr_payload_ptr as *mut u32,
            1,
        );

        let mut new_frame_buf: Vec<u8> = Vec::new();
        let new_frame_buf_len = curr_len as usize - padding as usize;
        new_frame_buf.set_len(new_frame_buf_len);
        ptr::copy_nonoverlapping(
            (curr_payload_ptr + padding as u32) as *const u8,
            new_frame_buf.as_mut_ptr() as *mut u8,
            new_frame_buf_len,
        );
        frame_bytes.append(&mut new_frame_buf);

        padding = 0;
        ptr::copy_nonoverlapping(
            (curr_pbuf_next + PBUF_NEXT as u32) as *const u32,
            &mut curr_pbuf_next as *mut u32,
            1,
        );
    }

    #[cfg(feature = "dbg_prints")]
    println!(
        "[<] ETH Frame OUT: {:x?} :: {} bytes",
        frame_bytes,
        frame_bytes.len()
    );
    // ERR_OK
    0
}
