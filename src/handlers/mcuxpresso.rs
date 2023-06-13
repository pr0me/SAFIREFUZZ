#![allow(dead_code)]
#![allow(unused_variables)]

use crate::handlers::ethernet::EthernetModel;
use core::ptr;

pub static mut ETHERNET_MODEL: EthernetModel = EthernetModel::new();
pub static mut ENET_READY: bool = false;
pub static mut SYS_TIME: u32 = 0;

pub unsafe fn uart_write_blocking(uart_base: u32, ptr: u32, len: u32) {
    #[cfg(feature = "dbg_prints")]
    {
        let mut buf: Vec<u8> = Vec::new();
        let len = len as usize;
        ptr::copy_nonoverlapping(ptr as *const u8, buf.as_mut_ptr(), len);
        buf.set_len(len);

        println!("UART >>> {:?}", String::from_utf8_lossy(&buf));
    }
}

pub unsafe fn enet_get_rx_frame_size(_: u32, frame_len_ptr: u32) -> u32 {
    if !ENET_READY {
        ENET_READY = true;
        ptr::write_unaligned(frame_len_ptr as *mut u32, 0_u32);
        4002
    } else {
        ENET_READY = false;
        let (_num_frames, len_next_frame) = ETHERNET_MODEL.get_frame_info();
        ptr::write_unaligned(frame_len_ptr as *mut u32, len_next_frame as u32);
        4000
    }
}

pub unsafe fn enet_send_frame(base: u32, handle: u32, data_ptr: u32, len: u32) {
    #[cfg(feature = "dbg_prints")]
    {
        let len = len as usize;
        let mut buf: Vec<u8> = Vec::new();
        ptr::copy_nonoverlapping(data_ptr as *const u8, buf.as_mut_ptr(), len);
        buf.set_len(len);

        println!("[<] ETH Frame OUT: {:?} :: {} bytes", buf, buf.len());
    }
}

pub unsafe fn enet_read_frame(base: u32, handle: u32, data_ptr: u32, len: u32) -> u32 {
    let data = ETHERNET_MODEL.get_rx_frame();
    let data_frame_len = data.len() as usize;
    ptr::copy_nonoverlapping(data.as_ptr(), data_ptr as *mut u8, data_frame_len);
    0
}

pub unsafe fn phy_get_link_status(_: u32, _: u32, status_ptr: u32) -> u32 {
    ptr::write_unaligned(status_ptr as *mut u8, 0x01_u8);
    0
}

pub unsafe fn phy_get_link_speed_duplex(_: u32, _: u32, speed_ptr: u32, duplex_ptr: u32) -> u32 {
    ptr::write_unaligned(speed_ptr as *mut u8, 0x01_u8);
    ptr::write_unaligned(duplex_ptr as *mut u8, 0x01_u8);
    0
}

pub unsafe fn sys_now() -> u32 {
    SYS_TIME += 64;
    SYS_TIME
}
