use crate::handlers::{self, ethernet, mcuxpresso};
use crate::utils::{exit_hook_ok, register_hook};

use std::io::Error;
use std::ptr;

pub static EMU_SP: u32 = 0x20030000;
pub static ENTRY: u32 = 0x4c4;

pub unsafe fn set_hooks() {
    register_hook(0x2b28, handlers::nop as *const fn()); // CLOCK_InitOsc0
    register_hook(0x29ac, handlers::nop as *const fn()); // CLOCK_SetInternalRefClkConfig
    register_hook(0x2c4c, handlers::nop as *const fn()); // CLOCK_BootToPeeMode
    register_hook(
        0x48c0,
        handlers::mcuxpresso::uart_write_blocking as *const fn(),
    );
    register_hook(0xf34, handlers::return_zero as *const fn()); // PHY_Init
    register_hook(
        0x352e,
        handlers::mcuxpresso::enet_get_rx_frame_size as *const fn(),
    );
    register_hook(0x37b4, handlers::mcuxpresso::enet_send_frame as *const fn());
    register_hook(0x35e2, handlers::mcuxpresso::enet_read_frame as *const fn());
    register_hook(
        0x1148,
        handlers::mcuxpresso::phy_get_link_status as *const fn(),
    );
    register_hook(
        0x1190,
        handlers::mcuxpresso::phy_get_link_speed_duplex as *const fn(),
    );
    register_hook(0x4fa8, handlers::mcuxpresso::sys_now as *const fn());

    register_hook(0x529e, handlers::return_zero as *const fn()); // ip_chksum_pseudo
    register_hook(0x52ca, handlers::return_zero as *const fn()); // inet_chksum
    register_hook(0x7d7c, handlers::return_zero as *const fn()); // tcp_next_iss

    register_hook(0x4ef0, exit_hook_ok as *const fn()); // sys_assert
    register_hook(0xf1c4, handlers::_memset as *const fn());
}

pub unsafe fn reset() {
    mcuxpresso::SYS_TIME = 0;
    mcuxpresso::ETHERNET_MODEL = ethernet::EthernetModel::new();
    mcuxpresso::ENET_READY = false;

    ptr::copy_nonoverlapping(
        crate::engine::BINARY.as_ptr() as *const u8,
        0x0 as *mut _,
        0x1000,
    );

    ptr::copy_nonoverlapping(
        crate::engine::BINARY[0x1214c..].as_ptr() as *const u8,
        0x1fff0000 as *mut u8,
        0x80,
    );

    ptr::write_bytes(0x1fff0080 as *mut u8, 0_u8, 0xd7a0 - 0x80);

    // handlers::MALLOC_CHUNK_CURR_PTR = handlers::MALLOC_CHUNK_TOP;
    // handlers::FREED_PREV.clear();
}

#[allow(unused_variables)]
pub unsafe fn setup(code: &[u8], offset: u32) -> Result<(), String> {
    let code_len = code.len();
    let code_segment_addr = libc::mmap(
        0x0 as _,
        code_len,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    );

    // mmap a chunk of your desired size for the use with the provided malloc hooks
    let malloc_chunk_size: u32 = 4 * 1000 * 1024;
    handlers::MALLOC_CHUNK_TOP = libc::mmap(
        0xff000000_u32 as _,
        malloc_chunk_size as _,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    ) as u32
        + malloc_chunk_size;
    handlers::MALLOC_CHUNK_CURR_PTR = handlers::MALLOC_CHUNK_TOP;

    // data: 0x20000000 - 0x20000230; bss: 0x20000230 - 0x200053c0; initial_sp: 0x20014000
    let ram = libc::mmap(
        0x20000000 as _,
        0x30000,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    );

    let mmio = libc::mmap(
        0x40000000 as _,
        0x10000000,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    );

    let nvic = libc::mmap(
        0xe0000000_u32 as _,
        0x10000,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    );

    let rom = libc::mmap(
        0x1fff0000_u32 as _,
        0x010000,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    );

    if code_segment_addr as i64 == 0xffffffff
        || ram as i64 == 0xffffffff
        || mmio as i64 == 0xffffffff
        || rom as i64 == 0xffffffff
        || nvic as i64 == 0xffffffff
        || handlers::MALLOC_CHUNK_TOP as i64 == 0xffffffff + (malloc_chunk_size - 1) as i64
    {
        Err(format!("mmap error: {:?}", Error::last_os_error()))
    } else {
        crate::engine::OFFSET = 0x0;

        ptr::copy_nonoverlapping(
            code.as_ptr() as *const u8,
            code_segment_addr as *mut u8,
            code_len,
        );

        Ok(())
    }
}
