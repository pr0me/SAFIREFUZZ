#![allow(unused_imports)]

use crate::handlers;
use crate::handlers::{ethernet, lwip, samr21, stm32};
use crate::utils::{exit_hook_ok, register_hook};

use std::io::Error;
use std::ptr;

pub static EMU_SP: u32 = 0x20014000;
pub static ENTRY: u32 = 0x2214;

pub unsafe fn set_hooks() {
    register_hook(0x969e, handlers::realloc_r as *const fn());
    register_hook(0x8b1c, handlers::free_r as *const fn());
    register_hook(0x8bb0, handlers::malloc_r as *const fn());
    register_hook(0x348c, handlers::malloc as *const fn()); // mem_malloc
    register_hook(0x3358, handlers::free as *const fn()); // mem_free
    register_hook(0x80c0, handlers::_memset as *const fn());

    // TCP HOOKS
    // register_hook(0x1eb0, handlers::nop as *const fn()); // system_init
    // register_hook(0x114, handlers::nop as *const fn()); // delay_init
    // register_hook(0x746c, handlers::nop as *const fn()); // init_ethernet
    // register_hook(0x3188, handlers::nop as *const fn()); // lwip_init
    // register_hook(0x74f8, lwip::tick as *const fn()); // ethernet_task
    // register_hook(0x3798, lwip::pbuf_free as *const fn());
    // register_hook(0x45cc, lwip::tcp_new as *const fn());
    // register_hook(0x3b0c, lwip::tcp_bind as *const fn());
    // register_hook(0x3b90, lwip::tcp_listen as *const fn()); // tcp_listen_with_backlog
    // register_hook(0x3d44, lwip::tcp_accept as *const fn());
    // register_hook(0x3d00, handlers::nop as *const fn()); // tcp_setprio
    // register_hook(0x3d30, lwip::tcp_arg as *const fn());
    // register_hook(0x3d34, lwip::tcp_recv as *const fn());
    // register_hook(0x3d3e, handlers::nop as *const fn()); // tcp_err
    // register_hook(0x3d48, handlers::nop as *const fn()); // tcp_poll
    // register_hook(0x3c80, handlers::nop as *const fn()); // tcp_recved
    // register_hook(0x5c08, lwip::tcp_write as *const fn());
    // register_hook(0x4284, lwip::tcp_close as *const fn());

    // atmel_asf_v3 HOOKS
    register_hook(0x19fc, handlers::nop as *const fn()); // system_clock_init
    register_hook(0x187c, handlers::nop as *const fn()); // system_clock_source_xosc32k_set_config
    register_hook(0x122c, handlers::nop as *const fn()); // usart_init
    register_hook(0x1520, handlers::nop as *const fn()); // usart_read_wait
    register_hook(0x488, handlers::nop as *const fn()); // ksz8851snl_init
    register_hook(0x7c90, stm32::hal_get_tick as *const fn()); // sys_get_ms
    register_hook(0x81c4, handlers::puts as *const fn());
    register_hook(0x14f0, samr21::usart_write_wait as *const fn());
    register_hook(0x6f94, samr21::ethernetif_input as *const fn());
    register_hook(0x6f5c, samr21::ksz8851snl_low_level_output as *const fn());
    register_hook(0x4494, handlers::return_zero as *const fn()); // tcp_next_iss
    register_hook(0x7ca8, handlers::thumb_case_sqi as *const fn());
    register_hook(0x7cbc, handlers::thumb_case_uqi as *const fn());
    register_hook(0x7cd0, handlers::thumb_case_uhi as *const fn());

    register_hook(0x3752, exit_hook_ok as *const fn());
    register_hook(0x502c, exit_hook_ok as *const fn());
    // register_hook(0x4356, exit_hook as *const fn()); // inf loop
    register_hook(0x41b4, exit_hook_ok as *const fn()); // UDF
}

pub unsafe fn reset() {
    stm32::SYSTEM_START_TIME = 0;
    samr21::LAST_TIME = 1234567;
    samr21::SYSTEM_START_TIME = 0;

    samr21::ETHERNET_MODEL = ethernet::EthernetModel::new();
    samr21::ETHERNET_DEV_PTR = 0;
    samr21::ETHERNET_ORIG_PTR = 0;
    samr21::ETHERNET_NETIF_PTR = 0;

    ptr::copy_nonoverlapping(
        crate::engine::BINARY.as_ptr() as *const u8,
        0x0 as *mut _,
        0xb4,
    );

    handlers::MALLOC_CHUNK_CURR_PTR = handlers::MALLOC_CHUNK_TOP;
    handlers::FREED_PREV.clear();
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

    // data: 0x20000000 - 0x2000022c; bss: 0x20000230 - 0x200053c0; initial_sp: 0x20014000
    let ram = libc::mmap(
        0x20000000 as _,
        0x00400000,
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

    if code_segment_addr as i64 == 0xffffffff
        || ram as i64 == 0xffffffff
        || mmio as i64 == 0xffffffff
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
