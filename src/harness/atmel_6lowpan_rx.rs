use crate::handlers::{self, rf233, samr21};
use crate::utils::register_hook;

use std::{io::Error, ptr};

pub static EMU_SP: u32 = 0x20014000;
pub static ENTRY: u32 = 0x283c;

pub unsafe fn reg_nop(addr: u32) {
    register_hook(addr, handlers::nop as *const fn());
}

pub unsafe fn reg_ret0(addr: u32) {
    register_hook(addr, handlers::return_zero as *const fn());
}

pub unsafe fn set_hooks() {
    // atmel_asf_v3 HOOKS
    reg_nop(0x1EB0); // system_clock_init
    reg_nop(0x1cd0); // system_clock_source_xosc32k_set_config
    reg_nop(0x15f8); // usart_init
    reg_nop(0x19d8); // usart_read_buffer_wait
    reg_nop(0x1968); // usart_read_wait
    register_hook(0xf7a8, handlers::puts as *const fn());
    register_hook(0xf67c, handlers::_memset as *const fn());
    reg_ret0(0xc9ac); // rf_set_channel

    reg_nop(0xc9dc); // SetIEEEAddr
    reg_ret0(0xcd00); // rf233_send
    reg_ret0(0xce54); // rf233_sleep

    reg_ret0(0x7d0); // i2c_master_init
    reg_ret0(0xde8); // i2c_master_write_packet_wait_no_stop
    reg_ret0(0xb40); // i2c_master_read_packet_wait
    reg_ret0(0xa98); // i2c_master_reset

    register_hook(0x193c, samr21::usart_write_wait as *const fn()); // usart_write_wait

    register_hook(0x6fb8, rf233::uip_chksum_fake as *const fn()); // uip_tcpchksum
    register_hook(0x6fc8, rf233::uip_chksum_fake as *const fn()); // uip_udpchksum
    register_hook(0x6fa8, rf233::uip_chksum_fake as *const fn()); // uip_icmp6chksum

    register_hook(0xcdd0, rf233::rf233_on as *const fn()); // usart_write_wait
    register_hook(0xce2c, rf233::rf233_off as *const fn()); // usart_write_wait
    register_hook(0xdd4, rf233::get_edbg_eui64 as *const fn()); // i2c_master_read_packet_wait
    register_hook(0x31b0, rf233::trx_sram_read as *const fn());
    register_hook(0x2f64, rf233::trx_frame_read as *const fn());
    register_hook(0x3094, rf233::trx_frame_write as *const fn());
    register_hook(0x2d1c, rf233::trx_reg_read as *const fn());
    register_hook(0x2e18, rf233::trx_reg_write as *const fn());

    register_hook(0xd2a8, handlers::contiki::clock_init as *const fn()); // usart_write_wait
    register_hook(0xd34c, handlers::contiki::clock_time as *const fn());
    register_hook(0xd36c, handlers::contiki::clock_seconds as *const fn());

    register_hook(0x10030, handlers::malloc_r as *const fn());
    register_hook(0xff9c, handlers::free_r as *const fn());
    register_hook(0xf67c, handlers::_memset as *const fn());

    // endless loop in ext_hdr_options_process CVE-2020-13984
    register_hook(0x6db0, crate::utils::exit_hook_timeout as *const fn());
    // register_hook(0x63f0, crate::utils::exit_hook_ok as *const fn());
    // register_hook(0x65d6, crate::utils::exit_hook_ok as *const fn());
    // register_hook(0x68ae, crate::utils::exit_hook_ok as *const fn());

    register_hook(0x28e6, crate::utils::exit_hook_ok as *const fn()); // while true loop after main
}

pub unsafe fn debug() {
    println!("BKPT");
    crate::sleep!(5);
}

pub unsafe fn reset() {
    handlers::contiki::CURRENT_FAKE_TIME = 0;

    rf233::IEEE802_MODEL = rf233::IEEE802Model::new();

    ptr::copy_nonoverlapping(
        crate::engine::BINARY.as_ptr() as *const u8,
        0x0 as *mut _,
        0xba,
    );

    ptr::copy_nonoverlapping(
        crate::engine::BINARY[0xc205..].as_ptr() as *const u32,
        0x88 as *mut u32,
        1,
    );

    ptr::copy_nonoverlapping(
        crate::engine::BINARY[0x11200..].as_ptr() as *const u8,
        0x20000000 as *mut u8,
        0x230,
    );

    // enable interrupts/timers
    crate::engine::IRQ_ENABLED = true;
    crate::engine::NUM_CURR_BRANCHES = 0;
    // disable all timers
    crate::engine::TIMERS.clear();

    // libc::memset(0x20000230 as _, 0, 0x4f60);

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

    let samr21_addrs = libc::mmap(
        0x800000_u32 as _,
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
        || samr21_addrs as i64 == 0xffffffff
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
