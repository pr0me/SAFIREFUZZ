use crate::handlers::{self, libopencm3, stm32};
use crate::utils::register_hook;
use crate::{engine, utils};

use std::io::Error;
use std::ptr;

/// Stackpointer expected by the target. Mandatory, engine will panic if it's not found.
pub static EMU_SP: u32 = 0x20014000;
/// Entry point to the target. Mandatory, engine will panic if it's not found.
pub static ENTRY: u32 = 0x7c0c;

pub unsafe fn set_hooks() {
    register_hook(0xfec, handlers::return_zero as *const fn()); // write_bootloader_pininit
    register_hook(0xa84, handlers::return_zero as *const fn()); // clock_setup
    register_hook(0x1100, handlers::return_zero as *const fn()); // rtc_setup
    register_hook(0x1118, handlers::return_zero as *const fn()); // tim_setup
    register_hook(0x2f34, handlers::return_zero as *const fn()); // AnaIn::Start
    register_hook(0x32a4, handlers::return_zero as *const fn()); // parm_load
    register_hook(0x4308, handlers::return_zero as *const fn()); // Can::Can
    register_hook(0x2acc, handlers::return_zero as *const fn()); // Encoder::UpdateRotorAngle
    register_hook(0x6c62, handlers::return_non_zero as *const fn()); // dma_get_interrupt_flag
    register_hook(0xb80, libopencm3::detect_hw as *const fn());
    register_hook(0x7be4, libopencm3::usart_send as *const fn());
    register_hook(0x6d1e, libopencm3::dma_set_memory_address as *const fn());
    register_hook(0x6d30, libopencm3::dma_get_number_of_data as *const fn());
    register_hook(0x6c28, libopencm3::desig_get_flash_size as *const fn());

    register_hook(0x667c, handlers::nop as *const fn()); // adc_reset_calibration
    register_hook(0x7bf4, handlers::nop as *const fn()); // usart_wait_send_ready
    register_hook(0x3d1c, handlers::nop as *const fn()); // Can::ClearMap

    register_hook(0x7caa, utils::exit_hook_ok as *const fn()); // scb_reset_system

    // register_hook_noreturn(0x4160, libopencm3::dbg_print_args as *const fn()); // Can::ReplaceParamEnumByUid
}

/// Reset global variables used in the harness and modified memory such as data (REL) sections
pub unsafe fn reset() {
    stm32::SYSTEM_START_TIME = 0;

    crate::engine::NUM_CURR_BRANCHES = 0;

    ptr::copy_nonoverlapping(engine::BINARY.as_ptr() as *const u8, 0x0 as *mut u8, 0x1000);

    // re-copy data segment
    ptr::copy_nonoverlapping(
        engine::BINARY[0xb2f4..].as_ptr() as *const u8,
        0x20000000 as *mut u8,
        0xff8,
    );
    // null bss
    ptr::write_bytes(0x20000ff8 as *mut u8, 0_u8, 1000 as usize);

    // clear DMA
    for entry in libopencm3::DMA_BACKINGS.iter() {
        ptr::write_bytes(*entry as *mut u8, 0_u8, 128);
    }
    libopencm3::DMA_BACKINGS = [0; 32];

    // set up flash size
    ptr::write(0x1ffff7e0_u32 as *mut u16, 1337_u16);
}

/// Map all memory sections for cortex-m3
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

    // map code a second time at known offset for absolute data accesses
    let code_segment_addr_dup = libc::mmap(
        0x8001000 as _,
        code_len,
        libc::PROT_READ | libc::PROT_WRITE,
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

    let flash_size = libc::mmap(
        0x1fff0000 as _,
        0x000010000,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    );

    let flash = libc::mmap(
        0x814d000 as _,
        0x000001000,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    );

    if code_segment_addr as i64 == 0xffffffff
        || ram as i64 == 0xffffffff
        || mmio as i64 == 0xffffffff
        || nvic as i64 == 0xffffffff
        || flash as i64 == 0xffffffff
        || flash_size as i64 == 0xffffffff
        || handlers::MALLOC_CHUNK_TOP as i64 == 0xffffffff + (malloc_chunk_size - 1) as i64
    {
        Err(format!("mmap error: {:?}", Error::last_os_error()))
    } else {
        crate::engine::OFFSET = 0x08001000;

        ptr::copy_nonoverlapping(
            code.as_ptr() as *const u8,
            code_segment_addr as *mut u8,
            code_len,
        );

        ptr::copy_nonoverlapping(
            code.as_ptr() as *const u8,
            code_segment_addr_dup as *mut u8,
            code_len,
        );

        Ok(())
    }
}
