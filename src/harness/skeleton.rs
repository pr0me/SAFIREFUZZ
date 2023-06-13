use crate::handlers::{self, stm32};
use crate::utils::register_hook;

use std::io::Error;
use std::ptr;

/// Stackpointer expected by the target. Mandatory, engine will panic if it's not found.
pub static EMU_SP: u32 = 0x20014000;
/// Entry point to the target. Mandatory, engine will panic if it's not found.
pub static ENTRY: u32 = 0x2214;


/// Register all the function-level hooks your firmware will need to run
pub unsafe fn set_hooks() {
    // Example
    register_hook(0x969e, handlers::realloc_r as *const fn());
    register_hook(0x8b1c, handlers::free_r as *const fn());
    register_hook(0x8bb0, handlers::malloc_r as *const fn());
}

/// Called before _every_ execution. 
/// Reset global variables used in the harness and modified memory such as data (REL) sections
pub unsafe fn reset() {
    stm32::SYSTEM_START_TIME = 0;

    // enable interrupts/timers
    crate::engine::IRQ_ENABLED = true;
    crate::engine::NUM_CURR_BRANCHES = 0;
    crate::engine::TIMERS.clear();

    // reset allocator stuff
    handlers::MALLOC_CHUNK_CURR_PTR = handlers::MALLOC_CHUNK_TOP;
    handlers::FREED_PREV.clear();

    // ...
}

/// Called once before the first execution.
/// Map all the memory section your firmware needs
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

    // Example for a cortex-m
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

    if code_segment_addr as i64 == 0xffffffff
        || ram as i64 == 0xffffffff
        || mmio as i64 == 0xffffffff
        || nvic as i64 == 0xffffffff
        || handlers::MALLOC_CHUNK_TOP as i64 == 0xffffffff + (malloc_chunk_size - 1) as i64
    {
        Err(format!("mmap error: {:?}", Error::last_os_error()))
    } else {
        crate::engine::OFFSET = 0x0;

        // put the input binary at the correct position
        ptr::copy_nonoverlapping(
            code.as_ptr() as *const u8,
            code_segment_addr as *mut u8,
            code_len,
        );

        Ok(())
    }
}
