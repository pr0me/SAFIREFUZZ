use crate::engine;
use crate::handlers::{self, stm32};
use crate::utils::{exit_hook_ok, register_hook};

use std::io::Error;
use std::ptr;

pub static EMU_SP: u32 = 0x20014000;
pub static ENTRY: u32 = 0xba7c;

pub unsafe fn set_hooks() {
    register_hook(0xcf64, handlers::return_zero as *const fn()); // SetSysClock
    register_hook(0xbb3c, handlers::return_zero as *const fn()); // HAL_GPIO_Init
    register_hook(0xbb0c, stm32::hal_get_tick as *const fn());
    register_hook(0xbd40, handlers::return_zero as *const fn()); // HAL_RCC_OscConfig
    register_hook(0xc3c8, handlers::return_zero as *const fn()); // HAL_RCC_ClockConfig
    register_hook(0xc74c, stm32::hal_rtc_getdate as *const fn());
    register_hook(0xc7d8, handlers::return_zero as *const fn()); // HAL_RTC_Init
    register_hook(0xc864, handlers::return_zero as *const fn()); // HAL_RTC_SetTime
    register_hook(0xc998, handlers::return_zero as *const fn()); // HAL_RTC_SetDate
    register_hook(0xce48, handlers::return_zero as *const fn()); // SetSysClock_PLL_HSE
    register_hook(0xcaac, stm32::hal_rtc_gettime as *const fn());
    register_hook(0xcd64, handlers::return_zero as *const fn()); // HAL_UART_Init
    register_hook(0xd1ac, stm32::serial_putc as *const fn());
    register_hook(0xd358, stm32::mbed_write as *const fn()); // mbed::Stream::write
    register_hook(0xd194, stm32::uart_tx as *const fn()); // serial_getc
    register_hook(0xd428, stm32::uart_tx as *const fn()); // mbed::Stream::getc
    register_hook(0xd58c, stm32::mbed_get_time as *const fn()); // time
    register_hook(0xd63c, handlers::return_zero as *const fn()); // wait_ms
    register_hook(0xd90c, stm32::mbed_get_time as *const fn()); // rtc_read
    register_hook(0xd96c, stm32::mbed_set_time as *const fn()); // rtc_write
    register_hook(0xf298, handlers::malloc_r as *const fn());
    register_hook(0x15750, handlers::realloc_r as *const fn());
    register_hook(0xf20c, handlers::free_r as *const fn());
    register_hook(0xb5c0, exit_hook_ok as *const fn()); // exit after main loop iteration
    register_hook(0xdbd0, exit_hook_ok as *const fn()); // literally exit
}

pub unsafe fn reset() {
    stm32::LAST_TIME = 1234567;
    stm32::SYSTEM_START_TIME = 0;

    ptr::copy_nonoverlapping(engine::BINARY.as_ptr() as *const u8, 0x0 as *mut u8, 0x1000);
    // libc::memcpy(0x2000013c as *mut u8, 0x18e04 as *mut u8, 348);
    ptr::copy_nonoverlapping(
        engine::BINARY[0x18e04..].as_ptr() as *const u8,
        0x2000013c as *mut u8,
        348,
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
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    );

    // map code a second time at known offset for absolute data accesses
    let code_segment_addr_dup = libc::mmap(
        0x8000000 as _,
        code_len,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    );

    let malloc_chunk_size: u32 = 32 * 1000000;
    handlers::MALLOC_CHUNK_TOP = libc::mmap(
        0x0 as _,
        malloc_chunk_size as _,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED,
        -1,
        0,
    ) as u32
        + malloc_chunk_size;
    handlers::MALLOC_CHUNK_CURR_PTR = handlers::MALLOC_CHUNK_TOP;

    // data: 0x2000013c - 0x20000298; bss: 0x20000298 - 0x20000f28
    let data = libc::mmap(
        0x20000000 as _,
        0x1000,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    );

    let stack = libc::mmap(
        0x20001000 as _,
        0x13000,
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
        0xe000e000_u32 as _,
        0x1000,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    );

    if code_segment_addr as i64 == 0xffffffff
        || code_segment_addr_dup as i64 == 0xffffffff
        || stack as i64 == 0xffffffff
        || data as i64 == 0xffffffff
        || mmio as i64 == 0xffffffff
        || nvic as i64 == 0xffffffff
        || handlers::MALLOC_CHUNK_TOP as i64 == 0xffffffff + (malloc_chunk_size - 1) as i64
    {
        Err(format!("mmap error: {:?}", Error::last_os_error()))
    } else {
        crate::engine::OFFSET = 0x8000000;

        libc::memcpy(code_segment_addr as _, code.as_ptr() as _, code_len);
        // region::protect(0x1001 as _, code_len - 0x1000, region::Protection::READ).unwrap();
        libc::memcpy(code_segment_addr_dup as _, code.as_ptr() as _, code_len);

        Ok(())
    }
}
