use crate::engine;
use crate::handlers::{self, stm32};
use crate::utils::{self, register_hook};

use std::io::Error;
use std::ptr;

/// Stackpointer expected by the target. Mandatory, engine will panic if it's not found.
pub static EMU_SP: u32 = 0x20030000;
/// Entry point to the target. Mandatory, engine will panic if it's not found.
pub static ENTRY: u32 = 0xdd4;

pub unsafe fn set_hooks() {
    register_hook(0xeb00, handlers::realloc_r as *const fn());
    register_hook(0xe2b0, handlers::free_r as *const fn());
    register_hook(0xe388, handlers::malloc_r as *const fn());
    register_hook(0x1f0, handlers::_memchr as *const fn());
    register_hook(0xe2a0, handlers::_memset as *const fn());

    register_hook(0x24e8, handlers::return_zero as *const fn()); // HAL_Init
    register_hook(0x3af0, handlers::return_zero as *const fn()); // HAL_RCC_ClockConfig
    register_hook(0x3a7c, handlers::return_zero as *const fn()); // HAL_PWREx_EnableOverDrive
    register_hook(0x3eac, handlers::return_zero as *const fn()); // HAL_RCC_ClockConfig
    register_hook(0x19ec, handlers::return_zero as *const fn()); // BSP_LED_Init
    register_hook(0x1f5c, handlers::return_zero as *const fn()); // BSP_LCD_Init
    register_hook(0x1c4c, handlers::return_zero as *const fn()); // BSP_LCD_LayerDefaultInit
    register_hook(0x1cc4, handlers::return_zero as *const fn()); // BSP_LCD_SelectLayer
    register_hook(0x1d50, handlers::return_zero as *const fn()); // BSP_LCD_DisplayOn
    register_hook(0x1cd0, handlers::return_zero as *const fn()); // BSP_LCD_SetLayerWindow
    register_hook(0x1d18, handlers::return_zero as *const fn()); // BSP_LCD_Clear
    register_hook(0xec4, handlers::nop as *const fn()); // Jpeg_CallbackFunction (buffers to LCD)
    register_hook(0x654c, handlers::return_zero as *const fn()); // f_close
    register_hook(0x6154, handlers::return_zero as *const fn()); // f_open

    register_hook(0x2534, handlers::stm32::hal_get_tick as *const fn());
    register_hook(0x2540, utils::trigger_tick as *const fn()); // HAL_Delay
    register_hook(0xeb0, handlers::stm32::read_file as *const fn());

    register_hook(0x1010, utils::exit_hook_ok as *const fn()); // while-true after main
    register_hook(0xf0c, utils::exit_hook_ok as *const fn()); // Error_Handler
    register_hook(0x103c, utils::exit_hook_ok as *const fn()); // UsageFault_Handler
    register_hook(0x103a, utils::exit_hook_timeout as *const fn()); // BusFault_Handler
    register_hook(0x1036, utils::exit_hook_timeout as *const fn()); // HardFault_Handler
    register_hook(0xbc82, utils::exit_hook_ok as *const fn()); // error_exit: should exit, but does not
}

/// Reset global variables used in the harness and modified memory
pub unsafe fn reset() {
    stm32::SYSTEM_START_TIME = 0;
    stm32::STM32_TIM = 0xffffffff;

    ptr::copy_nonoverlapping(engine::BINARY.as_ptr() as *const u8, 0x0 as *mut u8, 0x1000);

    // re-copy data segment
    ptr::copy_nonoverlapping(
        engine::BINARY[0x14a5c..].as_ptr() as *const u8,
        0x20000000 as *mut u8,
        0x148,
    );

    // reset allocator stuff
    handlers::MALLOC_CHUNK_CURR_PTR = handlers::MALLOC_CHUNK_TOP;
    handlers::FREED_PREV.clear();
}

/// Map all the memory segments
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

    let code_segment_addr_dup = libc::mmap(
        0x8000000 as _,
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

    // data: 0x20000000 - 0x20000230; bss: 0x20000230 - 0x200053c0;
    let ram = libc::mmap(
        0x20000000 as _,
        0x10000,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    );

    // initial_sp: 0x20030000
    let stack = libc::mmap(
        0x20020000 as _,
        0x10000,
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
        || code_segment_addr_dup as i64 == 0xffffffff
        || ram as i64 == 0xffffffff
        || mmio as i64 == 0xffffffff
        || nvic as i64 == 0xffffffff
        || handlers::MALLOC_CHUNK_TOP as i64 == 0xffffffff + (malloc_chunk_size - 1) as i64
    {
        Err(format!("mmap error: {:?}", Error::last_os_error()))
    } else {
        crate::engine::OFFSET = 0x8000000;

        // put the input binary at the correct position
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
