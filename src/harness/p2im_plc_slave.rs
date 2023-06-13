#![allow(unused_imports)]

use crate::handlers::{self, arduino, stm32};
use crate::utils::{self, exit_hook_ok, register_hook};

use std::io::Error;
use std::ptr;

// These are being accessed by the gngine, they are mandatory
pub static EMU_SP: u32 = 0x20030000;
pub static ENTRY: u32 = 0xd1c;

/// Register all the function-level hooks your firmware will need to run
pub unsafe fn set_hooks() {
    register_hook(0xf08, handlers::nop as *const fn()); // HAL_SYSTICK_CLKSourceConfig
    register_hook(0xf90, handlers::nop as *const fn()); // HAL_GPIO_Init
    register_hook(0x1174, handlers::nop as *const fn()); // HAL_GPIO_WritePin
    register_hook(0xf08, handlers::nop as *const fn()); // HAL_SYSTICK_CLKSourceConfig

    register_hook(0xdc0, handlers::return_zero as *const fn()); // HAL_init
    register_hook(0xd74, handlers::return_zero as *const fn()); // HAL_initTick
    register_hook(0xc68, handlers::return_zero as *const fn()); // SystemClock_Config
    register_hook(0x3598, handlers::return_zero as *const fn()); // SystemInit
    register_hook(0x2464, handlers::return_zero as *const fn()); // HAL_RCC_ClockConfig
    register_hook(0x1ff8, handlers::return_zero as *const fn()); // HAL_RCC_OscConfig
    register_hook(0x1f78, handlers::return_zero as *const fn()); // HAL_PWREx_EnableOverDrive
    register_hook(0xebc, handlers::stm32::systick_config as *const fn()); // HAL_SYSTICK_Config
    register_hook(0x26aa, handlers::stm32::hal_tim_irq_handler as *const fn()); // HAL_TIM_IRQHandler
    register_hook(0x2ce8, handlers::return_zero as *const fn()); // UART_WaitOnFlagUntilTimeout
    register_hook(0x2d4e, handlers::return_zero as *const fn()); // HAL_UART_Init
    register_hook(0x2ed6, handlers::stm32::hal_uart_receive_it as *const fn()); // HAL_UART_Receive_IT
    register_hook(0x2dac, handlers::stm32::hal_uart_transmit as *const fn()); // HAL_UART_Transmit
    register_hook(0x2fd8, handlers::stm32::hal_uart_irq_handler as *const fn()); // HAL_UART_IRQHandler
    register_hook(0xe0c, handlers::stm32::hal_get_tick as *const fn()); // HAL_GetTick

    register_hook(0x4624, handlers::nop as *const fn()); // premain
    register_hook(0x4e10, handlers::arduino::millis as *const fn());
    register_hook(0x4364, handlers::nop as *const fn()); // HardwareSerial::begin
    register_hook(0x424c, handlers::arduino::serial_read as *const fn());
    register_hook(0x42c4, handlers::arduino::puts as *const fn());
    register_hook(0x459a, handlers::arduino::puts as *const fn());
    register_hook(
        0x421c,
        handlers::arduino::hardware_serial_available as *const fn(),
    );
    register_hook(0x708, handlers::arduino::calc_crc as *const fn()); // modbus::calcCRC
    register_hook(0x40ec, handlers::return_zero as *const fn()); // pinMode
    register_hook(0x4198, handlers::return_zero as *const fn()); // digitalWrite

    register_hook(0x48a8, handlers::_memset as *const fn());
    register_hook(0x48b8, handlers::free_r as *const fn());
    register_hook(0x4954, handlers::malloc_r as *const fn());
}

/// Called _before_ every execution.
/// Reset global variables used in the harness and modified memory such as data (REL) sections
pub unsafe fn reset() {
    stm32::SYSTEM_START_TIME = 0;
    stm32::UART_TIMER = 0xffffffff;
    stm32::UART_RX = false;
    arduino::SERIAL_LINE = arduino::SerialModel::new();
    arduino::TICKS = 0;
    arduino::TICK_MOD = 2;
    arduino::COLLECTED_PKT = false;
    arduino::LAST_BYTES_AVAIL = 0;
    arduino::SERIAL_AVAILABLE_ROUND = 0;

    ptr::copy_nonoverlapping(
        crate::engine::BINARY.as_ptr() as *const u8,
        0x0 as *mut _,
        0x1a0,
    );

    ptr::copy_nonoverlapping(
        crate::engine::BINARY[0x6010..].as_ptr() as *const u8,
        0x20000000 as *mut u8,
        0x104,
    );

    // enable interrupts/timers
    crate::engine::IRQ_ENABLED = true;
    crate::engine::NUM_CURR_BRANCHES = 0;
    crate::engine::TIMERS.clear();
    utils::enable_timer(256, arduino::loop_detection_heuristic, 0);

    handlers::MALLOC_CHUNK_CURR_PTR = handlers::MALLOC_CHUNK_TOP;
    handlers::FREED_PREV.clear();
}

/// Called once before the first execution.
/// Map all the memory section your firmware needs
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

    // _user_heap_stack
    let malloc_chunk_size: u32 = 9336;
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

    // data: 0x20000000 - 0x20000104; bss: 0x20000104 - 0x20000678; initial_sp: 0x20030000
    let ram = libc::mmap(
        0x20000000 as _,
        0x30000,
        // 0x400000,
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

    let flash = libc::mmap(
        0x08000000_u32 as _,
        0x800000,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED,
        -1,
        0,
    );

    if code_segment_addr as i64 == 0xffffffff
        || ram as i64 == 0xffffffff
        || mmio as i64 == 0xffffffff
        || nvic as i64 == 0xffffffff
        || flash as i64 == 0xffffffff
        || handlers::MALLOC_CHUNK_TOP as i64 == 0xffffffff + (malloc_chunk_size - 1) as i64
    {
        Err(format!("mmap error: {:?}", Error::last_os_error()))
    } else {
        crate::engine::OFFSET = 0x08000000_u32;
        stm32::HAL_UART_RX_CALLBACK_ADDR = 0x3f00;
        stm32::HAL_TIM_PERIOD_ELAPSED_CALLBACK_ADDR = 0x374a;
        stm32::EXTI15_IRQ_HANDLER_ADDR = 0x4784;

        ptr::copy_nonoverlapping(
            code.as_ptr() as *const u8,
            code_segment_addr as *mut u8,
            code_len,
        );
        ptr::copy_nonoverlapping(code.as_ptr() as *const u8, flash as *mut u8, code_len);

        Ok(())
    }
}
