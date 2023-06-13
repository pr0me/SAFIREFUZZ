use crate::handlers::{self, stm32};
use crate::utils::{self, register_hook, register_hook_noreturn};

use std::io::Error;
use std::ptr;

// These are being accessed by the gngine, they are mandatory
pub static EMU_SP: u32 = 0x20014000;
pub static ENTRY: u32 = 0x52b4;

/// Register all the function-level hooks your firmware will need to run
pub unsafe fn set_hooks() {
    register_hook(0x5b1c, handlers::realloc_r as *const fn());
    register_hook(0x59c8, handlers::free_r as *const fn());
    register_hook(0x5a60, handlers::malloc_r as *const fn());

    // register_hook(0x26e8, handlers::return_zero as *const fn()); // UART_WaitOnFlagUntilTimeout

    register_hook(0x1128, handlers::return_zero as *const fn()); // HAL_Init
    register_hook(0x1104, handlers::return_zero as *const fn()); // HAL_InitTick
    register_hook(0x4834, handlers::return_zero as *const fn()); // SystemClock_Config
    register_hook(0x525c, handlers::return_zero as *const fn()); // SystemInit
    register_hook(0x2070, handlers::return_zero as *const fn()); // HAL_RCC_ClockConfig
    register_hook(0x1b2c, handlers::return_zero as *const fn()); // HAL_RCC_OscConfig
    register_hook(0x2568, handlers::return_zero as *const fn()); // HAL_TIMEx_MasterConfigSynchronization
    register_hook(0x2394, handlers::return_zero as *const fn()); // HAL_TIM_PWM_Init
    register_hook(0x2420, handlers::return_zero as *const fn()); // HAL_TIM_PWM_ConfigChannel
    register_hook(0x24fc, handlers::return_zero as *const fn()); // HAL_TIM_PWM_Start
    register_hook(0x2528, handlers::return_zero as *const fn()); // HAL_TIMEx_ConfigBreakDeadTime
    register_hook(0x17a0, handlers::return_zero as *const fn()); // HAL_I2C_Init
    register_hook(0x1874, handlers::return_zero as *const fn()); // HAL_I2C_Mem_Write
    register_hook(0x2748, handlers::return_zero as *const fn()); // HAL_UART_Init
    register_hook(0x1278, handlers::nop as *const fn()); // HAL_GPIO_Init
    register_hook(0x1438, handlers::nop as *const fn()); // HAL_GPIO_WritePin
    register_hook(0x1168, handlers::nop as *const fn()); // HAL_Delay
    register_hook(0x1254, handlers::nop as *const fn()); // HAL_SYSTICK_CLKSourceConfig

    register_hook(0x1228, handlers::stm32::systick_config as *const fn());
    register_hook(0x1964, handlers::stm32::hal_i2c_mem_read as *const fn());
    register_hook(0x2856, handlers::stm32::hal_uart_receive_it as *const fn());
    register_hook(0x27a0, handlers::stm32::hal_uart_transmit as *const fn());
    register_hook(0x28be, handlers::stm32::hal_uart_irq_handler as *const fn());

    register_hook(0x47b0, utils::exit_hook_ok as *const fn()); // _Error_Handler

    register_hook_noreturn(0x4364, utils::trigger_tick as *const fn());
    register_hook_noreturn(0x696, utils::trigger_tick as *const fn());
    register_hook(0x115c, stm32::hal_get_tick as *const fn());
}

/// Reset global variables used in the harness and modified memory such as data (REL) sections
pub unsafe fn reset() {
    stm32::SYSTEM_START_TIME = 0;
    stm32::UART_TIMER = 0xffffffff;
    stm32::UART_RX = false;

    ptr::copy_nonoverlapping(
        crate::engine::BINARY.as_ptr() as *const u8,
        0x0 as *mut _,
        0x10c,
    );

    ptr::copy_nonoverlapping(
        crate::engine::BINARY[0x7798..].as_ptr() as *const u8,
        0x20000000 as *mut u8,
        0x228,
    );

    crate::engine::IRQ_ENABLED = true;
    crate::engine::NUM_CURR_BRANCHES = 0;
    crate::engine::TIMERS.clear();

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
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_FIXED,
        -1,
        0,
    );

    let code_segment_addr_dup = libc::mmap(
        0x8000000 as _,
        0x800000,
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

    if code_segment_addr as i64 == 0xffffffff
        || code_segment_addr_dup as i64 == 0xffffffff
        || ram as i64 == 0xffffffff
        || mmio as i64 == 0xffffffff
        || nvic as i64 == 0xffffffff
        || handlers::MALLOC_CHUNK_TOP as i64 == 0xffffffff + (malloc_chunk_size - 1) as i64
    {
        Err(format!("mmap error: {:?}", Error::last_os_error()))
    } else {
        crate::engine::OFFSET = 0x08000000_u32;
        stm32::HAL_UART_RX_CALLBACK_ADDR = 0x4f7c;
        stm32::HUART1 = 0x20001578;

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
