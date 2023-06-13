use crate::engine;
use crate::handlers::{self, stm32, wifi};
use crate::utils::{exit_hook_timeout, register_hook, register_hook_noreturn};

use std::io::Error;
use std::ptr;

pub static EMU_SP: u32 = 0x20018000;
pub static ENTRY: u32 = 0x1ad0;

pub unsafe fn set_hooks() {
    register_hook(0x1c74, handlers::return_zero as *const fn()); // HAL_Init
    register_hook(0x1261c, handlers::return_zero as *const fn()); // SystemClock_Config
    register_hook(0x1b20, handlers::return_zero as *const fn()); // SystemInit
    register_hook(0x6f28, handlers::return_zero as *const fn()); // HAL_RCC_ClockConfig
    register_hook(0x41d0, handlers::stm32::systick_config as *const fn()); // HAL_SYSTICK_Config
    register_hook(0x4388, handlers::nop as *const fn()); // HAL_SYSTICK_CLKSourceConfig
    register_hook(0xc950, handlers::return_zero as *const fn()); // HAL_TIM_ConfigClockSource
    register_hook(0xeb5c, handlers::return_zero as *const fn()); // HAL_TIMEx_MasterConfigSynchronization
    register_hook(
        0x9ce0,
        handlers::stm32::hal_tim_base_start_it as *const fn(),
    );
    register_hook(0x9d18, handlers::stm32::hal_tim_base_stop_it as *const fn());
    register_hook(0xbb2c, handlers::stm32::hal_tim_irq_handler as *const fn());
    register_hook(0xa510, handlers::return_zero as *const fn()); // HAL_TIM_PWM_Init
    register_hook(0xbf34, handlers::return_zero as *const fn()); // HAL_TIM_PWM_ConfigChannel
    register_hook(0xa5f0, handlers::return_zero as *const fn()); // HAL_TIM_PWM_Start
    register_hook(0xebe8, handlers::return_zero as *const fn()); // HAL_TIMEx_ConfigBreakDeadTime
    register_hook(0x145b8, handlers::wifi::wifi_init as *const fn());
    register_hook(0x1569c, handlers::nop as *const fn()); // wifi_wakeup
    register_hook(0x1661c, handlers::nop as *const fn()); // Wifi_SysTick_Isr
    register_hook(0x15d34, handlers::wifi::wifi_tim_handler as *const fn());
    register_hook(
        0x14ea4,
        handlers::wifi::wifi_socket_server_open as *const fn(),
    );
    register_hook(
        0x14ef8,
        handlers::wifi::wifi_socket_server_write as *const fn(),
    );
    register_hook(0x153c0, handlers::nop as *const fn()); // wifi_ap_start
    register_hook(0x15ce8, handlers::nop as *const fn()); // Receive_Data
    register_hook(0x5e24, handlers::nop as *const fn()); // HAL_GPIO_Init
    register_hook(0x6314, handlers::nop as *const fn()); // HAL_GPIO_WritePin
    register_hook(0xed90, handlers::return_zero as *const fn()); // HAL_UART_Init
    register_hook(0xf3fc, handlers::stm32::hal_uart_receive_it as *const fn());
    register_hook_noreturn(0xf0f4, handlers::stm32::hal_uart_transmit as *const fn());
    register_hook(0xfcdc, handlers::stm32::hal_uart_irq_handler as *const fn());
    register_hook(0x19178, exit_hook_timeout as *const fn()); // BSP_LED_On

    register_hook(0x1c0e4, handlers::malloc_r as *const fn());
    register_hook(0x2679c, handlers::realloc_r as *const fn());
    register_hook(0x1be4c, handlers::free_r as *const fn());

    // register_hook_noreturn(0x1d7c, crate::utils::trigger_tick as *const fn()); // HAL_Delay
    register_hook(0x1d7c, stm32::hal_get_tick as *const fn()); // HAL_Delay

    // register_hook_noreturn(0x1c5f0, crate::utils::print_args_hook as *const fn());
}

pub unsafe fn reset() {
    stm32::SYSTEM_START_TIME = 0;
    stm32::STM32_TIM = 0xffffffff;
    wifi::TCP_MODEL = wifi::TCPModel::new();

    ptr::copy_nonoverlapping(engine::BINARY.as_ptr() as *const u8, 0x0 as *mut u8, 0x1000);
    ptr::copy_nonoverlapping(
        engine::BINARY[0x2917c..].as_ptr() as *const u8,
        0x20000000 as *mut u8,
        0x940,
    );

    crate::engine::IRQ_ENABLED = true;
    crate::engine::NUM_CURR_BRANCHES = 0;
    crate::engine::TIMERS.clear();

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

    // map code a second time at known offset for absolute data accesses
    let code_segment_addr_dup = libc::mmap(
        0x8000000 as _,
        code_len,
        libc::PROT_READ | libc::PROT_WRITE,
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
        crate::engine::OFFSET = 0x8000000;
        stm32::HAL_UART_RX_CALLBACK_ADDR = 0x12e40;
        stm32::HAL_TIM_PERIOD_ELAPSED_CALLBACK_ADDR = 0x12d90;
        wifi::IND_WIFI_CONNECTED_ADDR = 0x128ec;
        wifi::IND_SOCKET_SERVER_CLIENT_JOINED_ADDR = 0x12904;
        wifi::IND_SOCKET_SERVER_CLIENT_LEFT_ADDR = 0x12934;
        wifi::IND_WIFI_SOCKET_DATA_RECEIVED_ADDR = 0x12824;

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
