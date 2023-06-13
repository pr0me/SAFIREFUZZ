use crate::engine;
use crate::handlers::{self, stm32};
use crate::utils::{register_hook, register_hook_noreturn};

use std::io::Error;
use std::ptr;

pub static EMU_SP: u32 = 0x20050000;
pub static ENTRY: u32 = 0x11f0;

pub unsafe fn set_hooks() {
    register_hook(0x24cc, handlers::return_zero as *const fn()); // HAL_Init
    register_hook(0x251c, handlers::return_zero as *const fn()); // HAL_InitTick
    register_hook(0x2470, handlers::return_zero as *const fn()); // SystemInit
    register_hook(0x4db0, handlers::return_zero as *const fn()); // HAL_RCC_ClockConfig
    register_hook(0x5100, handlers::return_zero as *const fn()); // HAL_RCC_OscConfig
    register_hook(0x4d14, handlers::return_zero as *const fn()); // HAL_PWREx_EnableOverDrive
    register_hook(0x27f4, handlers::stm32::systick_config as *const fn()); // HAL_SYSTICK_Config
    register_hook(0x25b8, handlers::nop as *const fn()); // HAL_Delay
    register_hook(0x280c, handlers::return_zero as *const fn()); // HAL_ETH_Init
    register_hook(0x3df4, handlers::return_zero as *const fn()); // HAL_I2C_Init
    register_hook(0x4250, handlers::stm32::hal_i2c_mem_read as *const fn());
    register_hook(0x403c, handlers::return_zero as *const fn()); // HAL_I2C_Mem_Write
    register_hook(0x3a48, handlers::nop as *const fn()); // HAL_GPIO_Init
    register_hook(0x3d94, handlers::nop as *const fn()); // HAL_GPIO_WritePin
    register_hook(0x6f1c, handlers::nop as *const fn()); // BSP_IO_ConfigPin
    register_hook(0xa2a4, handlers::return_zero as *const fn()); // tcp_next_iss
    register_hook(0x49b8, handlers::return_zero as *const fn()); // I2C_WaitOnFlagUntilTimeout
    register_hook(0x4a5c, handlers::return_zero as *const fn()); // I2C_WaitOnMasterAddressFlagUntilTimeout
    register_hook(0x4b38, handlers::return_zero as *const fn()); // I2C_WaitOnTXEFlagUntilTimeout
    register_hook(0x4bb4, handlers::return_zero as *const fn()); // I2C_WaitOnBTFFlagUntilTimeout
    register_hook(0x4c30, handlers::return_zero as *const fn()); // I2C_WaitOnRXNEFlagUntilTimeout
    register_hook(
        0x2cf4,
        handlers::stm32::hal_eth_transmit_frame as *const fn(),
    );
    register_hook(
        0x2ec8,
        handlers::stm32::hal_eth_get_received_frame as *const fn(),
    );
    register_hook(
        0x30a4,
        handlers::stm32::hal_eth_write_phy_register as *const fn(),
    );
    register_hook(
        0x2fd4,
        handlers::stm32::hal_eth_read_phy_register as *const fn(),
    );
    register_hook_noreturn(
        0x19ec,
        handlers::stm32::inject_button_click_once as *const fn(),
    ); // ethernetif_input
    register_hook(0x25a0, handlers::stm32::hal_get_tick as *const fn());

    register_hook(0x15b2c, handlers::malloc_r as *const fn());
    register_hook(0x16fec, handlers::realloc_r as *const fn());
    register_hook(0x15830, handlers::free_r as *const fn());
    register_hook(0x11858, handlers::_memset as *const fn());
}

pub unsafe fn reset() {
    stm32::SYSTEM_START_TIME = 0;
    stm32::PHY_REGS = [0; 64];
    stm32::ETHERNET_MODEL = handlers::ethernet::EthernetModel::new();
    stm32::BUTTON_CLICKED = false;

    ptr::copy_nonoverlapping(engine::BINARY.as_ptr() as *const u8, 0x0 as *mut u8, 0x1000);
    ptr::copy_nonoverlapping(
        engine::BINARY[0x1d844..].as_ptr() as *const u8,
        0x20000000 as *mut u8,
        0x9a4,
    );

    crate::engine::IRQ_ENABLED = false;
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
        0x00050000,
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
        stm32::HAL_GPIO_EXTI_CALLBACK_ADDR = 0x1cc4;
        stm32::EXTI15_IRQ_HANDLER_ADDR = 0x1e4c;

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
