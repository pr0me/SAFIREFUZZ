use crate::engine;
use crate::handlers::{self, stm32};
use crate::utils::register_hook;

use std::io::Error;
use std::ptr;

pub static EMU_SP: u32 = 0x20050000;
pub static ENTRY: u32 = 0x11f0;

pub unsafe fn set_hooks() {
    register_hook(0x21e4, handlers::return_zero as *const fn()); // HAL_Init
    register_hook(0x2234, handlers::return_zero as *const fn()); // HAL_InitTick
    register_hook(0x2188, handlers::return_zero as *const fn()); // SystemInit
    register_hook(0x4ac8, handlers::return_zero as *const fn()); // HAL_RCC_ClockConfig
    register_hook(0x4e18, handlers::return_zero as *const fn()); // HAL_RCC_OscConfig
    register_hook(0x4a2c, handlers::return_zero as *const fn()); // HAL_PWREx_EnableOverDrive
    register_hook(0x250c, handlers::stm32::systick_config as *const fn()); // HAL_SYSTICK_Config
    register_hook(0x22d0, handlers::nop as *const fn()); // HAL_Delay
    register_hook(0x2524, handlers::return_zero as *const fn()); // HAL_ETH_Init
    register_hook(0x3b0c, handlers::return_zero as *const fn()); // HAL_I2C_Init
    register_hook(0x3f68, handlers::stm32::hal_i2c_mem_read as *const fn());
    register_hook(0x3d54, handlers::return_zero as *const fn()); // HAL_I2C_Mem_Write
    register_hook(0x3760, handlers::nop as *const fn()); // HAL_GPIO_Init
    register_hook(0x3aac, handlers::nop as *const fn()); // HAL_GPIO_WritePin
    register_hook(0x6b0c, handlers::nop as *const fn()); // BSP_IO_ConfigPin
    register_hook(0x46d0, handlers::return_zero as *const fn()); // I2C_WaitOnFlagUntilTimeout
    register_hook(0x4774, handlers::return_zero as *const fn()); // I2C_WaitOnMasterAddressFlagUntilTimeout
    register_hook(0x4850, handlers::return_zero as *const fn()); // I2C_WaitOnTXEFlagUntilTimeout
    register_hook(0x48cc, handlers::return_zero as *const fn()); // I2C_WaitOnBTFFlagUntilTimeout
    register_hook(0x4948, handlers::return_zero as *const fn()); // I2C_WaitOnRXNEFlagUntilTimeout
    register_hook(
        0x2a0c,
        handlers::stm32::hal_eth_transmit_frame as *const fn(),
    );
    register_hook(
        0x2be0,
        handlers::stm32::hal_eth_get_received_frame as *const fn(),
    );
    register_hook(
        0x2dbc,
        handlers::stm32::hal_eth_write_phy_register as *const fn(),
    );
    register_hook(
        0x2cec,
        handlers::stm32::hal_eth_read_phy_register as *const fn(),
    );

    register_hook(0x1370c, handlers::malloc_r as *const fn());
    register_hook(0x14ac8, handlers::realloc_r as *const fn());
    register_hook(0x13410, handlers::free_r as *const fn());
    register_hook(0x10978, handlers::_memset as *const fn());
}

pub unsafe fn reset() {
    stm32::SYSTEM_START_TIME = 0;
    stm32::PHY_REGS = [0; 64];
    stm32::ETHERNET_MODEL = handlers::ethernet::EthernetModel::new();

    ptr::copy_nonoverlapping(engine::BINARY.as_ptr() as *const u8, 0x0 as *mut u8, 0x1000);
    ptr::copy_nonoverlapping(
        engine::BINARY[0x1b28c..].as_ptr() as *const u8,
        0x20000000 as *mut u8,
        0x98c,
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
