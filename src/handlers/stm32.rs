#![allow(dead_code)]
#![allow(unused_imports)]

use crate::engine::{rewrite_bb, FUZZ_INDEX, FUZZ_INPUT, FUZZ_LEN, O2N_CACHE, RECOMPILED_CODE_TOP};
use crate::handlers::{ethernet::EthernetModel, puts};
use crate::utils;
use core::{arch::asm, ptr};
use libc::memcpy;

static mut DUMMY_DATE_STRUCT: [u8; 4] = [0x01, 0x01, 0x01, 0x18];
static mut DUMMY_TIME_STRUCT: [u8; 20] = [0x00; 20];
pub static mut UART_TIMER: usize = 0xffffffff;
pub static mut STM32_TIM: usize = 0xffffffff;
pub static mut UART_RX: bool = false;
pub static mut HAL_UART_RX_CALLBACK_ADDR: u32 = 0;
pub static mut HAL_TIM_PERIOD_ELAPSED_CALLBACK_ADDR: u32 = 0;
pub static mut HAL_GPIO_EXTI_CALLBACK_ADDR: u32 = 0;
pub static mut EXTI15_IRQ_HANDLER_ADDR: u32 = 0;
pub static mut HUART1: u32 = 0;
pub static mut SYSTEM_START_TIME: u32 = 0;
pub static mut LAST_TIME: u32 = 12345678;
pub static mut ETHERNET_MODEL: EthernetModel = EthernetModel::new();
pub static mut PHY_REGS: [u32; 64] = [0; 64];
pub static mut IF_ID: u32 = 0;
pub static mut BUTTON_CLICKED: bool = false;

const OFF_RX_DESC: u32 = 40;
const OFF_TX_DESC: u32 = 44;
const OFF_DMA_RX_FRAME_INFOS: u32 = 48;
const OFF_DMA_DESC_BUF_1_ADDR: u32 = 8;
const OFF_DMA_DESC_BUG_2_NEXT_DESC_ADDR: u32 = 12;

/// Enables interrupts and sets default callback
pub unsafe fn systick_config() -> u32 {
    #[cfg(feature = "dbg_prints")]
    println!("SYSTICK CONFIG");
    crate::engine::IRQ_ENABLED = true;
    utils::enable_timer(256, systick_irq_handler, 0);
    0
}

#[naked]
unsafe extern "aapcs" fn _invoke_exti15_isr(target_addr: u32) {
    asm!("mov pc, r0", options(noreturn))
}

pub unsafe fn systick_irq_handler() {
    // systick = IRQ 15
    if EXTI15_IRQ_HANDLER_ADDR == 0 {
        panic!("[X] Aborting. Please set the address of `EXTI15_10_IRQHandler` in your harness")
    }

    let isr_resolved_addr: u32;
    let cache_index = (EXTI15_IRQ_HANDLER_ADDR >> 1) as usize;
    if O2N_CACHE[cache_index] != 0 {
        isr_resolved_addr = O2N_CACHE[cache_index];
    } else {
        isr_resolved_addr = RECOMPILED_CODE_TOP;
        rewrite_bb(EXTI15_IRQ_HANDLER_ADDR);
    }
    _invoke_exti15_isr(isr_resolved_addr | 1);
}

pub unsafe fn uart_tx() -> u32 {
    let b = utils::return_fuzz_byte() as u32;
    #[cfg(feature = "dbg_prints")]
    println!("uart_tx: {:#x}", b);
    b
}

pub unsafe fn mbed_write(_ptr: u32, size: u32) -> u32 {
    #[cfg(feature = "dbg_prints")]
    println!("{:?}", std::ffi::CStr::from_ptr(_ptr as _));
    size
}

pub fn serial_putc(_: u32, c: u8) -> u8 {
    #[cfg(feature = "dbg_prints")]
    print!("{}", c as char);
    c
}

pub unsafe fn serial_puts(_: u32, _buf: u32) -> u32 {
    #[cfg(feature = "dbg_prints")]
    puts(_buf);
    1_u32
}

#[naked]
unsafe extern "aapcs" fn _invoke_period_elapsed_cb(timer_obj: u32, target_addr: u32) {
    asm!("mov pc, r1", options(noreturn))
}

pub unsafe fn hal_tim_irq_handler(timer_obj: u32) {
    let cb_resolved_addr: u32;

    if HAL_TIM_PERIOD_ELAPSED_CALLBACK_ADDR == 0 {
        panic!("[X] Aborting. Please set the address of `HAL_TIM_PeriodElapsedCallback` in your harness")
    }

    let cache_index = (HAL_TIM_PERIOD_ELAPSED_CALLBACK_ADDR >> 1) as usize;
    if O2N_CACHE[cache_index] != 0 {
        cb_resolved_addr = O2N_CACHE[cache_index];
    } else {
        cb_resolved_addr = RECOMPILED_CODE_TOP;
        rewrite_bb(HAL_TIM_PERIOD_ELAPSED_CALLBACK_ADDR);
    }
    _invoke_period_elapsed_cb(timer_obj, cb_resolved_addr | 1);
}

pub unsafe fn hal_tim_base_start_it(_timer_obj: u32) -> u32 {
    #[cfg(feature = "dbg_prints")]
    {
        let timer_base = ptr::read_unaligned(_timer_obj as *const u32);
        println!("STM32_TIM start, base: {:#x}", timer_base);
    }

    if STM32_TIM == 0xffffffff {
        STM32_TIM = utils::enable_timer(256, tim3_irq_handler, 0);
    }

    0
}

pub unsafe fn hal_tim_base_stop_it(_timer_obj: u32) -> u32 {
    if STM32_TIM != 0xffffffff {
        #[cfg(feature = "dbg_prints")]
        {
            let timer_base = ptr::read_unaligned(_timer_obj as *const u32);
            println!(
                "STM32_TIM stop, base: {:#x} ({:#x})",
                timer_base, _timer_obj
            );
        }
        utils::disable_timer(STM32_TIM);
        STM32_TIM = 0xffffffff;
    }

    0
}

/// Corresponds to ISR 45. Triggers HAL_TIM_IRQHandler with the right argument.
pub unsafe fn tim3_irq_handler() {
    // `TimHandle` specific to st-plc
    hal_tim_irq_handler(0x20004594);
}

pub unsafe fn hal_get_tick() -> u32 {
    utils::trigger_tick();
    SYSTEM_START_TIME += 10000;
    SYSTEM_START_TIME
}

pub unsafe fn hal_init_tick() -> u32 {
    // SYSTEM_START_TIME = SystemTime::now();
    SYSTEM_START_TIME = 0;
    0
}

pub unsafe fn hal_rtc_getdate(rtc_handle_ptr: u32) -> u32 {
    memcpy(rtc_handle_ptr as _, DUMMY_DATE_STRUCT.as_ptr() as _, 4);
    0
}

pub unsafe fn hal_rtc_gettime(rtc_handle_ptr: u32) -> u32 {
    memcpy(rtc_handle_ptr as _, DUMMY_TIME_STRUCT.as_ptr() as _, 20);
    0
}

pub unsafe fn hal_uart_transmit(uart_msg_handle: u32) {
    let instance_ptr: u32 = *(uart_msg_handle as *const u32);
    if instance_ptr == 0 {
        #[cfg(feature = "dbg_prints")]
        println!("[!] UART instance is NULL: crashing");
        utils::exit_hook_timeout();
    } else {
        // crash if reading from unmapped
        let mut byte: u8 = 0;
        ptr::copy_nonoverlapping(instance_ptr as *const u8, &mut byte as *mut u8, 1);
    }
}

pub unsafe fn hal_uart_receive_it(_uart_msg_handle: u32, buf: u32, len: u32) -> u32 {
    assert!(buf != 0);
    if FUZZ_INDEX + len < FUZZ_LEN {
        #[cfg(feature = "dbg_prints")]
        println!(
            "RX :: {:?}",
            &FUZZ_INPUT[FUZZ_INDEX as usize..(FUZZ_INDEX + len) as usize]
        );
        ptr::copy_nonoverlapping(
            FUZZ_INPUT[FUZZ_INDEX as usize..(FUZZ_INDEX + len) as usize].as_ptr(),
            buf as *mut u8,
            len as usize,
        );
        FUZZ_INDEX += len;
    } else {
        #[cfg(feature = "dbg_prints")]
        println!("Ran out of fuzz :: rx");
        utils::exit_hook_ok();
        unreachable!();
    }

    if UART_TIMER == 0xffffffff {
        UART_TIMER = utils::enable_timer(128, hal_uart_irq_handler, 0);
    }

    0
}

#[naked]
unsafe extern "aapcs" fn _invoke_rx_cplt_cb(index: u32, target_addr: u32) {
    asm!("mov pc, r1", options(noreturn))
}

pub unsafe fn hal_uart_irq_handler() {
    if HUART1 == 0 {
        panic!("[X] Aborting. Please set the address of `huart1` in your harness")
    } else if HAL_UART_RX_CALLBACK_ADDR == 0 {
        panic!("[X] Aborting. Please set the address of `HAL_UART_RxCpltCallback` in your harness")
    }

    let cb_resolved_addr: u32;
    let cache_index = (HAL_UART_RX_CALLBACK_ADDR >> 1) as usize;
    if O2N_CACHE[cache_index] != 0 {
        cb_resolved_addr = O2N_CACHE[cache_index];
    } else {
        cb_resolved_addr = RECOMPILED_CODE_TOP;
        rewrite_bb(HAL_UART_RX_CALLBACK_ADDR);
    }

    _invoke_rx_cplt_cb(HUART1, cb_resolved_addr | 1);
}

pub unsafe extern "aapcs" fn hal_i2c_mem_read(
    _device_id: u32,
    _dev_addr: u32,
    mem_addr: u32,
    mem_addr_size: u32,
) -> u32 {
    let sp: u32;
    asm!("mov {}, r9", out(reg) sp);
    let dst_buf_ptr = *(sp as *const u32);
    let dst_buf_size = *((sp + 4) as *const u32);
    assert!(dst_buf_ptr != 0);
    assert!(dst_buf_size < 1000);
    assert!(mem_addr < 65535);
    assert!(dst_buf_size >= mem_addr_size);
    if FUZZ_INDEX + mem_addr_size < FUZZ_LEN {
        #[cfg(feature = "dbg_prints")]
        println!(
            "I2C :: <<< {:?}",
            &FUZZ_INPUT[FUZZ_INDEX as usize..(FUZZ_INDEX + mem_addr_size) as usize]
        );
        ptr::copy_nonoverlapping(
            FUZZ_INPUT[FUZZ_INDEX as usize..(FUZZ_INDEX + mem_addr_size) as usize].as_ptr(),
            dst_buf_ptr as *mut u8,
            mem_addr_size as usize,
        );
        FUZZ_INDEX += mem_addr_size;
    } else {
        #[cfg(feature = "dbg_prints")]
        println!("Ran out of fuzz :: mem_read");
        utils::exit_hook_ok();
        unreachable!();
    }
    0
}

pub unsafe fn mbed_get_time() -> u32 {
    LAST_TIME += 1000;
    LAST_TIME
}

pub unsafe fn mbed_set_time(r0: u32) {
    LAST_TIME = r0;
}

pub unsafe fn hal_eth_transmit_frame(heth: u32, frame_len: u32) -> u32 {
    #[cfg(feature = "dbg_prints")]
    println!("HAL_ETH_TransmitFrame");

    let tx_desc: u32 = ptr::read_unaligned((heth + OFF_TX_DESC) as *const u32);
    let tx_frame: u32 = ptr::read_unaligned((tx_desc + OFF_DMA_DESC_BUF_1_ADDR) as *const u32);

    let mut new_frame_buf: Vec<u8> = Vec::with_capacity(frame_len as usize);
    ptr::copy_nonoverlapping(
        tx_frame as *const u8,
        new_frame_buf.as_mut_ptr() as *mut u8,
        frame_len as usize,
    );
    new_frame_buf.set_len(frame_len as usize);

    let interface_id: u32 = ptr::read_unaligned(heth as *const u32);
    if IF_ID != 0 && IF_ID != interface_id {
        panic!();
    }
    IF_ID = interface_id;

    #[cfg(feature = "dbg_prints")]
    println!(
        "[<] ETH Frame OUT [IF {:#x}]: {:?} :: {} bytes",
        interface_id,
        new_frame_buf,
        new_frame_buf.len()
    );

    0
}

pub unsafe fn hal_eth_get_received_frame(heth: u32) -> u32 {
    let interface_id: u32 = ptr::read_unaligned(heth as *const u32);
    if IF_ID != 0 && IF_ID != interface_id {
        panic!();
    }
    IF_ID = interface_id;

    #[cfg(feature = "dbg_prints")]
    println!("HAL_ETH_GetReceivedFrame [IF: {:#x}]", interface_id);

    let contents = ETHERNET_MODEL.get_rx_frame();
    let content_len = contents.len();
    let rx_desc: u32 = ptr::read_unaligned((heth + OFF_RX_DESC) as *const u32);
    let next_desc_addr: u32 =
        ptr::read_unaligned((rx_desc + OFF_DMA_DESC_BUG_2_NEXT_DESC_ADDR) as *const u32);
    let desc_buf_addr: u32 =
        ptr::read_unaligned((next_desc_addr + OFF_DMA_DESC_BUF_1_ADDR) as *const u32);

    ptr::write_unaligned((heth + OFF_RX_DESC) as *mut u32, next_desc_addr);
    ptr::copy_nonoverlapping(
        contents.as_ptr() as *const u8,
        desc_buf_addr as *mut u8,
        content_len,
    );

    // write back frame_info struct
    ptr::write_unaligned((heth + OFF_DMA_RX_FRAME_INFOS) as *mut u32, rx_desc);
    ptr::write_unaligned((heth + OFF_DMA_RX_FRAME_INFOS + 4) as *mut u32, rx_desc);
    ptr::write_unaligned((heth + OFF_DMA_RX_FRAME_INFOS + 8) as *mut u32, 1_u32);
    ptr::write_unaligned(
        (heth + OFF_DMA_RX_FRAME_INFOS + 12) as *mut u32,
        content_len as u32,
    );
    ptr::write_unaligned(
        (heth + OFF_DMA_RX_FRAME_INFOS + 16) as *mut u32,
        desc_buf_addr,
    );

    0
}

pub unsafe fn hal_eth_write_phy_register(_heth: u32, phy_reg: u32, reg_val: u32) -> u32 {
    PHY_REGS[phy_reg as usize] = reg_val;

    #[cfg(feature = "dbg_prints")]
    println!("HAL_ETH_WritePHYRegister [{:#x}] = {:#x}", phy_reg, reg_val);

    0
}

pub unsafe fn hal_eth_read_phy_register(_heth: u32, phy_reg: u32, reg_ptr: u32) -> u32 {
    let reg_val = PHY_REGS[phy_reg as usize];
    ptr::write_unaligned(reg_ptr as *mut u32, reg_val);

    #[cfg(feature = "dbg_prints")]
    println!("HAL_ETH_ReadPHYRegister [{:#x}] = {:#x}", phy_reg, reg_val);

    0
}

#[naked]
unsafe extern "aapcs" fn _invoke_cb(val: u32, target_addr: u32) -> u32 {
    asm!("mov pc, r1", options(noreturn))
}

pub unsafe fn inject_button_click_once(r0: u32) -> u32 {
    if !BUTTON_CLICKED {
        #[cfg(feature = "dbg_prints")]
        println!("HAL_GPIO_EXTI_Callback");

        BUTTON_CLICKED = true;

        if HAL_GPIO_EXTI_CALLBACK_ADDR == 0 {
            panic!(
                "[X] Aborting. Please set the address of `HAL_GPIO_EXTI_Callback` in your harness"
            )
        }

        let cb_resolved_addr: u32;
        let cache_index = (HAL_GPIO_EXTI_CALLBACK_ADDR >> 1) as usize;
        if O2N_CACHE[cache_index] != 0 {
            cb_resolved_addr = O2N_CACHE[cache_index];
        } else {
            cb_resolved_addr = RECOMPILED_CODE_TOP;
            rewrite_bb(HAL_GPIO_EXTI_CALLBACK_ADDR);
        }
        _invoke_cb(0x2000, cb_resolved_addr | 1);
    }

    r0
}

#[derive(Debug, Default)]
#[repr(C)]
struct FDID {
    fs: u32,        // Pointer to the owner file system object
    id: u32,        // Owner file system mount ID
    attr: u8,       // Object attribute
    stat: u8,       // Object chain status
    sclust: u64,    // Object start cluster (0:no cluster or root directory)
    objsize: usize, // Object size (valid when sclust != 0)
}

#[derive(Debug, Default)]
#[repr(C)]
struct File {
    obj: FDID,  // Object identifier (must be the 1st member to detect invalid object pointer)
    flag: u8,   // File status flags
    err: u8,    // Abort flag (error code)
    fptr: u32,  // File read/write pointer (Zeroed on file open)
    clust: u64, // Current cluster of fptr (invalid when fptr is 0)
    sect: u64,
}

/// Return fake FatFs FILE object
pub unsafe fn f_open(file_ptr: u32, _path_ptr: u32, _mode_byte: u32) -> u32 {
    let buf_ptr = crate::handlers::malloc(FUZZ_LEN);

    if FUZZ_INDEX == 0 {
        ptr::copy_nonoverlapping(FUZZ_INPUT.as_ptr(), buf_ptr as *mut u8, FUZZ_LEN as usize);
        FUZZ_INDEX += FUZZ_LEN;
    } else {
        #[cfg(feature = "dbg_prints")]
        println!("Ran out of fuzz after populating one file with f_read");
        utils::exit_hook_ok();
        unreachable!();
    }

    let mut dummy_obj = FDID::default();
    dummy_obj.objsize = FUZZ_LEN as _;
    let new_file = File {
        obj: dummy_obj,
        flag: 0x1,
        err: 0,
        fptr: 0,
        clust: 1,
        sect: 0,
    };
    ptr::copy_nonoverlapping(&new_file as *const _, file_ptr as *mut File, 1);
    0
}

/// Substitute file read with fuzz input
pub unsafe fn read_file(_file_ptr: u32, buf_ptr: u32, sizeofbuf: u32) -> u32 {
    let n = core::cmp::min(sizeofbuf, FUZZ_LEN - FUZZ_INDEX);
    if FUZZ_INDEX + n < FUZZ_LEN {
        ptr::copy_nonoverlapping(
            FUZZ_INPUT[FUZZ_INDEX as usize..].as_ptr(),
            buf_ptr as *mut u8,
            n as usize,
        );
        FUZZ_INDEX += n;
        n
    } else {
        0
    }
}
