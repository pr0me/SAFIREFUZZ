use crate::engine::{FUZZ_INDEX, FUZZ_INPUT, FUZZ_LEN};
use crate::utils;
use core::ptr;

pub static mut DMA_BACKINGS: [u32; 32] = [0; 32];

/// fuzz-dependend id generation for libopeninv
pub fn detect_hw() -> u32 {
    // use fuzz input as seed without consuming
    let hw_rev_id = unsafe { FUZZ_INPUT[0] } as u32 % 6;
    hw_rev_id
}

/// Populates DMA with data and randomize length
pub unsafe fn dma_get_number_of_data(_dma: u32, channel: u32) -> u32 {
    let dmarx_buf_addr = DMA_BACKINGS[channel as usize];
    if FUZZ_INDEX + 1 < FUZZ_LEN {
        let size = FUZZ_INPUT[FUZZ_INDEX as usize] as u32 % (FUZZ_LEN - FUZZ_INDEX - 1);
        FUZZ_INDEX += 1;
        ptr::copy_nonoverlapping(
            FUZZ_INPUT[FUZZ_INDEX as usize..].as_ptr(),
            dmarx_buf_addr as *mut u8,
            size as usize,
        );
        FUZZ_INDEX += 1;
        size
    } else {
        utils::exit_hook_ok();
        unreachable!();
    }
}

pub unsafe fn dma_set_memory_address(_dma: u32, channel: u32, address: u32) {
    DMA_BACKINGS[channel as usize] = address;
    // #[cfg(feature = "dbg_prints")]
    // println!(
    // "dma_set_memory_address: dma {:#x}, channel {:#x}, address {:#x}",
    // _dma, channel, address
    // );
}

pub unsafe fn usart_send(_usart: u32, _data: u32) {
    #[cfg(feature = "dbg_prints")]
    println!("USART OUT: {} [{:#x}]", _data as u8 as char, _data);
}

pub unsafe fn usart_recv(_data_ptr: u32) {
    #[cfg(feature = "dbg_prints")]
    print!("{}", *(_data_ptr as *const u8) as char);
}

pub unsafe fn desig_get_flash_size() -> u32 {
    let flash_size = ptr::read_volatile(0x1ffff7e0_u32 as *const u16) as u32;
    #[cfg(feature = "dbg_prints")]
    {
        println!("saved flash size: {}", flash_size);
        println!("FlashAddress: {:#x}", (0x41fffe + flash_size) << 0xa);
    }
    if flash_size != 1337 {
        utils::exit_hook_timeout();
        unreachable!();
    }
    flash_size
}
