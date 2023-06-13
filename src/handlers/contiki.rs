use core::arch::asm;

pub static mut CURRENT_FAKE_TIME: u32 = 0;
pub static mut SECONDS_DIVIDER: u32 = 120;
pub static mut FAKE_TIME_INCREASE: u32 = 2000;

pub fn reset_time() {
    unsafe {
        CURRENT_FAKE_TIME = 0;
    }
}

pub unsafe fn clock_time() -> u32 {
    crate::engine::NUM_CURR_BRANCHES as u32 / 256
}

pub fn clock_seconds() -> u32 {
    unsafe { clock_time() / SECONDS_DIVIDER }
}

pub unsafe fn clock_init() {
    #[cfg(feature = "dbg_prints")]
    println!("[*] clock_init: turn tc timer ON");
    crate::utils::enable_timer(32, clock_irq, 0);
}

/// Clock interrupt handler for atmel 6lowpan with ISR `etimer_request_poll`
pub unsafe fn clock_irq() {
    #[cfg(feature = "dbg_prints")]
    println!("[IRQ] Clock");

    // checking address
    let fn_addr: u32 = if crate::engine::O2N_CACHE[24834] != 0 {
        crate::engine::O2N_CACHE[24834]
    } else {
        crate::engine::rewrite_bb(0xc204)
    };

    asm!(
        "push {{r0-r12, lr}}
        mov r7, {}
        blx r7
        pop {{r0-r12, lr}}",
        in(reg) fn_addr | 1,
    );
}
