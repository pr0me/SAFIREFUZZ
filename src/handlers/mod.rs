pub mod arduino;
pub mod contiki;
pub mod ethernet;
pub mod libopencm3;
pub mod lwip;
pub mod mcuxpresso;
pub mod rf233;
pub mod samr21;
pub mod stm32;
pub mod wifi;

use core::arch::asm;
use std::collections::BTreeSet;
use std::process;

pub static mut MALLOC_CHUNK_TOP: u32 = 0;
pub static mut MALLOC_CHUNK_CURR_PTR: u32 = 0;
pub static mut FREED_PREV: BTreeSet<u32> = BTreeSet::new();

pub fn nop() {}

pub fn return_zero() -> u32 {
    0
}

pub fn return_non_zero() -> u32 {
    7
}

pub unsafe fn malloc(size: u32) -> u32 {
    let aligned_size = size + (8 - (size % 8));
    MALLOC_CHUNK_CURR_PTR -= aligned_size;
    #[cfg(feature = "dbg_prints")]
    println!("[+] malloc: {MALLOC_CHUNK_CURR_PTR:#x}, {aligned_size}");
    MALLOC_CHUNK_CURR_PTR
}

pub unsafe fn malloc_r(_: u32, size: u32) -> u32 {
    malloc(size)
}

// WARNING: might read oob
pub unsafe fn realloc_r(_: u32, ptr: u32, size: u32) -> u32 {
    if ptr == 0 {
        return malloc_r(0, size);
    }
    let new_ptr = malloc_r(0, size);
    libc::memcpy(new_ptr as _, ptr as _, size as _);
    free_r(0, ptr);
    new_ptr
}

pub unsafe fn free(ptr: u32) {
    if ptr == 0 {
        return;
    };

    #[cfg(feature = "dbg_prints")]
    println!("[*] FREEING {:#x}", ptr);

    if FREED_PREV.contains(&ptr) {
        #[cfg(feature = "dbg_prints")]
        println!("[!] Double Free detected. Aborting");
        process::abort();
    } else {
        FREED_PREV.insert(ptr);
    }
}

pub unsafe fn free_r(_: u32, ptr: u32) {
    free(ptr);
}

pub unsafe fn puts(mut _s_ptr: u32) -> u32 {
    #[cfg(debug_assertions)]
    {
        let mut c: [u8; 1] = [0x0];
        loop {
            libc::memcpy(c.as_mut_ptr() as _, _s_ptr as _, 1);
            if c[0] == 0x0 {
                break;
            }
            print!("{}", c[0] as char);
            _s_ptr += 1;
        }
    }
    1_u32
}

// GNU compiler switch case needs special handling as it directly manipuates lr
#[naked]
pub unsafe extern "aapcs" fn thumb_case_sqi() {
    asm!(
        "pop {{r1-r11, lr}}
        push {{r0, r1, r2, r3}}
        mov r1, #0x30000000
        ldr lr, [r1]
        add lr, 5
        mov r1, lr
        lsrs r1, r1, #1
        lsls r1, r1, #1
        ldrsb r1, [r1, r0]
        lsls r1, r1, #1
        add lr, r1
        mov r0, lr
        sub r0, 1
        mov r1, #0x30000000
        ldr r1, [r1, #4]
        blx r1
        mov lr, r0
        add lr, 1
        pop {{r0, r1, r2, r3}}
        bx lr
    ",
        options(noreturn)
    );
}

#[naked]
pub unsafe extern "aapcs" fn thumb_case_uqi() {
    asm!(
        "pop {{r1-r11, lr}}
        push {{r0, r1, r2, r3}}
        mov r1, #0x30000000
        ldr lr, [r1]
        add lr, 5
        mov r1, lr
        lsrs r1, r1, #1
        lsls r1, r1, #1
        ldrb r1, [r1, r0]
        lsls r1, r1, #1
        add lr, r1
        mov r0, lr
        sub r0, 1
        mov r1, #0x30000000
        ldr r1, [r1, #4]
        blx r1
        mov lr, r0
        add lr, 1
        pop {{r0, r1, r2, r3}}
        bx lr
    ",
        options(noreturn)
    );
}

#[naked]
pub unsafe extern "aapcs" fn thumb_case_uhi() {
    asm!(
        "pop {{r1-r11, lr}}
        push {{r0, r1, r2, r3}}
        mov r1, #0x30000000
        ldr lr, [r1]
        add lr, 5
        mov r1, lr
        lsrs r1, r1, #1
        lsls r0, r0, #1
        lsls r1, r1, #1
        ldrh r1, [r1, r0]
        lsls r1, r1, #1
        add lr, r1
        mov r0, lr
        sub r0, 1
        mov r1, #0x30000000
        ldr r1, [r1, #4]
        blx r1
        mov lr, r0
        add lr, 1
        pop {{r0, r1, r2, r3}}
        bx lr
    ",
        options(noreturn)
    );
}

pub unsafe fn _memset(ptr: u32, val: u32, size: u32) {
    core::ptr::write_bytes(ptr as *mut u8, val as u8, size as usize);
}

pub unsafe fn _memchr(s_ptr: u32, c: u32, n: u32) -> u32 {
    let idx = core::slice::memchr::memchr(
        c as u8,
        core::slice::from_raw_parts(s_ptr as *const u8, n as usize),
    );
    let x: u32;
    if let Some(idx) = idx {
        x = s_ptr + idx as u32;
    } else {
        x = 0;
    }
    x
}

pub unsafe fn dump_args(r0: u32, r1: u32, r2: u32, r3: u32) {
    println!(
        "r0: {:#x} :: r1: {:#x} :: r2: {:#x} :: r3: {:#x}",
        r0, r1, r2, r3
    );
}
