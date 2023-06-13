#![allow(dead_code)]
#![allow(unused_variables)]

use crate::engine::{rewrite_bb, FUZZ_INDEX, FUZZ_INPUT, FUZZ_LEN, O2N_CACHE, RECOMPILED_CODE_TOP};
use crate::handlers::{free_r, malloc_r};
use crate::utils::exit_hook_ok;
use core::{arch::asm, ptr};

static mut DUMMY_DATE_STRUCT: [u8; 4] = [0x01, 0x01, 0x01, 0x18];
static mut DUMMY_TIME_STRUCT: [u8; 20] = [0x00; 20];
pub static mut SYSTEM_START_TIME: u32 = 0;
pub static mut LAST_TIME: u32 = 12345678;
pub static mut MALLOC_CHUNK_TOP: u32 = 0;
pub static mut MALLOC_CHUNK_CURR_PTR: u32 = 0;
pub static mut PCB_OBJECT: PCB = PCB::new();

static PBUF_SIZE: u32 = 2 * 4 + 2 * 2 + 2 * 1 + 2;
static PCB_SIZE: u32 = 208;
static OFF_PCB_SNDBUF: u32 = 102;

static PBUF_RAM: u8 = 0;
static PBUF_ROM: u8 = 1;
static PBUF_REF: u8 = 2;
static PBUF_POOL: u8 = 3;

#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct PBuf {
    /** next pbuf in singly linked pbuf chain */
    next_ptr: u32,
    /** pointer to the actual data in the buffer */
    payload_ptr: u32,
    /**
     * total length of this buffer and all next buffers in chain
     * belonging to the same packet.
     *
     * For non-queue packet chains this is the invariant:
     * p->tot_len == p->len + (p->next? p->next->tot_len: 0)
     */
    tot_len: u16,
    /** length of this buffer */
    len: u16,
    /** pbuf_type as u8_t instead of enum to save space */
    pbuf_type: u8,
    /** misc flags */
    flags: u8,
    /**
     * the reference count always equals the number of pointers
     * that refer to this pbuf. This can be pointers from an application,
     * the stack itself, or pbuf->next pointers from a chain.
     */
    ref_counter: u16,
}

// Internal representation
#[derive(Debug)]
pub struct PCB {
    addr: u32,
    cb_arg: u32,
    accept_cb: u32,
    recv_cb: u32,
    port: u32,
}

impl PCB {
    pub const fn new() -> Self {
        Self {
            addr: 0,
            cb_arg: 0,
            accept_cb: 0,
            recv_cb: 0,
            port: 0,
        }
    }
}

pub unsafe fn pbuf_free(pbuf_ptr: *const PBuf) {
    let payload = (*pbuf_ptr).payload_ptr;
    let ref_count = (*pbuf_ptr).ref_counter;
    if ref_count == 1 {
        free_r(0, payload);
        free_r(0, pbuf_ptr as u32);
    }
}

pub unsafe fn memp_malloc(pool_type: u32) -> u32 {
    let size: u32 = match pool_type {
        0 | 4 => 32,
        1 => 152,
        2 => 28,
        3 | 6 | 7 => 16,
        5 => 24,
        8 => 1536,
        _ => unreachable!(),
    };
    malloc_r(0, size)
}

pub unsafe fn tcp_new() -> u32 {
    let new_buf_ptr = malloc_r(0, PCB_SIZE);
    let snd_buf_length: u16 = 0xffff;
    ptr::copy_nonoverlapping(
        &snd_buf_length as *const u16,
        (new_buf_ptr + OFF_PCB_SNDBUF) as *mut u16,
        1,
    );
    let new_obj = PCB {
        addr: new_buf_ptr,
        cb_arg: 0,
        accept_cb: 0,
        recv_cb: 0,
        port: 0,
    };
    #[cfg(feature = "dbg_prints")]
    println!("tcp_new inserted {new_buf_ptr:#x}, {new_obj:#x?}");

    PCB_OBJECT = new_obj;
    new_buf_ptr
}

pub unsafe fn tcp_bind(pcb_ptr: u32, _: u32, port: u32) {
    #[cfg(feature = "dbg_prints")]
    println!("tcp_bind requesting port for {pcb_ptr:#x}");
    PCB_OBJECT.port = port;
}

pub unsafe fn tcp_listen(pcb_ptr: u32) -> u32 {
    #[cfg(feature = "dbg_prints")]
    {
        println!(
            "[+] TCP Listen on port {:#x}, {}\n\n",
            pcb_ptr, PCB_OBJECT.port
        );
    }
    pcb_ptr
}

pub unsafe fn tcp_accept(pcb_ptr: u32, mut cb: u32) -> u32 {
    let mut pcb = &mut PCB_OBJECT;
    pcb.accept_cb = cb;
    cb -= 1;

    #[cfg(feature = "dbg_prints")]
    println!("[+] tcp_accept: pcb {:#x}, callback {:#x}", pcb_ptr, cb);

    let cb_resolved_addr: u32;
    let cache_index = (cb >> 1) as usize;
    if O2N_CACHE[cache_index] != 0 {
        cb_resolved_addr = O2N_CACHE[cache_index];
    } else {
        cb_resolved_addr = RECOMPILED_CODE_TOP;
        rewrite_bb(cb);
    }
    #[cfg(feature = "dbg_prints")]
    println!("SYN accept");
    let x = _invoke_accept_cb(pcb.cb_arg, pcb_ptr, 0, cb_resolved_addr + 1);
    #[cfg(feature = "dbg_prints")]
    println!("ACK accept");
    x
}

pub unsafe fn tcp_arg(pcb_ptr: u32, cb_arg: u32) {
    PCB_OBJECT.cb_arg = cb_arg;
}

pub unsafe fn tcp_recv(pcb_ptr: u32, cb: u32) {
    #[cfg(feature = "dbg_prints")]
    println!("[!] tcp_recv: setting recv_cb for PCB @ {pcb_ptr:#x}\n");
    let mut pcb = &mut PCB_OBJECT;
    pcb.recv_cb = cb;
}

pub unsafe fn tcp_write(_: u32, buf_ptr: u32, len: usize) {
    #[cfg(feature = "dbg_prints")]
    {
        let mut buf: Vec<u8> = Vec::new();
        ptr::copy_nonoverlapping(buf_ptr as *const u8, buf.as_mut_ptr() as *mut u8, len);
        buf.set_len(len);
        println!(
            "[i] tcp_write with contents :: {:?}",
            std::str::from_utf8(&buf[..]).unwrap()
        );
    }
}

pub unsafe fn tcp_close(pcb_ptr: u32) -> u32 {
    free_r(0, pcb_ptr);
    // ERR_OK
    0
}

pub unsafe fn tick() -> u32 {
    let pcb = &PCB_OBJECT;

    #[cfg(feature = "dbg_prints")]
    println!(
        "[o] Using PCB @ {:#x} for recv callback: {:#x?}",
        pcb.addr, pcb
    );

    // static err_t http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
    let pbuf_ptr: u32;
    if FUZZ_INDEX < FUZZ_LEN {
        pbuf_ptr = _create_pbuf(FUZZ_INPUT[FUZZ_INDEX as usize..].to_vec());
        FUZZ_INDEX = FUZZ_LEN;
    } else {
        exit_hook_ok();
        unreachable!();
    }

    // let target_addr = pcb.1.recv_cb - 1;
    let target_addr = pcb.recv_cb - 1;
    let cb_resolved_addr: u32;
    let cache_index = (target_addr >> 1) as usize;
    if O2N_CACHE[cache_index] != 0 {
        cb_resolved_addr = O2N_CACHE[cache_index];
    } else {
        cb_resolved_addr = RECOMPILED_CODE_TOP;
        rewrite_bb(target_addr);
    }

    #[cfg(feature = "dbg_prints")]
    println!("SYN tick");
    let x = _invoke_recv_cb(pcb.cb_arg, pcb.addr, pbuf_ptr, cb_resolved_addr + 1);
    #[cfg(feature = "dbg_prints")]
    println!("ACK tick");
    x
}

/// http_accept callback handler
#[naked]
unsafe extern "aapcs" fn _invoke_accept_cb(arg: u32, pcb_ptr: u32, _: u32, cb: u32) -> u32 {
    asm!("mov pc, r3", options(noreturn))
}

/// http_recv callback handler: void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err
#[naked]
unsafe extern "aapcs" fn _invoke_recv_cb(arg: u32, pcb_ptr: u32, pbuf_ptr: u32, cb: u32) -> u32 {
    asm!("mov r4, r3", "mov r3, 0", "mov pc, r4", options(noreturn))
}

/// creates new pbuf for incoming packet with fuzzing inputs
unsafe fn _create_pbuf(content: Vec<u8>) -> u32 {
    let new_pbuf_ptr = malloc_r(0, PBUF_SIZE);
    let content_len = content.len();
    let payload_ptr = malloc_r(0, content_len as u32 + 5);
    let new_pbuf = PBuf {
        next_ptr: 0,
        payload_ptr,
        tot_len: content_len as u16,
        len: content_len as u16,
        pbuf_type: PBUF_RAM,
        flags: 0,
        ref_counter: 1,
    };
    ptr::copy_nonoverlapping(
        &new_pbuf as *const PBuf as *const u8,
        new_pbuf_ptr as *mut u8,
        PBUF_SIZE as usize,
    );
    ptr::copy_nonoverlapping(
        content.as_ptr() as *const u8,
        payload_ptr as *mut u8,
        content_len,
    );
    new_pbuf_ptr
}
