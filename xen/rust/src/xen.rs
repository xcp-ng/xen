//! Xen support for Rust.

use core::{
    alloc::{GlobalAlloc, Layout},
    arch::asm,
    ffi::{c_char, c_uint},
    fmt::{self, Write},
    hint::unreachable_unchecked,
    panic::PanicInfo,
};

unsafe extern "C" {
    pub unsafe fn rust_stub_printk(line: *const c_char);

    pub unsafe fn _xvmalloc(size: usize, align: c_uint) -> *mut u8;
    pub unsafe fn _xvzalloc(size: usize, align: c_uint) -> *mut u8;
    pub unsafe fn _xvrealloc(va: *mut u8, size: usize, align: c_uint) -> *mut u8;
    pub unsafe fn xvfree(va: *mut u8);
}

/// printk console
pub struct XenConsole;

impl Write for XenConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // Write in chunks of 63 bytes.
        for chunk in s.as_bytes().chunks(63) {
            let mut buffer = [0u8; 64];
            buffer[..chunk.len()].copy_from_slice(chunk);
            buffer[chunk.len()] = b'\0';

            unsafe { rust_stub_printk(buffer.as_ptr() as _) }
        }

        Ok(())
    }
}

#[global_allocator]
static XEN_ALLOCATOR: XenAllocator = XenAllocator;

struct XenAllocator;

unsafe impl GlobalAlloc for XenAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { _xvmalloc(layout.size(), layout.align() as _) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { _xvzalloc(layout.size(), layout.align() as _) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
        unsafe { xvfree(ptr) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe { _xvrealloc(ptr, new_size, layout.align() as _) }
    }
}

#[panic_handler]
fn panic<'a, 'b>(info: &'a PanicInfo<'b>) -> ! {
    writeln!(XenConsole, "Rust code panic: {info}").ok();

    unsafe {
        #[cfg(target_arch = "x86_64")]
        asm!("ud2");
        unreachable_unchecked()
    }
}
