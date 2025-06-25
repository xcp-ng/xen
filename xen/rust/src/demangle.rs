//! Rust symbol demangling utilities for C code.

use core::{
    ffi::c_int,
    fmt::{self, Write},
    slice,
};

/// Wrapper on mutable bytes to implement fmt::Write.
pub struct Cursor<'a>(&'a mut [u8], usize);

impl Write for Cursor<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let Some(part) = self.0.get_mut(self.1..self.1 + s.len()) else {
            return Err(fmt::Error);
        };

        part.copy_from_slice(s.as_bytes());
        self.1 += s.len();
        Ok(())
    }
}

/// Take a symbol, and try to demangle it if it is a Rust one.
#[unsafe(no_mangle)]
unsafe extern "C" fn rust_demangle_symbol(
    symbol: *const u8,
    symbol_size: usize,
    output: *mut u8,
    output_size: usize,
) -> c_int {
    let symbol_slice = unsafe { slice::from_raw_parts(symbol, symbol_size) };

    // We expect C code to give us a UTF-8 string.
    let Ok(symbol) = str::from_utf8(symbol_slice) else {
        return -1;
    };

    let Ok(demangled) = rustc_demangle::try_demangle(symbol) else {
        // Not a rust symbol
        return -1;
    };

    let output = unsafe { slice::from_raw_parts_mut(output as _, output_size) };
    let mut output_cursor = Cursor(output, 0);

    // Write the demangled output as a NUL-terminated string.
    if write!(output_cursor, "{demangled}\0").is_err() {
        return -1;
    };

    0
}
