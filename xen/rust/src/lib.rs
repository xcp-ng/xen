#![no_std]
#![no_main]
#![panic_handler]

pub mod xen;
mod demangle;

use core::{slice, fmt::Write};

use ciborium::Value;

use crate::xen::XenConsole;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dump_cbor_buffer(buffer: *const u8, len: usize) {
    let buffer = unsafe { slice::from_raw_parts(buffer, len) };

    let value: Value = match ciborium::from_reader(buffer) {
        Ok(v) => v,
        Err(e) => {
            writeln!(XenConsole, "Unable to parse CBOR: {e}").ok();
            return;
        }
    };

    writeln!(XenConsole, "{:#?}", value).ok();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn test_rust_panic() {
    panic!("Test panic");
}