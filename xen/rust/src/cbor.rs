use core::{ffi::c_long, fmt::Write, slice};

use ciborium::Value;
use serde::Serialize;

use crate::xen::XenConsole;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_cbor_process(
    input: *const u8,
    input_size: usize,
    output: *mut u8,
    output_size: usize,
    output_len: &mut usize,
) -> c_long {
    let input_slice = unsafe { slice::from_raw_parts(input, input_size) };
    let output_slice = unsafe { slice::from_raw_parts_mut(output, output_size) };

    let Some(len) = cbor_process(input_slice, output_slice) else {
        return -1;
    };

    *output_len = len;
    0
}

#[derive(Serialize)]
pub enum CborFoo {
    Bar,
}

#[derive(Serialize)]
pub struct CborTestPayload {
    hello: &'static str,
    world: u32,

    foo: CborFoo,
}

pub fn cbor_process(input: &[u8], output: &mut [u8]) -> Option<usize> {
    let value: Value = match ciborium::from_reader(input) {
        Ok(v) => v,
        Err(e) => {
            writeln!(XenConsole, "Unable to parse CBOR: {e}").ok();
            return None;
        }
    };
    let output_len = output.len();

    writeln!(XenConsole, "{:?}", value).ok();

    ciborium::into_writer(
        &CborTestPayload {
            hello: "world",
            world: 42,
            foo: CborFoo::Bar,
        },
        output,
    )
    .ok()?;

    Some(output_len)
}
