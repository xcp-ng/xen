use core::{ffi::c_long, fmt::Write, slice};

use crate::{
    Cursor,
    cbor::{
        abi::{CborHypercall, HypercallError},
        domctl::get_domain_status,
    },
    xen::XenConsole,
};

mod abi;
mod domctl;
mod unpack_serde;

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

pub fn cbor_process(input: &[u8], output: &mut [u8]) -> Option<usize> {
    let mut output = Cursor(output, 0);

    let result = match ciborium::from_reader(input) {
        Ok(CborHypercall::GetDomainState { domid, dump_vcpus }) => {
            get_domain_status(&mut output, domid, dump_vcpus)
        }
        Ok(CborHypercall::GetDomainInfo { domid }) => Err("TODO"),

        Err(e) => {
            writeln!(XenConsole, "CBOR parsing failure: {e}").ok();

            match e {
                ciborium::de::Error::RecursionLimitExceeded => Err("Exceeded recursion limit"),
                ciborium::de::Error::Io(_) => Err("Unexpected EOF"),
                ciborium::de::Error::Semantic(_, _) | ciborium::de::Error::Syntax(_) => {
                    Err("Invalid CBOR")
                }
            }
        }
    };

    if let Err(message) = result {
        /* Ignore any error there */
        ciborium::into_writer(&HypercallError { message }, &mut output).ok();
    }

    Some(output.written())
}
