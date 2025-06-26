#![no_std]
#![no_main]
#![panic_handler]

use core::fmt::{self, Write};

mod cbor;
mod demangle;
pub mod xen;

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
