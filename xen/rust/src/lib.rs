#![no_std]
#![no_main]
#![panic_handler]

use core::fmt;

use ciborium_io::Write;

mod cbor;
mod demangle;
pub mod xen;

/// Wrapper on mutable bytes to implement fmt::Write.
pub struct Cursor<'a>(&'a mut [u8], usize);

impl Cursor<'_> {
    pub fn written(&self) -> usize {
        self.1
    }
}

#[derive(Debug)]
pub struct OutOfSpace;

impl ciborium_io::Write for Cursor<'_> {
    type Error = OutOfSpace;

    fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let Some(part) = self.0.get_mut(self.1..self.1 + data.len()) else {
            return Err(OutOfSpace);
        };

        part.copy_from_slice(data);
        self.1 += data.len();
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl fmt::Write for Cursor<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_all(s.as_bytes()).map_err(|_| fmt::Error)
    }
}
