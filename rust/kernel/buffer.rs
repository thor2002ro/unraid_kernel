// SPDX-License-Identifier: GPL-2.0

//! Struct for writing to a pre-allocated buffer with the [`write!`] macro.

use core::fmt;

/// A pre-allocated buffer that implements [`core::fmt::Write`].
///
/// Consecutive writes will append to what has already been written.
/// Writes that don't fit in the buffer will fail.
pub struct Buffer<'a> {
    slice: &'a mut [u8],
    pos: usize,
}

impl<'a> Buffer<'a> {
    /// Creates a new buffer from an existing array.
    pub fn new(slice: &'a mut [u8]) -> Self {
        Buffer { slice, pos: 0 }
    }

    /// Creates a new buffer from a raw pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must be valid for read and writes, have at least `len` bytes in
    /// size, and remain valid and not be used by other threads for the lifetime
    /// of the returned instance.
    pub unsafe fn from_raw(ptr: *mut u8, len: usize) -> Self {
        // SAFETY: The safety requirements of the function satisfy those of
        // `from_raw_parts_mut`.
        Self::new(unsafe { core::slice::from_raw_parts_mut(ptr, len) })
    }

    /// Number of bytes that have already been written to the buffer.
    /// This will always be less than the length of the original array.
    pub fn bytes_written(&self) -> usize {
        self.pos
    }
}

impl fmt::Write for Buffer<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if s.len() > self.slice.len() - self.pos {
            Err(fmt::Error)
        } else {
            self.slice[self.pos..self.pos + s.len()].copy_from_slice(s.as_bytes());
            self.pos += s.len();
            Ok(())
        }
    }
}
