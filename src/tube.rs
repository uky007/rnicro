//! Process I/O tubes for exploit interaction.
//!
//! Provides pwntools-style send/recv for automated exploit delivery
//! against child processes via pipes.

use crate::error::{Error, Result};

/// Default timeout for recv operations (5 seconds).
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Internal read buffer size.
const BUF_SIZE: usize = 4096;

/// File descriptors for the parent side of child I/O pipes.
///
/// Created during fork(), used to construct a `Tube`.
pub struct ChildPipes {
    /// Parent writes here -> child reads as stdin.
    pub stdin_write: i32,
    /// Parent reads here <- child writes to stdout.
    pub stdout_read: i32,
    /// Parent reads here <- child writes to stderr (optional).
    pub stderr_read: Option<i32>,
}

/// File descriptors for the child side of pipes (used after fork, before exec).
pub struct ChildFds {
    pub stdin_read: i32,
    pub stdout_write: i32,
    pub stderr_write: i32,
}

impl ChildFds {
    /// In the child process, dup2 these fds to stdin/stdout/stderr and close originals.
    ///
    /// # Safety
    /// Must be called in the child process after fork, before exec.
    pub unsafe fn setup_in_child(&self) {
        libc::dup2(self.stdin_read, 0);
        libc::dup2(self.stdout_write, 1);
        libc::dup2(self.stderr_write, 2);
        libc::close(self.stdin_read);
        libc::close(self.stdout_write);
        libc::close(self.stderr_write);
    }
}

/// Create pipes for child I/O.
///
/// Returns (child_fds, parent_pipes) where child_fds are used in the child
/// process (dup2 to stdin/stdout/stderr) and parent_pipes are wrapped in a Tube.
pub fn create_child_pipes() -> Result<(ChildFds, ChildPipes)> {
    let mut stdin_pipe = [0i32; 2];
    let mut stdout_pipe = [0i32; 2];
    let mut stderr_pipe = [0i32; 2];

    unsafe {
        if libc::pipe(stdin_pipe.as_mut_ptr()) != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        if libc::pipe(stdout_pipe.as_mut_ptr()) != 0 {
            libc::close(stdin_pipe[0]);
            libc::close(stdin_pipe[1]);
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        if libc::pipe(stderr_pipe.as_mut_ptr()) != 0 {
            libc::close(stdin_pipe[0]);
            libc::close(stdin_pipe[1]);
            libc::close(stdout_pipe[0]);
            libc::close(stdout_pipe[1]);
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }

    Ok((
        ChildFds {
            stdin_read: stdin_pipe[0],
            stdout_write: stdout_pipe[1],
            stderr_write: stderr_pipe[1],
        },
        ChildPipes {
            stdin_write: stdin_pipe[1],
            stdout_read: stdout_pipe[0],
            stderr_read: Some(stderr_pipe[0]),
        },
    ))
}

/// A bidirectional communication channel to a child process.
///
/// Provides pwntools-style send/recv for interacting with a
/// process's stdin/stdout.
pub struct Tube {
    /// Write fd: feeds into child's stdin.
    stdin_fd: i32,
    /// Read fd: reads from child's stdout.
    stdout_fd: i32,
    /// Internal receive buffer.
    buffer: Vec<u8>,
    /// Default timeout in milliseconds.
    timeout_ms: u64,
    /// Whether this tube owns the fds (should close on drop).
    owns_fds: bool,
}

impl Tube {
    /// Create a Tube from pipe file descriptors.
    ///
    /// Sets the stdout fd to non-blocking mode.
    pub fn from_pipes(pipes: ChildPipes) -> Self {
        // Set stdout_read to non-blocking
        unsafe {
            let flags = libc::fcntl(pipes.stdout_read, libc::F_GETFL);
            libc::fcntl(pipes.stdout_read, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        Self {
            stdin_fd: pipes.stdin_write,
            stdout_fd: pipes.stdout_read,
            buffer: Vec::new(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            owns_fds: true,
        }
    }

    /// Create a Tube from raw file descriptors without taking ownership.
    ///
    /// The caller is responsible for closing the fds.
    pub fn from_raw_fds(stdin_write: i32, stdout_read: i32) -> Self {
        unsafe {
            let flags = libc::fcntl(stdout_read, libc::F_GETFL);
            libc::fcntl(stdout_read, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        Self {
            stdin_fd: stdin_write,
            stdout_fd: stdout_read,
            buffer: Vec::new(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            owns_fds: false,
        }
    }

    /// Set the default timeout in milliseconds.
    pub fn set_timeout_ms(&mut self, ms: u64) {
        self.timeout_ms = ms;
    }

    /// Send raw bytes to the child's stdin.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        let mut total = 0;
        while total < data.len() {
            let n = unsafe {
                libc::write(
                    self.stdin_fd,
                    data[total..].as_ptr() as *const libc::c_void,
                    data.len() - total,
                )
            };
            if n < 0 {
                return Err(Error::Io(std::io::Error::last_os_error()));
            }
            total += n as usize;
        }
        Ok(())
    }

    /// Send bytes followed by a newline.
    pub fn sendline(&mut self, data: &[u8]) -> Result<()> {
        self.send(data)?;
        self.send(b"\n")
    }

    /// Receive up to `n` bytes with the default timeout.
    pub fn recv(&mut self, n: usize) -> Result<Vec<u8>> {
        self.recv_timeout(n, self.timeout_ms)
    }

    /// Receive up to `n` bytes with explicit timeout (milliseconds).
    pub fn recv_timeout(&mut self, n: usize, timeout_ms: u64) -> Result<Vec<u8>> {
        // Check buffer first
        if !self.buffer.is_empty() {
            let take = n.min(self.buffer.len());
            return Ok(self.buffer.drain(..take).collect());
        }

        self.poll_read(timeout_ms)?;
        self.fill_buffer()?;

        let take = n.min(self.buffer.len());
        if take == 0 {
            return Err(Error::Other("recv timeout: no data".into()));
        }
        Ok(self.buffer.drain(..take).collect())
    }

    /// Receive exactly `n` bytes with the default timeout.
    pub fn recvn(&mut self, n: usize) -> Result<Vec<u8>> {
        self.recvn_timeout(n, self.timeout_ms)
    }

    /// Receive exactly `n` bytes with explicit timeout.
    pub fn recvn_timeout(&mut self, n: usize, timeout_ms: u64) -> Result<Vec<u8>> {
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(timeout_ms);

        while self.buffer.len() < n {
            let remaining = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis() as u64;
            if remaining == 0 {
                return Err(Error::Other(format!(
                    "recvn timeout: got {} of {} bytes",
                    self.buffer.len(), n
                )));
            }
            self.poll_read(remaining)?;
            self.fill_buffer()?;
        }

        Ok(self.buffer.drain(..n).collect())
    }

    /// Receive data until a delimiter is found.
    ///
    /// Returns all data up to and including the delimiter.
    pub fn recvuntil(&mut self, delim: &[u8]) -> Result<Vec<u8>> {
        self.recvuntil_timeout(delim, self.timeout_ms)
    }

    /// Receive until delimiter with explicit timeout.
    pub fn recvuntil_timeout(&mut self, delim: &[u8], timeout_ms: u64) -> Result<Vec<u8>> {
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(timeout_ms);

        loop {
            if let Some(pos) = find_subsequence(&self.buffer, delim) {
                let end = pos + delim.len();
                return Ok(self.buffer.drain(..end).collect());
            }

            let remaining = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis() as u64;
            if remaining == 0 {
                return Err(Error::Other("recvuntil timeout".into()));
            }

            self.poll_read(remaining)?;
            self.fill_buffer()?;
        }
    }

    /// Receive one line (until \n).
    pub fn recvline(&mut self) -> Result<Vec<u8>> {
        self.recvuntil(b"\n")
    }

    /// Check if data is available without blocking.
    pub fn can_recv(&self) -> bool {
        if !self.buffer.is_empty() {
            return true;
        }
        let mut pfd = libc::pollfd {
            fd: self.stdout_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
        ret > 0 && (pfd.revents & libc::POLLIN != 0)
    }

    /// Drain all currently buffered data without blocking.
    pub fn clean(&mut self) -> Vec<u8> {
        let _ = self.fill_buffer();
        self.buffer.drain(..).collect()
    }

    /// Send data, then receive until delimiter.
    pub fn sendafter(&mut self, delim: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let received = self.recvuntil(delim)?;
        self.send(data)?;
        Ok(received)
    }

    /// Send a line after receiving a delimiter.
    pub fn sendlineafter(&mut self, delim: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let received = self.recvuntil(delim)?;
        self.sendline(data)?;
        Ok(received)
    }

    // ── Internal helpers ──

    fn poll_read(&self, timeout_ms: u64) -> Result<()> {
        let mut pfd = libc::pollfd {
            fd: self.stdout_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = timeout_ms.min(i32::MAX as u64) as i32;
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout) };
        if ret < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        if ret == 0 {
            return Err(Error::Other("poll timeout".into()));
        }
        if pfd.revents & libc::POLLHUP != 0 && pfd.revents & libc::POLLIN == 0 {
            return Err(Error::Other("child closed stdout".into()));
        }
        Ok(())
    }

    fn fill_buffer(&mut self) -> Result<()> {
        let mut tmp = [0u8; BUF_SIZE];
        let n = unsafe {
            libc::read(
                self.stdout_fd,
                tmp.as_mut_ptr() as *mut libc::c_void,
                BUF_SIZE,
            )
        };
        if n > 0 {
            self.buffer.extend_from_slice(&tmp[..n as usize]);
        } else if n == 0 {
            return Err(Error::Other("EOF from child".into()));
        }
        // n < 0 with EAGAIN is ok (no data available yet)
        Ok(())
    }
}

impl Drop for Tube {
    fn drop(&mut self) {
        if self.owns_fds {
            unsafe {
                libc::close(self.stdin_fd);
                libc::close(self.stdout_fd);
            }
        }
    }
}

/// Find a subsequence (delimiter) in a byte slice.
pub fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Pack a u64 as little-endian bytes (pwntools p64 equivalent).
pub fn p64(val: u64) -> [u8; 8] {
    val.to_le_bytes()
}

/// Pack a u32 as little-endian bytes (pwntools p32 equivalent).
pub fn p32(val: u32) -> [u8; 4] {
    val.to_le_bytes()
}

/// Pack a u16 as little-endian bytes (pwntools p16 equivalent).
pub fn p16(val: u16) -> [u8; 2] {
    val.to_le_bytes()
}

/// Unpack little-endian bytes to u64 (pwntools u64 equivalent).
pub fn u64_le(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = data.len().min(8);
    buf[..len].copy_from_slice(&data[..len]);
    u64::from_le_bytes(buf)
}

/// Unpack little-endian bytes to u32 (pwntools u32 equivalent).
pub fn u32_le(data: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let len = data.len().min(4);
    buf[..len].copy_from_slice(&data[..len]);
    u32::from_le_bytes(buf)
}

/// Build a padding + payload buffer (common pattern for buffer overflows).
///
/// `offset` is the number of bytes to the return address.
/// `payload` is the data to place after the padding.
/// `pad_byte` is the fill character (default: b'A').
pub fn flat(offset: usize, payload: &[u8], pad_byte: u8) -> Vec<u8> {
    let mut buf = vec![pad_byte; offset];
    buf.extend_from_slice(payload);
    buf
}

/// Cyclic pattern generator for offset finding (De Bruijn sequence).
///
/// Generates a non-repeating pattern of `length` bytes.
pub fn cyclic(length: usize) -> Vec<u8> {
    let mut pattern = Vec::with_capacity(length);
    for i in 0..length {
        let a = (i / (26 * 26)) % 26;
        let b = (i / 26) % 26;
        let c = i % 26;
        pattern.push(b'A' + a as u8);
        if pattern.len() >= length { break; }
        pattern.push(b'a' + b as u8);
        if pattern.len() >= length { break; }
        pattern.push(b'a' + c as u8);
        if pattern.len() >= length { break; }
    }
    pattern.truncate(length);
    pattern
}

/// Find the offset of a 4-byte value in a cyclic pattern.
pub fn cyclic_find(value: u32) -> Option<usize> {
    let pattern = cyclic(0x10000); // Generate a large pattern
    let needle = value.to_le_bytes();
    find_subsequence(&pattern, &needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_subseq_basic() {
        assert_eq!(find_subsequence(b"hello world", b"world"), Some(6));
        assert_eq!(find_subsequence(b"hello", b"xyz"), None);
        assert_eq!(find_subsequence(b"aabbcc", b"bb"), Some(2));
    }

    #[test]
    fn find_subseq_empty() {
        assert_eq!(find_subsequence(b"hello", b""), Some(0));
        assert_eq!(find_subsequence(b"", b"a"), None);
    }

    #[test]
    fn find_subseq_at_boundaries() {
        assert_eq!(find_subsequence(b"abc", b"abc"), Some(0));
        assert_eq!(find_subsequence(b"abc", b"c"), Some(2));
    }

    #[test]
    fn pack_unpack_u64() {
        let val = 0xDEADBEEF12345678u64;
        let packed = p64(val);
        let unpacked = u64_le(&packed);
        assert_eq!(unpacked, val);
    }

    #[test]
    fn pack_unpack_u32() {
        let val = 0xDEADBEEFu32;
        let packed = p32(val);
        let unpacked = u32_le(&packed);
        assert_eq!(unpacked, val);
    }

    #[test]
    fn unpack_short_data() {
        // Unpack 3 bytes as u64 (zero-padded)
        let val = u64_le(&[0x41, 0x42, 0x43]);
        assert_eq!(val, 0x434241);
    }

    #[test]
    fn flat_buffer() {
        let payload = p64(0xDEADBEEF);
        let buf = flat(40, &payload, b'A');
        assert_eq!(buf.len(), 48);
        assert!(buf[..40].iter().all(|&b| b == b'A'));
        assert_eq!(&buf[40..], &payload);
    }

    #[test]
    fn cyclic_pattern_length() {
        let pat = cyclic(100);
        assert_eq!(pat.len(), 100);
    }

    #[test]
    fn cyclic_pattern_non_repeating() {
        let pat = cyclic(1000);
        // Check that no 4-byte subsequence repeats (within a reasonable range)
        for i in 0..pat.len().saturating_sub(4) {
            let needle = &pat[i..i + 4];
            // Should find it at position i and nowhere before
            let first = find_subsequence(&pat, needle).unwrap();
            assert_eq!(first, i, "repeat found at offset {} vs {}", first, i);
        }
    }

    #[test]
    fn cyclic_find_value() {
        let pat = cyclic(1000);
        // Take 4 bytes at offset 100
        let val = u32_le(&pat[100..104]);
        assert_eq!(cyclic_find(val), Some(100));
    }

    #[test]
    fn create_pipes_succeeds() {
        let (child_fds, parent_pipes) = create_child_pipes().unwrap();
        // Clean up
        unsafe {
            libc::close(child_fds.stdin_read);
            libc::close(child_fds.stdout_write);
            libc::close(child_fds.stderr_write);
            libc::close(parent_pipes.stdin_write);
            libc::close(parent_pipes.stdout_read);
            if let Some(fd) = parent_pipes.stderr_read {
                libc::close(fd);
            }
        }
    }

    #[test]
    fn tube_send_recv_via_pipe() {
        // Create a pair of pipes and test tube I/O directly
        let mut pipe_in = [0i32; 2];  // tube writes, test reads
        let mut pipe_out = [0i32; 2]; // test writes, tube reads
        unsafe {
            libc::pipe(pipe_in.as_mut_ptr());
            libc::pipe(pipe_out.as_mut_ptr());
        }

        let mut tube = Tube::from_raw_fds(pipe_in[1], pipe_out[0]);
        tube.set_timeout_ms(1000);

        // Write to the "child stdout" (pipe_out write end)
        let msg = b"hello\n";
        unsafe {
            libc::write(pipe_out[1], msg.as_ptr() as *const libc::c_void, msg.len());
        }

        // Tube should receive it
        let line = tube.recvline().unwrap();
        assert_eq!(line, b"hello\n");

        // Tube sends data
        tube.send(b"world").unwrap();
        let mut buf = [0u8; 5];
        unsafe {
            libc::read(pipe_in[0], buf.as_mut_ptr() as *mut libc::c_void, 5);
        }
        assert_eq!(&buf, b"world");

        // Clean up
        unsafe {
            libc::close(pipe_in[0]);
            libc::close(pipe_out[1]);
        }
    }

    #[test]
    fn tube_recvuntil() {
        let mut pipe_out = [0i32; 2];
        let mut pipe_in = [0i32; 2];
        unsafe {
            libc::pipe(pipe_in.as_mut_ptr());
            libc::pipe(pipe_out.as_mut_ptr());
        }

        let mut tube = Tube::from_raw_fds(pipe_in[1], pipe_out[0]);
        tube.set_timeout_ms(1000);

        let msg = b"Enter name: ";
        unsafe {
            libc::write(pipe_out[1], msg.as_ptr() as *const libc::c_void, msg.len());
        }

        let received = tube.recvuntil(b": ").unwrap();
        assert_eq!(received, b"Enter name: ");

        unsafe {
            libc::close(pipe_in[0]);
            libc::close(pipe_out[1]);
        }
    }

    #[test]
    fn p16_roundtrip() {
        let val = 0x1234u16;
        let packed = p16(val);
        assert_eq!(packed, [0x34, 0x12]);
    }
}
