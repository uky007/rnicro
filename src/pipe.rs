//! Inter-process pipe for fork/exec synchronization.
//!
//! Corresponds to sdb's pipe.hpp and book Ch.4 (Pipes, procfs, and Automated Testing).
//!
//! When launching a debuggee via fork + exec, there is a race between
//! the child calling `PTRACE_TRACEME` and the parent calling `waitpid`.
//! A pipe provides a reliable synchronization mechanism: the child
//! notifies the parent after `traceme` succeeds, and the parent waits
//! on the pipe before proceeding.

use crate::error::{Error, Result};

/// A unidirectional byte pipe used to synchronize parent and child processes.
pub struct Channel {
    read_fd: i32,
    write_fd: i32,
}

impl Channel {
    /// Create a new pipe channel.
    pub fn new() -> Result<Self> {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if ret == -1 {
            return Err(Error::Process("pipe() failed".into()));
        }
        Ok(Channel {
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }

    /// Send a one-byte notification through the pipe.
    ///
    /// Called by the child process after `PTRACE_TRACEME` succeeds.
    pub fn notify(&self) -> Result<()> {
        let buf = [0u8; 1];
        let ret = unsafe { libc::write(self.write_fd, buf.as_ptr() as *const libc::c_void, 1) };
        if ret == -1 {
            return Err(Error::Process("pipe notify failed".into()));
        }
        Ok(())
    }

    /// Block until a notification is received.
    ///
    /// Called by the parent process to wait for the child's `traceme`.
    pub fn wait(&self) -> Result<()> {
        let mut buf = [0u8; 1];
        let ret =
            unsafe { libc::read(self.read_fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        if ret == -1 {
            return Err(Error::Process("pipe wait failed".into()));
        }
        if ret == 0 {
            return Err(Error::Process("pipe closed unexpectedly (child failed?)".into()));
        }
        Ok(())
    }

    /// Close the read end (typically called by the child after fork).
    pub fn close_read(&self) {
        unsafe { libc::close(self.read_fd) };
    }

    /// Close the write end (typically called by the parent after fork).
    pub fn close_write(&self) {
        unsafe { libc::close(self.write_fd) };
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_creation() {
        let ch = Channel::new().expect("pipe creation should succeed");
        assert!(ch.read_fd >= 0);
        assert!(ch.write_fd >= 0);
        assert_ne!(ch.read_fd, ch.write_fd);
    }
}
