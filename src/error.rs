//! Error types used throughout the crate.
//!
//! Provides a unified [`Error`] enum covering ptrace failures, process
//! control issues, breakpoint/register errors, I/O, and general-purpose
//! error messages. All fallible functions return [`Result<T>`].

use thiserror::Error;

/// Unified error type for all rnicro operations.
#[derive(Error, Debug)]
pub enum Error {
    /// A ptrace system call failed.
    #[error("ptrace error: {0}")]
    Ptrace(#[from] nix::errno::Errno),

    /// Process control error (launch, attach, wait, etc.).
    #[error("process error: {0}")]
    Process(String),

    /// Breakpoint management error.
    #[error("breakpoint error: {0}")]
    Breakpoint(String),

    /// Register read/write error.
    #[error("register error: {0}")]
    Register(String),

    /// Standard I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// General-purpose error with a descriptive message.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias for `std::result::Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;
