use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("ptrace error: {0}")]
    Ptrace(#[from] nix::errno::Errno),

    #[error("process error: {0}")]
    Process(String),

    #[error("breakpoint error: {0}")]
    Breakpoint(String),

    #[error("register error: {0}")]
    Register(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
