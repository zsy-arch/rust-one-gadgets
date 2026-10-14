//! 统一错误类型。

use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum RogError {
    #[error("failed to parse ELF: {0}")]
    ElfParse(String),
    #[error("unsupported architecture (machine={0}); rog supports x86-64 and i386")]
    UnsupportedArch(u16),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RogError>;
