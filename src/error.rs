//! Error types for string extraction operations.

use std::fmt;
use thiserror::Error;

/// Errors that can occur during string extraction operations.
#[derive(Error, Debug)]
pub enum StngError {
    /// Input file or data is too large to process safely.
    #[error("Input too large: {size} bytes (max {max} bytes)")]
    InputTooLarge {
        /// Actual size of the input.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Invalid binary format or unable to parse binary.
    #[error("Invalid binary format: {0}")]
    InvalidBinary(String),

    /// Invalid instruction bytes or unable to decode.
    #[error("Invalid instruction at offset {offset}: {reason}")]
    InvalidInstruction {
        /// Offset where the invalid instruction was found.
        offset: usize,
        /// Reason the instruction is invalid.
        reason: String,
    },

    /// File offset out of bounds.
    #[error("Offset {offset} out of bounds (file size: {size})")]
    OffsetOutOfBounds {
        /// The invalid offset.
        offset: usize,
        /// The file size.
        size: usize,
    },

    /// Cache operation failed.
    #[error("Cache error: {0}")]
    CacheError(String),

    /// Time calculation failed.
    #[error("Time error: {0}")]
    TimeError(String),

    /// System call or operation failed.
    #[error("System error: {0}")]
    SystemError(String),

    /// Invalid XOR key.
    #[error("Invalid XOR key: {0}")]
    InvalidXorKey(String),

    /// Generic error for other cases.
    #[error("{0}")]
    Other(String),
}

impl StngError {
    /// Create an error for input that's too large.
    pub fn input_too_large(size: usize, max: usize) -> Self {
        Self::InputTooLarge { size, max }
    }

    /// Create an error for an invalid binary format.
    pub fn invalid_binary(msg: impl fmt::Display) -> Self {
        Self::InvalidBinary(msg.to_string())
    }

    /// Create an error for an invalid instruction.
    pub fn invalid_instruction(offset: usize, reason: impl fmt::Display) -> Self {
        Self::InvalidInstruction {
            offset,
            reason: reason.to_string(),
        }
    }

    /// Create an error for an out-of-bounds offset.
    pub fn offset_out_of_bounds(offset: usize, size: usize) -> Self {
        Self::OffsetOutOfBounds { offset, size }
    }

    /// Create a cache error.
    pub fn cache_error(msg: impl fmt::Display) -> Self {
        Self::CacheError(msg.to_string())
    }

    /// Create a time error.
    pub fn time_error(msg: impl fmt::Display) -> Self {
        Self::TimeError(msg.to_string())
    }

    /// Create a system error.
    pub fn system_error(msg: impl fmt::Display) -> Self {
        Self::SystemError(msg.to_string())
    }

    /// Create an invalid XOR key error.
    pub fn invalid_xor_key(msg: impl fmt::Display) -> Self {
        Self::InvalidXorKey(msg.to_string())
    }
}

/// Result type alias using StngError.
pub type Result<T> = std::result::Result<T, StngError>;

// Note: StngError implements std::error::Error via thiserror, so it automatically
// works with anyhow via anyhow's blanket From<E> implementation for any E: std::error::Error
