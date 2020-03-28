//? implementation of errors taken from
//? https://github.com/BurntSushi/imdb-rename/blob/master/imdb-index/src/error.rs

use std::fmt;
use std::result;

use failure::{Backtrace, Context, Fail};

/// A type alias for handling errors throughout openssl-aes.
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    ctx: Context<ErrorKind>,
}

impl Error {
    /// Return the kind of this error.
    pub fn kind(&self) -> &ErrorKind {
        self.ctx.get_context()
    }

    pub(crate) fn encryption<T>(msg: T) -> Error
    where
        T: ToString,
    {
        Error::from(ErrorKind::EncryptionError(msg.to_string()))
    }

    pub(crate) fn decryption<T>(msg: T) -> Error
    where
        T: ToString,
    {
        Error::from(ErrorKind::DecryptionError(msg.to_string()))
    }

    pub(crate) fn keylen(expected: usize, got: usize) -> Error {
        Error::from(ErrorKind::KeyLengthError { expected, got })
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.ctx.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.ctx.backtrace()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.ctx.fmt(f)
    }
}

/// The specific kind of error that can occur.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    KeyLengthError {
        /// The expected key length.
        expected: usize,
        /// The actual key length.
        got: usize,
    },
    /// An error in encryption.
    EncryptionError(String),

    /// An error in decryption.
    DecryptionError(String),
    /// This enum may grow additional variants, so this makes sure clients
    /// don't count on exhaustive matching. (Otherwise, adding a new variant
    /// could break existing code.)
    #[doc(hidden)]
    __Nonexhaustive,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            ErrorKind::KeyLengthError { expected, got } => write!(
                f,
                "key length mismatch: expected {} \
                           but got {}.",
                expected, got
            ),
            ErrorKind::EncryptionError(err) => write!(f, "encryption error: '{}'", err),
            ErrorKind::DecryptionError(err) => write!(f, "decryption error: '{}'", err),
            ErrorKind::__Nonexhaustive => panic!("invalid error"),
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error::from(Context::new(kind))
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(ctx: Context<ErrorKind>) -> Error {
        Error { ctx }
    }
}
