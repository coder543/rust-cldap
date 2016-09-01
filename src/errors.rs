//! Errors and trait implementations.
//!
use std::fmt;
use std::error;
use std::convert;


/// A LDAP error.
///
/// LDAP errors occur when an underlying function returns with an error code. Currently, there is
/// only one type of error raised: `LDAPError::NativeError`. A `LDAPError::NativeError` includes a
/// string field describing the error in more detail.
///
/// A `LDAPError` implements necessary traits (i.e., std::fmt::Display, std::error::Error, and
/// std::convert::From) to do proper error handling using the `try!` macro.
///
#[derive(Debug, PartialEq)]
pub enum LDAPError {
    NativeError(String),
}

impl fmt::Display for LDAPError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LDAPError::NativeError(ref err) => write!(f, "LDAP error: {}", err),
        }
    }
}

impl error::Error for LDAPError {

    /// Get the description of this error.
    ///
    fn description(&self) -> &str {
        match *self {
            LDAPError::NativeError(ref err) => err
        }
    }

    /// Get the cause of this error.
    ///
    /// Note, currently this method always return `None` as we do not know the root cause of the
    /// error.
    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

impl convert::From<String> for LDAPError {
    fn from(err: String) -> LDAPError {
        LDAPError::NativeError(err)
    }
}

