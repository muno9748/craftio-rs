#![cfg_attr(feature = "backtrace", feature(backtrace))]
#![cfg_attr(feature = "gat", feature(generic_associated_types))]

#[cfg(feature = "encryption")]
pub mod cfb8;
pub mod connection;
pub mod reader;
pub mod tcp;
pub mod util;
pub mod wrapper;
pub mod writer;

#[cfg(feature = "encryption")]
pub use crate::cfb8::CipherError;
pub use connection::CraftConnection;
pub use reader::*;
pub use tcp::*;
pub use wrapper::*;
pub use writer::*;
