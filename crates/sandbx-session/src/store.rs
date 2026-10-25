//! Session persistence on disk: [`session`] is the store and an open transcript,
//! [`record`] the line format, [`shape`] what a legal history looks like, [`vet`] who
//! may read the files.

mod record;
mod session;
mod shape;
mod vet;

pub use session::{Session, SessionStore};
