#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

mod core;
mod errors;
pub mod matcher;
mod substituter;
mod validator;

pub use crate::core::{Decision, Effect, Policy, Request};
pub use crate::core::{PolicyBuilder, PolicyDefinition, Statement};
pub use crate::errors::{Error, Result};
pub use crate::matcher::ResourceMatcher;
pub use crate::substituter::{DefaultSubstituter, Substituter, VariableIter};
pub use crate::validator::{DefaultValidator, PolicyValidator};
