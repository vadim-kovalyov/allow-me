#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::cognitive_complexity,
    clippy::large_enum_variant,
    clippy::similar_names,
    clippy::module_name_repetitions,
    clippy::use_self,
    clippy::match_same_arms,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,

    dead_code //TODO: remove this
)]
mod builder;
mod errors;
mod matcher;
mod policy;
mod substituter;
mod validator;

pub use builder::PolicyBuilder;
pub use errors::{Error, Result};
pub use matcher::{DefaultResourceMatcher, ResourceMatcher};
pub use policy::{Decision, Policy, Request};
pub use substituter::{DefaultSubstituter, Substituter};
pub use validator::{DefaultValidator, PolicyValidator};
