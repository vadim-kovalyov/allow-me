//! # An authorization library with json-based policy definition.
//! Define your authorization rules in a simple `Identity` (I), `Operation` (O),
//! `Resource` (R) model. Evaluate requests against your policy rules.
//!
//! Supports the following customizations:
//! * variable rules and custom variables,
//! * custom resource matching,
//! * custom validation,
//! * default decision if no rules match.
//!
//! ## Examples
//!
//! ```rust
//! use allow_me::{Decision, PolicyBuilder, Request};
//!
//! let json = r#"{
//!     "statements": [
//!         {
//!             "effect": "allow",
//!             "identities": [
//!                 "actor_a"
//!             ],
//!             "operations": [
//!                 "write"
//!             ],
//!             "resources": [
//!                 "resource_1"
//!             ]
//!         }
//!     ]
//! }"#;
//!
//! // Construct the policy.
//! let policy = PolicyBuilder::from_json(json).build().unwrap();
//!
//! // Prepare request (e.g. from user input).
//! let request = Request::new("actor_a", "write", "resource_1").unwrap();
//!
//! // Evaluate the request.
//! match policy.evaluate(&request).unwrap() {
//!     Decision::Allowed => println!("Allowed"),
//!     Decision::Denied => {
//!         panic!("Denied!")
//!     }
//! };
//! ```
//!
//! See more in Examples folder.
//!

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
