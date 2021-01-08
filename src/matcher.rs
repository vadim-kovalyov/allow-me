use crate::core::Request;

/// Trait to extend [`Policy`](`crate::Policy`) resource matching.
pub trait ResourceMatcher {
    /// The type of the context associated with the request.
    type Context;

    /// This method is being called by [`Policy`](`crate::Policy`) when it tries to match a [`Request`] to
    /// a resource in the policy rules.
    fn do_match(&self, context: &Request<Self::Context>, input: &str, policy: &str) -> bool;
}

/// Default matcher uses equality check for resource matching.
#[derive(Debug)]
pub struct Default;

impl ResourceMatcher for Default {
    type Context = ();

    fn do_match(&self, _context: &Request<Self::Context>, input: &str, policy: &str) -> bool {
        input == policy
    }
}

/// Resource matcher that uses "star-with" check for resource matching.
/// Input matches the policy if input value starts with policy value.
#[derive(Debug)]
pub struct StartsWith;

impl ResourceMatcher for StartsWith {
    type Context = ();

    fn do_match(&self, _context: &Request<Self::Context>, input: &str, policy: &str) -> bool {
        input.starts_with(policy)
    }
}
