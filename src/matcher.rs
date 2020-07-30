use crate::{policy::Request, Resource};

pub trait ResourceMatcher {
    fn do_match(&self, context: &Request, input: &Resource, policy: &Resource) -> bool;
}

#[derive(Debug)]
pub struct DefaultMatcher;

impl ResourceMatcher for DefaultMatcher {
    fn do_match(&self, context: &Request, input: &Resource, policy: &Resource) -> bool {
        input == policy
    }
}
