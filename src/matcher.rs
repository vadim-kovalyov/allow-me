use crate::policy::Request;

pub trait ResourceMatcher {
    fn do_match(&self, context: &Request, input: &str, policy: &str) -> bool;
}

#[derive(Debug)]
pub struct DefaultResourceMatcher;

impl ResourceMatcher for DefaultResourceMatcher {
    fn do_match(&self, _context: &Request, input: &str, policy: &str) -> bool {
        input == policy
    }
}
