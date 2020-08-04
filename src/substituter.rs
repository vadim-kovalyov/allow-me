use crate::{Error, Request};

pub trait Substituter {
    fn visit_identity(&self, value: &str, context: &Request) -> Result<String, Error>;
    fn visit_resource(&self, value: &str, context: &Request) -> Result<String, Error>;
}

#[derive(Debug)]
pub struct DefaultSubstituter;

impl Substituter for DefaultSubstituter {
    fn visit_identity(&self, value: &str, _context: &Request) -> Result<String, Error> {
        Ok(value.to_string())
    }

    fn visit_resource(&self, value: &str, _context: &Request) -> Result<String, Error> {
        Ok(value.to_string())
    }
}
