use crate::errors::Result;

pub trait PolicyValidator {
    fn validate(&self, field: Field, value: &str) -> Result<()>;
}

#[derive(Debug)]
pub enum Field {
    Identities,
    Operations,
    Resources,
    Description,
}

#[derive(Debug)]
pub struct DefaultValidator;

impl PolicyValidator for DefaultValidator {
    fn validate(&self, _field: Field, _value: &str) -> Result<()> {
        Ok(())
    }
}
