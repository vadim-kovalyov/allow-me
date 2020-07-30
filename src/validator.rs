use crate::Error;

pub trait PolicyValidator {
    fn validate(field: Field, value: &str) -> Result<(), Error>;
}

pub enum Field {
    Identities,
    Operations,
    Resources,
    Description,
}

struct DefaultValidator;

impl PolicyValidator for DefaultValidator {
    fn validate(field: Field, value: &str) -> Result<(), Error> {
        Ok(())
    }
}
