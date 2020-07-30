use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("An error occurred deserializing policy definition {0}.")]
    DeserializingError(String),

    #[error("An error occurred validating policy definition {0}.")]
    ValidationError(String),
}
