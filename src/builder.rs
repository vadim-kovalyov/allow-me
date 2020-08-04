use serde::Deserialize;

use crate::{Decision, Error, Policy, PolicyValidator, ResourceMatcher, Result, Substituter};

pub struct PolicyBuilder<V, M, S> {
    validator: Option<V>,
    matcher: Option<M>,
    substituter: Option<S>,
    json: String,
    default_decision: Decision,
}

impl<V, M, S> PolicyBuilder<V, M, S>
where
    V: PolicyValidator,
    M: ResourceMatcher,
    S: Substituter,
{
    pub fn from_json(json: &str) -> Self {
        Self {
            json: json.into(),
            validator: None,
            matcher: None,
            substituter: None,
            default_decision: Decision::Denied,
        }
    }

    pub fn with_validator(mut self, validator: V) -> Self {
        self.validator = Some(validator);
        self
    }

    pub fn with_matcher(mut self, matcher: M) -> Self {
        self.matcher = Some(matcher);
        self
    }

    pub fn with_substituter(mut self, substituter: S) -> Self {
        self.substituter = Some(substituter);
        self
    }

    pub fn with_default_decision(mut self, decision: Decision) -> Self {
        self.default_decision = decision;
        self
    }

    pub fn build(self) -> Result<Policy<M, S>> {
        let definition: PolicyDefinitionV1 =
            serde_json::from_str(&self.json).map_err(|e| Error::Deserializing(e))?;

        todo!()
    }
}

#[derive(Deserialize)]
struct PolicyVersion {
    version: String,
}

#[derive(Deserialize)]
struct PolicyDefinitionV1 {
    version: String,
    allow: Vec<StatementV1>,
    deny: Vec<StatementV1>,
}

#[derive(Deserialize)]
struct StatementV1 {
    identity: Vec<String>,
    operation: Vec<String>,
    resource: Vec<String>,
}
