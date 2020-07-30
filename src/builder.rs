use crate::{policy::Decision, Policy, PolicyValidator, ResourceMatcher, Result};

pub struct PolicyBuilder<V, M> {
    validator: Option<V>,
    matcher: Option<M>,
    json: String,
    decision: Decision,
}

impl<V, M> PolicyBuilder<V, M>
where
    V: PolicyValidator,
    M: ResourceMatcher,
{
    pub fn from_json(mut self, json: &str) -> Self {
        Self {
            json: json.into(),
            validator: None,
            matcher: None,
            decision: Decision::Denied,
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

    pub fn with_default_decision(mut self, decision: Decision) -> Self {
        self.decision = decision;
        self
    }

    pub fn build(mut self) -> Result<Policy<M>> {
        todo!()
    }
}
