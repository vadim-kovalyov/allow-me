use std::collections::{btree_map::Entry, BTreeMap};

use crate::errors::Result;
use crate::{substituter::Substituter, Error, ResourceMatcher};

#[derive(Debug)]
pub struct Policy<R, S> {
    default_decision: Decision,
    resource_matcher: R,
    substituter: S,
    static_rules: BTreeMap<String, Operations>,
    variable_rules: BTreeMap<String, Operations>,
}

impl<R, S> Policy<R, S>
where
    R: ResourceMatcher,
    S: Substituter,
{
    pub(crate) fn new(
        default_decision: Decision,
        resource_matcher: R,
        substituter: S,
        static_rules: BTreeMap<String, Operations>,
        variable_rules: BTreeMap<String, Operations>,
    ) -> Self {
        Policy {
            default_decision,
            resource_matcher,
            substituter,
            static_rules,
            variable_rules,
        }
    }

    pub fn evaluate(&self, request: &Request) -> Result<Decision> {
        match self.eval_rules(request) {
            // explicit rules deny operation.
            Ok(Effect::Deny) => Ok(Decision::Denied),
            // explicit rules allow operation. Still need to check substitution rules.
            Ok(Effect::Allow) => match self.eval_substitutions(request) {
                // Substitution rules undefined. Proceed to allow operation.
                Ok(Effect::Undefined) => Ok(Decision::Allowed),
                // Substitution rules defined. Return the decision.
                Ok(effect) => Ok(effect.into()),
                Err(e) => Err(e),
            },
            // explicit rules not defined. Need to check substitution rules.
            Ok(Effect::Undefined) => match self.eval_substitutions(request) {
                // Substitution rules undefined as well. Return default decision.
                Ok(Effect::Undefined) => Ok(self.default_decision),
                // Substitution rules defined. Return the decision.
                Ok(effect) => Ok(effect.into()),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        }
    }

    fn eval_rules(&self, request: &Request) -> Result<Effect> {
        // lookup an identity
        match self.static_rules.get(&request.identity) {
            // identity rules exist. Look up operations.
            Some(operations) => match operations.0.get(&request.operation) {
                // operation exist.
                Some(resources) => {
                    // Iterate over and match resources.
                    for (resource, effect) in &resources.0 {
                        if self
                            .resource_matcher
                            .do_match(request, &request.resource, &resource)
                        {
                            return Ok(effect.effect);
                        }
                    }
                    Ok(Effect::Undefined)
                }
                None => Ok(Effect::Undefined),
            },
            None => Ok(Effect::Undefined),
        }
    }

    fn eval_substitutions(&self, request: &Request) -> Result<Effect> {
        for (identity, operations) in &self.variable_rules {
            // process identity substitution.
            let identity = self.substituter.visit_identity(identity, request)?;
            // check if it does match after substitution.
            if identity == request.identity {
                // lookup operation.
                return match operations.0.get(&request.operation) {
                    // operation exists.
                    Some(resources) => {
                        // Iterate over and match resources.
                        for (resource, effect) in &resources.0 {
                            let resource = self.substituter.visit_resource(resource, request)?;
                            if self
                                .resource_matcher
                                .do_match(request, &request.resource, &resource)
                            {
                                return Ok(effect.effect);
                            }
                        }
                        Ok(Effect::Undefined)
                    }
                    None => Ok(Effect::Undefined),
                };
            }
        }
        Ok(Effect::Undefined)
    }
}

#[derive(Debug, Clone)]
pub struct Identities(pub BTreeMap<String, Operations>);

impl Identities {
    pub fn new() -> Self {
        Identities(BTreeMap::new())
    }

    pub fn merge(&mut self, collection: Identities) {
        for (key, value) in collection.0 {
            self.insert(&key, value);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn insert(&mut self, operation: &str, resources: Operations) {
        if !resources.is_empty() {
            let entry = self.0.entry(operation.to_string());
            match entry {
                Entry::Vacant(item) => {
                    item.insert(resources);
                }
                Entry::Occupied(mut item) => item.get_mut().merge(resources),
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Operations(BTreeMap<String, Resources>);

impl Operations {
    pub fn new() -> Self {
        Operations(BTreeMap::new())
    }

    pub fn merge(&mut self, collection: Operations) {
        for (key, value) in collection.0 {
            self.insert(&key, value);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn insert(&mut self, operation: &str, resources: Resources) {
        if !resources.is_empty() {
            let entry = self.0.entry(operation.to_string());
            match entry {
                Entry::Vacant(item) => {
                    item.insert(resources);
                }
                Entry::Occupied(mut item) => item.get_mut().merge(resources),
            }
        }
    }
}

impl From<BTreeMap<String, Resources>> for Operations {
    fn from(map: BTreeMap<String, Resources>) -> Self {
        Operations(map)
    }
}

#[derive(Debug, Clone)]
pub struct Resources(BTreeMap<String, EffectOrd>);

impl Resources {
    pub fn new() -> Self {
        Resources(BTreeMap::new())
    }

    pub fn merge(&mut self, collection: Resources) {
        for (key, value) in collection.0 {
            self.insert(key, value);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn insert(&mut self, resource: String, effect: EffectOrd) {
        let entry = self.0.entry(resource);
        match entry {
            Entry::Vacant(item) => {
                item.insert(effect);
            }
            Entry::Occupied(mut item) => {
                // lower the order => higher the effect priority.
                if item.get().order > effect.order {
                    item.insert(effect);
                }
            }
        }
    }
}

impl From<BTreeMap<String, EffectOrd>> for Resources {
    fn from(map: BTreeMap<String, EffectOrd>) -> Self {
        Resources(map)
    }
}

#[derive(Debug)]
pub struct Request {
    identity: String,
    operation: String,
    resource: String,
}

impl Request {
    pub fn new(identity: String, operation: String, resource: String) -> Result<Self> {
        if identity.is_empty() {
            return Err(Error::BadRequest("Identity must be specified".into()));
        }

        if operation.is_empty() {
            return Err(Error::BadRequest("Operation must be specified".into()));
        }

        Ok(Self {
            identity,
            operation,
            resource,
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Decision {
    Allowed,
    Denied,
}

impl From<Effect> for Decision {
    fn from(effect: Effect) -> Self {
        match effect {
            Effect::Allow => Decision::Allowed,
            Effect::Deny => Decision::Denied,
            Effect::Undefined => Decision::Denied,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Effect {
    Allow,
    Deny,
    Undefined,
}

#[derive(Debug, Copy, Clone)]
pub struct EffectOrd {
    order: usize,
    effect: Effect,
}

impl EffectOrd {
    pub fn new(effect: Effect, order: usize) -> Self {
        Self { order, effect }
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;
    use crate::{DefaultResourceMatcher, DefaultSubstituter, DefaultValidator, PolicyBuilder};

    #[test]
    fn evaluate_explicit_rule_allowed() {
        let json = r#"{
            "schemaVersion": "2020-10-30",
            "statements": [
                {
                    "effect": "allow",
                    "identities": [
                        "contoso.azure-devices.net/sensor_a"
                    ],
                    "operations": [
                        "mqtt:publish"
                    ],
                    "resources": [
                        "events/alerts"
                    ]
                }
            ]
        }"#;

        let policy = PolicyBuilder::from_json(json)
            .with_validator(DefaultValidator)
            .with_matcher(DefaultResourceMatcher)
            .with_substituter(DefaultSubstituter)
            .with_default_decision(Decision::Denied)
            .build()
            .unwrap();

        let request = Request::new(
            "contoso.azure-devices.net/sensor_a".into(),
            "mqtt:publish".into(),
            "events/alerts".into(),
        )
        .unwrap();

        let result = policy.evaluate(&request).unwrap();
        assert_eq!(Decision::Allowed, result);
    }

    fn evaluate_explicit_rule_denied() {}

    fn evaluate_explicit_rule_undefined_expected_default_action() {}

    fn evaluate_explicit_rule_allowed_substitution_rule_denied_expected_denied() {}

    fn evaluate_explicit_rule_denied_substitution_rule_allowed_expected_denied() {}

    fn evaluate_explicit_rule_empty_resource_allowed() {}

    fn evaluate_explicit_rule_empty_resource_denied() {}
}
