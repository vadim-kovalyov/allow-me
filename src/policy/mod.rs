mod builder;
pub use builder::PolicyBuilder;

use std::collections::{btree_map::Entry, BTreeMap};

use crate::errors::Result;
use crate::{substituter::Substituter, Error, ResourceMatcher};

/// Policy engine. Represents a read-only set of rules and can
/// evaluate `Request` based on those rules.
///
/// Policy engine consists of two sets:
/// - static rules
/// - variable rules - any rule that contains variables ("{{..}}").
/// Static rules are organized in a data structure with near-constant querying time.
/// Variable rules are evaluated on every request.
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
    /// Evaluates the provided `&Request` and produces the `Decision`.
    ///
    /// If no rules match the `&Request` - the default `Decision` is returned.
    pub fn evaluate(&self, request: &Request) -> Result<Decision> {
        match self.eval_static_rules(request) {
            // static rules deny operation.
            Ok(Effect::Deny) => Ok(Decision::Denied),
            // static rules allow operation. Still need to check variable rules.
            Ok(Effect::Allow) => match self.eval_variable_rules(request) {
                // variable rules undefined. Proceed to allow operation.
                Ok(Effect::Undefined) => Ok(Decision::Allowed),
                // variable rules defined. Return the decision.
                Ok(effect) => Ok(effect.into()),
                Err(e) => Err(e),
            },
            // static rules not defined. Need to check variable rules.
            Ok(Effect::Undefined) => match self.eval_variable_rules(request) {
                // variable rules undefined as well. Return default decision.
                Ok(Effect::Undefined) => Ok(self.default_decision),
                // variable rules defined. Return the decision.
                Ok(effect) => Ok(effect.into()),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        }
    }

    fn eval_static_rules(&self, request: &Request) -> Result<Effect> {
        // lookup an identity
        match self.static_rules.get(&request.identity) {
            // identity exists. Look up operations.
            Some(operations) => match operations.0.get(&request.operation) {
                // operation exists.
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

    fn eval_variable_rules(&self, request: &Request) -> Result<Effect> {
        for (identity, operations) in &self.variable_rules {
            // process identity variables.
            let identity = self.substituter.visit_identity(identity, request)?;
            // check if it does match after processing variables.
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
            self.insert(&key, value);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn insert(&mut self, resource: &str, effect: EffectOrd) {
        let entry = self.0.entry(resource.to_string());
        match entry {
            Entry::Vacant(item) => {
                item.insert(effect);
            }
            Entry::Occupied(mut item) => item.get_mut().merge(effect),
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

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub enum Effect {
    Allow,
    Deny,
    Undefined,
}

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub struct EffectOrd {
    order: usize,
    effect: Effect,
}

impl EffectOrd {
    pub fn new(effect: Effect, order: usize) -> Self {
        Self { order, effect }
    }

    pub fn merge(&mut self, item: EffectOrd) {
        // lower the order => higher the effect priority.
        if self.order > item.order {
            *self = item;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{DefaultResourceMatcher, DefaultSubstituter};
    use matches::assert_matches;

    /// Helper method to build a policy.
    /// Used in both policy and builder tests.
    pub(crate) fn build_policy(json: &str) -> Policy<DefaultResourceMatcher, DefaultSubstituter> {
        PolicyBuilder::from_json(json)
            .with_default_decision(Decision::Denied)
            .build()
            .expect("Unable to build policy from json.")
    }

    #[test]
    fn evaluate_static_rules() {
        let json = r#"{
            "schemaVersion": "2020-10-30",
            "statements": [
                {
                    "effect": "deny",
                    "identities": [
                        "contoso.azure-devices.net/sensor_a"
                    ],
                    "operations": [
                        "mqtt:publish"
                    ],
                    "resources": [
                        "events/alerts"
                    ]
                },
                {
                    "effect": "allow",
                    "identities": [
                        "contoso.azure-devices.net/sensor_b"
                    ],
                    "operations": [
                        "mqtt:subscribe"
                    ],
                    "resources": [
                        "events/alerts"
                    ]
                }
            ]
        }"#;

        let policy = build_policy(json);

        let request = Request::new(
            "contoso.azure-devices.net/sensor_a".into(),
            "mqtt:publish".into(),
            "events/alerts".into(),
        )
        .unwrap();

        assert_matches!(policy.evaluate(&request), Ok(Decision::Denied));

        let request = Request::new(
            "contoso.azure-devices.net/sensor_b".into(),
            "mqtt:subscribe".into(),
            "events/alerts".into(),
        )
        .unwrap();

        assert_matches!(policy.evaluate(&request), Ok(Decision::Allowed));
    }

    #[test]
    fn evaluate_undefined_rules_expected_default_action() {
        let json = r#"{
            "schemaVersion": "2020-10-30",
            "statements": [
                {
                    "effect": "allow",
                    "identities": [
                        "contoso.azure-devices.net/some_device"
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

        let request = Request::new(
            "contoso.azure-devices.net/some_other_device".into(),
            "mqtt:publish".into(),
            "events/alerts".into(),
        )
        .unwrap();

        let allow_default_policy = PolicyBuilder::from_json(json)
            .with_default_decision(Decision::Allowed)
            .build()
            .expect("Unable to build policy from json.");

        assert_matches!(
            allow_default_policy.evaluate(&request),
            Ok(Decision::Allowed)
        );

        let deny_default_policy = PolicyBuilder::from_json(json)
            .with_default_decision(Decision::Denied)
            .build()
            .expect("Unable to build policy from json.");

        assert_matches!(deny_default_policy.evaluate(&request), Ok(Decision::Denied));
    }

    #[test]
    fn evaluate_static_variable_rule_conflict_first_rule_wins() {
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
                },
                {
                    "effect": "deny",
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

        let policy = build_policy(json);

        let request = Request::new(
            "contoso.azure-devices.net/sensor_a".into(),
            "mqtt:publish".into(),
            "events/alerts".into(),
        )
        .unwrap();

        let result = policy.evaluate(&request).unwrap();
        assert_eq!(Decision::Allowed, result);
        todo!()
    }
}
