use std::collections::BTreeMap;

use crate::errors::Result;
use crate::{substituter::Substituter, Error, ResourceMatcher};

#[derive(Debug)]
pub struct Policy<R, S> {
    default_decision: Decision,
    resource_matcher: R,
    substituter: S,
    rules: BTreeMap<String, Operations>,
    substitution_rules: BTreeMap<String, Operations>,
}

impl<R, S> Policy<R, S>
where
    R: ResourceMatcher,
    S: Substituter,
{
    pub fn evaluate(&mut self, request: &Request) -> Result<Decision> {
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

    fn eval_rules(&mut self, request: &Request) -> Result<Effect> {
        // lookup an identity
        match self.rules.get(&request.identity) {
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
                            return Ok(*effect);
                        }
                    }
                    Ok(Effect::Undefined)
                }
                None => Ok(Effect::Undefined),
            },
            None => Ok(Effect::Undefined),
        }
    }

    fn eval_substitutions(&mut self, request: &Request) -> Result<Effect> {
        for (identity, operations) in &self.substitution_rules {
            // process identity substitution.
            if let Ok(identity) = self.substituter.visit_identity(identity, request) {
                // check if it does match after substitution.
                if identity == request.identity {
                    // lookup operation.
                    return match operations.0.get(&request.operation) {
                        // operation exists.
                        Some(resources) => {
                            // Iterate over and match resources.
                            for (resource, effect) in &resources.0 {
                                if self.resource_matcher.do_match(
                                    request,
                                    &request.resource,
                                    &resource,
                                ) {
                                    return Ok(*effect);
                                }
                            }
                            Ok(Effect::Undefined)
                        }
                        None => Ok(Effect::Undefined),
                    };
                }
            }
        }
        Ok(Effect::Undefined)
    }
}

#[derive(Debug)]
pub struct Operations(BTreeMap<String, Resources>);

#[derive(Debug)]
pub struct Resources(BTreeMap<String, Effect>);

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

#[derive(Debug, Copy, Clone)]
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

#[cfg(test)]
pub(crate) mod tests {

    fn evaluate_explicit_rule_allowed() {}

    fn evaluate_explicit_rule_denied() {}

    fn evaluate_explicit_rule_undefined_expected_default_action() {}

    fn evaluate_explicit_rule_allowed_substitution_rule_denied_expected_denied() {}

    fn evaluate_explicit_rule_denied_substitution_rule_allowed_expected_denied() {}
}
