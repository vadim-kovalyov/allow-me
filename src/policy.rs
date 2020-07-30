use std::collections::{BTreeMap, HashMap};

use crate::{Error, ResourceMatcher};

#[derive(Debug)]
pub struct Policy<R> {
    default_decision: Decision,
    resource_matcher: R,
    rules: BTreeMap<(Identity, Operation), Rules>,
    substitutions: HashMap<String, String>,
}

impl<R> Policy<R>
where
    R: ResourceMatcher,
{
    pub fn evaluate(&mut self, request: &Request) -> Result<Decision, Error> {
        let key = (request.identity.clone(), request.operation.clone());
        match self.rules.get(&key) {
            Some(Rules::Operation(effect)) => Ok(effect.into()),
            Some(Rules::Resources(resources)) => {
                for resource in request.resources.0.iter() {
                    match resources.get(resource) {
                        Some(effect) => Ok::<Decision, Error>(effect.into()),
                        None => Ok(self.default_decision),
                    };
                }
                Ok(self.default_decision)
            }
            None => Ok(self.default_decision),
        }
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct Identity(String);

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct Operation(String);

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Clone)]
pub struct Resource(String);

#[derive(Debug)]
pub struct Resources(Vec<Resource>);

#[derive(Debug)]
pub struct Request {
    identity: Identity,
    operation: Operation,
    resources: Option<Resources>,
    data: HashMap<String, String>,
}

#[derive(Debug, Copy, Clone)]
pub enum Decision {
    Allowed,
    Denied,
}

impl From<&Effect> for Decision {
    fn from(effect: &Effect) -> Self {
        match effect {
            Effect::Allow => Decision::Allowed,
            Effect::Deny => Decision::Denied,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug)]
pub enum Rules {
    Operation(Effect),
    Resources(HashMap<String, Effect>),
}

//#[derive(Debug)]
//pub struct _Rules(Vec<Rule>);
