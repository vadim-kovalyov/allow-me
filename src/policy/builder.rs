use serde::Deserialize;

use crate::{
    policy::{Effect as CoreEffect, EffectOrd, Identities, Operations, Resources},
    Decision, Error, Policy, PolicyValidator, ResourceMatcher, Result, Substituter,
};

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
        let mut definition: PolicyDefinition20201030 =
            serde_json::from_str(&self.json).map_err(Error::Deserializing)?;

        for (order, mut statement) in definition.statements.iter_mut().enumerate() {
            statement.order = order;
        }

        let mut static_rules = Identities::new();
        let mut variable_rules = Identities::new();

        for statement in definition.statements {
            process_statement(&statement, &mut static_rules, &mut variable_rules);
        }

        Ok(Policy {
            default_decision: self.default_decision,
            resource_matcher: self.matcher.unwrap(),
            substituter: self.substituter.unwrap(),
            static_rules: static_rules.0,
            variable_rules: variable_rules.0,
        })
    }
}

fn process_statement(
    statement: &Statement20201030,
    static_rules: &mut Identities,
    variable_rules: &mut Identities,
) {
    let (static_ids, variable_ids) = process_identities(statement);

    static_rules.merge(static_ids);
    variable_rules.merge(variable_ids);
}

fn process_identities(statement: &Statement20201030) -> (Identities, Identities) {
    let mut static_ids = Identities::new();
    let mut variable_ids = Identities::new();
    for identity in &statement.identities {
        let (static_ops, variable_ops) = process_operations(&statement);

        if is_variable_rule(identity) {
            // if current identity has substitutions,
            // then the whole operation subtree need
            // to be cloned into substitutions tree.
            let mut all = static_ops.clone();
            all.merge(variable_ops);
            variable_ids.insert(identity, all);
        } else {
            // else, divide operations and operation substitutions
            // between identities and identity substitutions.
            static_ids.insert(identity, static_ops);
            variable_ids.insert(identity, variable_ops);
        }
    }

    (static_ids, variable_ids)
}

fn process_operations(statement: &Statement20201030) -> (Operations, Operations) {
    let mut static_ops = Operations::new();
    let mut variable_ops = Operations::new();
    for operation in &statement.operations {
        let (static_res, variable_res) = process_resources(&statement);

        if is_variable_rule(operation) {
            // if current operation has variables,
            // then the whole resource subtree need
            // to be cloned into variables tree.
            let mut all = static_res.clone();
            all.merge(variable_res);
            variable_ops.insert(operation, all);
        } else {
            // else, divide static resources and variable resources
            // between static operations and variable operation.
            static_ops.insert(operation, static_res);
            variable_ops.insert(operation, variable_res);
        }
    }

    (static_ops, variable_ops)
}

fn process_resources(statement: &Statement20201030) -> (Resources, Resources) {
    let mut static_res = Resources::new();
    let mut variable_res = Resources::new();
    for resource in &statement.resources {
        // split resources into two static or variable rules:
        let map = if is_variable_rule(resource) {
            &mut variable_res
        } else {
            &mut static_res
        };

        map.insert(resource, statement.into());
    }

    (static_res, variable_res)
}

fn is_variable_rule(value: &str) -> bool {
    value.contains("{{") //TODO: change to regex
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyVersion {
    schema_version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyDefinition20201030 {
    schema_version: String,
    statements: Vec<Statement20201030>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Statement20201030 {
    #[serde(default)]
    order: usize,
    #[serde(default)]
    description: String,
    effect: Effect20201030,
    identities: Vec<String>,
    operations: Vec<String>,
    #[serde(default)]
    resources: Vec<String>,
}

#[derive(Deserialize, Copy, Clone)]
#[serde(rename_all = "camelCase")]
enum Effect20201030 {
    Allow,
    Deny,
}

impl Into<EffectOrd> for &Statement20201030 {
    fn into(self) -> EffectOrd {
        match self.effect {
            Effect20201030::Allow => EffectOrd::new(CoreEffect::Allow, self.order),
            Effect20201030::Deny => EffectOrd::new(CoreEffect::Deny, self.order),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DefaultResourceMatcher, DefaultSubstituter, DefaultValidator};

    fn build_policy(json: &str) -> Policy<DefaultResourceMatcher, DefaultSubstituter> {
        PolicyBuilder::from_json(json)
            .with_validator(DefaultValidator)
            .with_matcher(DefaultResourceMatcher)
            .with_substituter(DefaultSubstituter)
            .with_default_decision(Decision::Denied)
            .build()
            .expect("Unable to build policy from json.")
    }

    #[test]
    fn test_basic_definition() {
        let json = r#"{
            "schemaVersion": "2020-10-30",
            "statements": [
                {
                    "effect": "allow",
                    "identities": [
                        "contoso.azure-devices.net/monitor_a"
                    ],
                    "operations": [
                        "mqtt:subscribe"
                    ],
                    "resources": [
                        "events/#"
                    ]
                },
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
                    "description": "Deny all other iot identities to subscribe",
                    "effect": "deny",
                    "identities": [
                        "{{iot:identity}}"
                    ],
                    "operations": [
                        "mqtt:subscribe"
                    ],
                    "resources": [
                        "events/#"
                    ]
                }
            ]
        }"#;

        let policy: Policy<DefaultResourceMatcher, DefaultSubstituter> = build_policy(json);

        assert_eq!(1, policy.variable_rules.len());
        assert_eq!(2, policy.static_rules.len());
    }

    #[test]
    fn identity_merge_rules() {
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
                        "events/telemetry"
                    ]
                },
                {
                    "effect": "allow",
                    "identities": [
                        "contoso.azure-devices.net/sensor_a"
                    ],
                    "operations": [
                        "mqtt:subscribe"
                    ],
                    "resources": [
                        "events/alerts"
                    ]
                },
                {
                    "effect": "allow",
                    "identities": [
                        "contoso.azure-devices.net/sensor_a"
                    ],
                    "operations": [
                        "mqtt:subscribe"
                    ],
                    "resources": [
                        "{{mqtt:client_id}}/#"
                    ]
                },
                {
                    "effect": "allow",
                    "identities": [
                        "contoso.azure-devices.net/sensor_a"
                    ],
                    "operations": [
                        "mqtt:publish"
                    ],
                    "resources": [
                        "{{mqtt:client_id}}/#"
                    ]
                }
            ]
        }"#;

        let policy: Policy<DefaultResourceMatcher, DefaultSubstituter> = build_policy(json);

        // assert static rules have 1 identity and 2 operations
        assert_eq!(1, policy.static_rules.len());
        assert_eq!(
            2,
            policy.static_rules["contoso.azure-devices.net/sensor_a"]
                .0
                .len()
        );

        // assert variable rules have 1 identity and 2 operations
        assert_eq!(1, policy.variable_rules.len());
        assert_eq!(
            2,
            policy.variable_rules["contoso.azure-devices.net/sensor_a"]
                .0
                .len()
        );
    }

    #[test]
    fn operation_merge_rules() {
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
                        "events/telemetry"
                    ]
                },
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
                    "effect": "allow",
                    "identities": [
                        "contoso.azure-devices.net/sensor_a"
                    ],
                    "operations": [
                        "mqtt:subscribe"
                    ],
                    "resources": [
                        "{{mqtt:client_id}}/#"
                    ]
                },
                {
                    "effect": "allow",
                    "identities": [
                        "contoso.azure-devices.net/sensor_a"
                    ],
                    "operations": [
                        "mqtt:subscribe"
                    ],
                    "resources": [
                        "devices/{{mqtt:client_id}}/#"
                    ]
                }
            ]
        }"#;

        let policy: Policy<DefaultResourceMatcher, DefaultSubstituter> = build_policy(json);

        // assert static rules have 1 identity, 1 operations and 2 resources
        assert_eq!(
            1,
            policy.static_rules["contoso.azure-devices.net/sensor_a"]
                .0
                .len()
        );
        assert_eq!(
            2,
            policy.static_rules["contoso.azure-devices.net/sensor_a"].0["mqtt:publish"]
                .0
                .len()
        );

        // assert variable rules have 1 identity, 1 operations and 2 resources
        assert_eq!(
            1,
            policy.variable_rules["contoso.azure-devices.net/sensor_a"]
                .0
                .len()
        );
        assert_eq!(
            2,
            policy.variable_rules["contoso.azure-devices.net/sensor_a"].0["mqtt:subscribe"]
                .0
                .len()
        );
    }

    #[test]
    fn resource_merge_rules_higher_priority_statement_wins() {
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
                        "events/telemetry"
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
                        "events/telemetry"
                    ]
                },
                {
                    "effect": "allow",
                    "identities": [
                        "contoso.azure-devices.net/sensor_a"
                    ],
                    "operations": [
                        "mqtt:subscribe"
                    ],
                    "resources": [
                        "{{mqtt:client_id}}/#"
                    ]
                },
                {
                    "effect": "deny",
                    "identities": [
                        "contoso.azure-devices.net/sensor_a"
                    ],
                    "operations": [
                        "mqtt:subscribe"
                    ],
                    "resources": [
                        "{{mqtt:client_id}}/#"
                    ]
                }
            ]
        }"#;

        let policy: Policy<DefaultResourceMatcher, DefaultSubstituter> = build_policy(json);

        // assert higher priority rule wins.
        assert_eq!(
            EffectOrd {
                order: 0,
                effect: CoreEffect::Allow
            },
            policy.static_rules["contoso.azure-devices.net/sensor_a"].0["mqtt:publish"].0
                ["events/telemetry"]
        );

        // assert higher priority rule wins for variable rules.
        assert_eq!(
            EffectOrd {
                order: 2,
                effect: CoreEffect::Allow
            },
            policy.variable_rules["contoso.azure-devices.net/sensor_a"].0["mqtt:subscribe"].0
                ["{{mqtt:client_id}}/#"]
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn grouping_rules_with_variables_test() {
        let json = r#"{
            "schemaVersion": "2020-10-30",
            "statements": [
                {
                    "effect": "allow",
                    "identities": [
                        "contoso.azure-devices.net/sensor_a",
                        "contoso.azure-devices.net/sensor_b",
                        "{{iot:identity}}"
                    ],
                    "operations": [
                        "mqtt:publish",
                        "mqtt:subscribe"
                    ],
                    "resources": [
                        "events/telemetry",
                        "devices/{{mqtt:client_id}}/#"
                    ]
                }
            ]
        }"#;

        let policy: Policy<DefaultResourceMatcher, DefaultSubstituter> = build_policy(json);

        // assert static rules.
        assert_eq!(2, policy.static_rules.len());
        assert_eq!(
            policy.static_rules["contoso.azure-devices.net/sensor_a"].0["mqtt:publish"].0
                ["events/telemetry"],
            EffectOrd {
                effect: CoreEffect::Allow,
                order: 0
            }
        );
        assert_eq!(
            policy.static_rules["contoso.azure-devices.net/sensor_a"].0["mqtt:subscribe"].0
                ["events/telemetry"],
            EffectOrd {
                effect: CoreEffect::Allow,
                order: 0
            }
        );
        assert_eq!(
            policy.static_rules["contoso.azure-devices.net/sensor_b"].0["mqtt:publish"].0
                ["events/telemetry"],
            EffectOrd {
                effect: CoreEffect::Allow,
                order: 0
            }
        );
        assert_eq!(
            policy.static_rules["contoso.azure-devices.net/sensor_b"].0["mqtt:subscribe"].0
                ["events/telemetry"],
            EffectOrd {
                effect: CoreEffect::Allow,
                order: 0
            }
        );

        // assert variable rules.
        assert_eq!(3, policy.variable_rules.len());
        assert_eq!(
            policy.variable_rules["contoso.azure-devices.net/sensor_a"].0["mqtt:publish"].0
                ["devices/{{mqtt:client_id}}/#"],
            EffectOrd {
                effect: CoreEffect::Allow,
                order: 0
            }
        );
        assert_eq!(
            policy.variable_rules["contoso.azure-devices.net/sensor_a"].0["mqtt:subscribe"].0
                ["devices/{{mqtt:client_id}}/#"],
            EffectOrd {
                effect: CoreEffect::Allow,
                order: 0
            }
        );
        assert_eq!(
            policy.variable_rules["contoso.azure-devices.net/sensor_b"].0["mqtt:publish"].0
                ["devices/{{mqtt:client_id}}/#"],
            EffectOrd {
                effect: CoreEffect::Allow,
                order: 0
            }
        );
        assert_eq!(
            policy.variable_rules["contoso.azure-devices.net/sensor_b"].0["mqtt:subscribe"].0
                ["devices/{{mqtt:client_id}}/#"],
            EffectOrd {
                effect: CoreEffect::Allow,
                order: 0
            }
        );
        assert_eq!(
            policy.variable_rules["{{iot:identity}}"].0["mqtt:publish"].0
                ["devices/{{mqtt:client_id}}/#"],
            EffectOrd {
                effect: CoreEffect::Allow,
                order: 0
            }
        );
        assert_eq!(
            policy.variable_rules["{{iot:identity}}"].0["mqtt:subscribe"].0
                ["devices/{{mqtt:client_id}}/#"],
            EffectOrd {
                effect: CoreEffect::Allow,
                order: 0
            }
        );
    }
}
