# Allow-me
![CI](https://github.com/vadim-kovalyov/allow-me/workflows/CI/badge.svg)   

An authorization library with json-based policy definition.

Define your authorization rules in a simple `Identity` (I), `Operation` (O), `Resource` (R) model. Evaluate requests against your policy rules.

# Installation
```toml
[dependencies]
allow-me = "0.1"
```
# Examples
## Json definition
A simple example for a policy with one statement and a request evaluated against that policy.
```rust
let json = r#"{
        "statements": [
            {
                "effect": "allow",
                "identities": [
                    "actor_a"
                ],
                "operations": [
                    "write"
                ],
                "resources": [
                    "resource_1"
                ]
            }
        ]
    }"#;

// Construct the policy.
let policy = PolicyBuilder::from_json(json).build()?;

// Prepare request (e.g. from user input).
let request = Request::new("actor_a", "write", "resource_1")?;

// Evaluate the request.
match policy.evaluate(&request)? {
    Decision::Allowed => println!("Allowed"),
    Decision::Denied => {
        panic!("Denied!")
    }
};
```
### Try it
```
cargo run --example json
```

## Variable rules
The following example shows a rule that allows any identity to read/write to it's own resource.
```rust
let json = r#"{
    "statements": [
        {
            "effect": "allow",
            "identities": [
                "{{any}}"
            ],
            "operations": [
                "read",
                "write"
            ],
            "resources": [
                "/home/{{identity}}/"
            ]
        }
    ]
}"#;

// Construct the policy.
let policy = PolicyBuilder::from_json(json)
    // use "starts with" matching for resources.
    .with_matcher(matcher::StartsWith)
    .with_default_decision(Decision::Denied)
    .build()?;

// Prepare request (e.g. from user input).
let request = Request::new("johndoe", "write", "/home/johndoe/my.resource")?;

// Evaluate the request.
match policy.evaluate(&request)? {
    Decision::Allowed => println!("Allowed"),
    Decision::Denied => {
        panic!("Denied!")
    }
};

```
### Try it
```
cargo run --example vars
```

## Rules ordering
Order of rules matter. In case of conflicting rules, the first rule wins. In the example below, we allow `actor_a` write to `resource_1`, and deny write to anything else. Note that any other request will be allowed (default decision).
```rust
let json = r#"{
    "statements": [
        {
            "effect": "allow",
            "identities": [
                "actor_a"
            ],
            "operations": [
                "write"
            ],
            "resources": [
                "resource_1"
            ]
        },
        {
            "effect": "deny",
            "identities": [
                "actor_a"
            ],
            "operations": [
                "write"
            ],
            "resources": [
                "{{any}}"
            ]
        }
    ]
}"#;

// Construct the policy.
let policy = PolicyBuilder::from_json(json)
    // default to Allow all requests.
    .with_default_decision(Decision::Allowed)
    .build()?;

// Prepare request (e.g. from user input).
let request = Request::new("actor_a", "write", "resource_1")?;

// Evaluate specific request.
match policy.evaluate(&request)? {
    Decision::Allowed => println!("allowed write resource_1"),
    Decision::Denied => {
        panic!("Denied!")
    }
};

let request = Request::new("actor_a", "write", "some_other_resource")?;

// Everything else denies.
assert_matches!(policy.evaluate(&request), Ok(Decision::Denied));
```
### Try it
```
cargo run --example order
```

# Customizations
There are several extension points in the library:
- `ResourceMatcher` trait - responsible for performing resource matching logic.
- `Substituter` trait - you can add custom variables that can be substituted.
- `Validator` trait - validates policy definition. If your need custom validation for policy rules.
- Request Context - you can have custom datatype associated with `Request`. Useful with custom `Substituter` or `ResourceMatcher` to implement custom variables or matching logic.

## ResourceMatcher
Custom ResourceMatcher that implements "start with" matching.
```rust
pub struct StartsWith;

impl ResourceMatcher for StartsWith {
    type Context = ();

    fn do_match(&self, _context: &Request<Self::Context>, input: &str, policy: &str) -> bool {
        input.starts_with(policy)
    }
}

```

## Substituter and custom Request Context
Custom Substituter that supports `{{any}}` and `{{role}}` variables. `{{role}}` variable substituted with a value from a request context.
```rust
// custom context
struct MyContext {
    role: String
};

// custom substituter
struct RoleSubstituter;

impl Substituter for RoleSubstituter {
    type Context = MyContext;

    fn visit_resource(&self, value: &str, context: &Request<Self::Context>) -> Result<String> {
        match context.context() {
            Some(role_context) => {
                let mut result = value.to_owned();
                for variable in VariableIter::new(value) {
                    result = match variable {
                        "{{any}}" => replace(&result, variable, context.resource()),
                        "{{role}}" => replace(&result, variable, &role_context.role),
                        _ => result,
                    };
                }
                Ok(result)
            }
            None => Ok(value.to_owned()),
        }
    }

    ...
}
```
### Try it
```
cargo run --example customizations
```

# Roadmap
- [ ] Regex support