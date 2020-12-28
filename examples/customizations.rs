use allow_me::{
    Decision, PolicyBuilder, Request, ResourceMatcher, Result, Substituter, VariableIter,
};

fn main() -> Result<()> {
    let json = r#"{
        "statements": [
            {
                "effect": "allow",
                "identities": [
                    "johndoe"
                ],
                "operations": [
                    "write"
                ],
                "resources": [
                    "/shared/{{role}}/"
                ]
            }
        ]
    }"#;

    // Construct the policy.
    let policy = PolicyBuilder::from_json(json)
        .with_matcher(StartsWith)
        .with_substituter(RoleSubstituter)
        .build()?;

    // Prepare request (e.g. from user input).
    let context = MyContext {
        role: "reviewer".into(),
    };
    let request = Request::with_context("johndoe", "write", "/shared/reviewer/notes.txt", context)?;

    // Evaluate the request.
    match policy.evaluate(&request)? {
        Decision::Allowed => println!("Allowed"),
        Decision::Denied => {
            panic!("Denied!")
        }
    };

    Ok(())
}

// custom request context
struct MyContext {
    role: String,
}

// custom ResourceMatcher that implements "start with" matching.
struct StartsWith;

impl ResourceMatcher for StartsWith {
    type Context = MyContext;

    fn do_match(&self, _context: &Request<Self::Context>, input: &str, policy: &str) -> bool {
        input.starts_with(policy)
    }
}

// custom Substituter that supports {{any}} and {{role}} variables.
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

    // skipping the rest of the implementation...
    fn visit_identity(&self, value: &str, _context: &Request<Self::Context>) -> Result<String> {
        Ok(value.to_owned())
    }

    fn visit_operation(&self, value: &str, _context: &Request<Self::Context>) -> Result<String> {
        Ok(value.to_owned())
    }
}

fn replace(value: &str, variable: &str, substitution: &str) -> String {
    value.replace(variable, substitution)
}
