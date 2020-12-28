use assert_matches::assert_matches;

use allow_me::{Decision, PolicyBuilder, Request, Result};

fn main() -> Result<()> {
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

    Ok(())
}
