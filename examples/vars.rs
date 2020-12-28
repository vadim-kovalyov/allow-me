use allow_me::{matcher, Decision, PolicyBuilder, Request, Result};

fn main() -> Result<()> {
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

    Ok(())
}
