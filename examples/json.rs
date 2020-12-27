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
            }
        ]
    }"#;

    let policy = PolicyBuilder::from_json(json)
        .with_default_decision(Decision::Denied)
        .build()?;

    let request = Request::new("actor_a", "write", "resource_1")?;

    match policy.evaluate(&request)? {
        Decision::Allowed => println!("Allowed"),
        Decision::Denied => {
            panic!("Denied!")
        }
    };

    Ok(())
}
