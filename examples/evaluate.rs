use allow_me_rs::{
    Decision, DefaultResourceMatcher, DefaultSubstituter, DefaultValidator, PolicyBuilder, Request,
    Result,
};

fn main() -> Result<()> {
    let json = "";

    let policy = PolicyBuilder::from_json(json)
        .with_validator(DefaultValidator)
        .with_matcher(DefaultResourceMatcher)
        .with_substituter(DefaultSubstituter)
        .with_default_decision(Decision::Denied)
        .build()?;

    let request = Request::new("actor_a".into(), "write".into(), "resource_1".into())?;

    let result = policy.evaluate(&request)?;
    println!("Result of policy evaluation: {:?}", result);

    Ok(())
}
