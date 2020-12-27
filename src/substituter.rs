use crate::{Error, Request};

/// Trait to extend `Policy` variable rules resolution.
pub trait Substituter {
    /// The type of the context associated with the request.
    type Context;

    /// This method is called by `Policy` on every `Request` for every variable identity rule.
    fn visit_identity(
        &self,
        value: &str,
        context: &Request<Self::Context>,
    ) -> Result<String, Error>;

    /// This method is called by `Policy` on every `Request` for every variable operation rule.
    fn visit_operation(
        &self,
        value: &str,
        context: &Request<Self::Context>,
    ) -> Result<String, Error>;

    /// This method is called by `Policy` on every `Request` for every variable resource rule.
    fn visit_resource(
        &self,
        value: &str,
        context: &Request<Self::Context>,
    ) -> Result<String, Error>;
}

pub(crate) const ANY_VAR: &str = "{{any}}";
pub(crate) const IDENTITY_VAR: &str = "{{identity}}";
pub(crate) const OPERATION_VAR: &str = "{{operation}}";

/// Default implementation of `Substituter`. It supports several useful variables:
/// * `any` - replaced by input value from the Request.
/// * `identity` - replaced by identity value from the Request.
/// * `operation` - replaced by operation value from the Request.
#[derive(Debug)]
pub struct DefaultSubstituter;

impl Substituter for DefaultSubstituter {
    type Context = ();

    fn visit_identity(
        &self,
        value: &str,
        context: &Request<Self::Context>,
    ) -> Result<String, Error> {
        Ok(replace_identity(value, context))
    }

    fn visit_operation(
        &self,
        value: &str,
        context: &Request<Self::Context>,
    ) -> Result<String, Error> {
        Ok(replace_operation(value, context))
    }

    fn visit_resource(
        &self,
        value: &str,
        context: &Request<Self::Context>,
    ) -> Result<String, Error> {
        Ok(replace_resource(value, context))
    }
}

fn replace_identity<RC>(value: &str, context: &Request<RC>) -> String {
    let mut result = value.to_owned();
    for variable in VariableIter::new(value) {
        result = match variable {
            ANY_VAR | IDENTITY_VAR => replace(&result, variable, context.identity()),
            _ => result,
        };
    }
    result
}

fn replace_operation<RC>(value: &str, context: &Request<RC>) -> String {
    let mut result = value.to_owned();
    for variable in VariableIter::new(value) {
        result = match variable {
            ANY_VAR | OPERATION_VAR => replace(&result, variable, context.operation()),
            IDENTITY_VAR => replace(&result, variable, context.identity()),
            _ => result,
        };
    }
    result
}

fn replace_resource<RC>(value: &str, context: &Request<RC>) -> String {
    let mut result = value.to_owned();
    for variable in VariableIter::new(value) {
        result = match variable {
            ANY_VAR => replace(&result, variable, context.resource()),
            IDENTITY_VAR => replace(&result, variable, context.identity()),
            OPERATION_VAR => replace(&result, variable, context.operation()),
            _ => result,
        };
    }
    result
}

fn replace(value: &str, variable: &str, substitution: &str) -> String {
    value.replace(variable, substitution)
}

/// A simple iterator that returns all occurrences
/// of variable substrings like `{{var_name}}` in the
/// provided string value.
#[derive(Debug)]
pub(super) struct VariableIter<'a> {
    value: &'a str,
    index: usize,
}

impl<'a> VariableIter<'a> {
    pub fn new(value: &'a str) -> Self {
        Self { value, index: 0 }
    }
}

impl<'a> Iterator for VariableIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let value = &self.value[self.index..];
        if let Some(start) = value.find("{{") {
            if let Some(end) = value.find("}}") {
                if start < end {
                    self.index = self.index + end + 2;
                    return Some(&value[start..end + 2]);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use test_case::test_case;

    use super::*;

    #[test_case("{{any}}", 
        "some_identity", 
        "some_operation", 
        "some_resource", 
        "some_identity"; 
        "any var substitution")]
    #[test_case("{{identity}}", 
        "some_identity", 
        "some_operation", 
        "some_resource", 
        "some_identity"; 
        "identity var substitution")]
    fn visit_identity_test(
        input: &str,
        identity: &str,
        operation: &str,
        resource: &str,
        expected: &str,
    ) {
        let request = Request::new(identity, operation, resource).unwrap();

        assert_eq!(
            expected,
            DefaultSubstituter.visit_identity(input, &request).unwrap()
        );
    }

    #[test_case("{{any}}", 
        "some_identity", 
        "some_operation", 
        "some_resource", 
        "some_operation"; 
        "any var substitution")]
    #[test_case("{{operation}}", 
        "some_identity", 
        "some_operation", 
        "some_resource", 
        "some_operation"; 
        "operation var substitution")]
    #[test_case("{{identity}}", 
        "some_identity", 
        "some_operation", 
        "some_resource", 
        "some_identity"; 
        "identity var substitution")]
    #[test_case("prefix-{{identity}}-suffix", 
        "some_identity", 
        "some_operation", 
        "some_resource", 
        "prefix-some_identity-suffix"; 
        "contains identity var substitution")]
    #[test_case("prefix-{{identity}}-contains-{{identity}}-suffix", 
        "some_identity", 
        "some_operation", 
        "some_resource", 
        "prefix-some_identity-contains-some_identity-suffix"; 
        "multiple vars substitution")]
    fn visit_operation_test(
        input: &str,
        identity: &str,
        operation: &str,
        resource: &str,
        expected: &str,
    ) {
        let request = Request::new(identity, operation, resource).unwrap();

        assert_eq!(
            expected,
            DefaultSubstituter.visit_operation(input, &request).unwrap()
        );
    }

    #[test_case("{{any}}", 
        "some_identity", 
        "some_operation", 
        "some_resource", 
        "some_resource"; 
        "any var substitution")]
    #[test_case("{{operation}}", 
        "some_identity", 
        "some_operation", 
        "some_resource", 
        "some_operation"; 
        "operation var substitution")]
    #[test_case("{{identity}}", 
        "some_identity", 
        "some_operation", 
        "some_resource", 
        "some_identity"; 
        "identity var substitution")]
    #[test_case("home/{{identity}}/middle/{{operation}}/last", 
        "some_identity", 
        "some_operation", 
        "some_resource", 
        "home/some_identity/middle/some_operation/last"; 
        "contains multiple vars substitution")]
    fn visit_resource_test(
        input: &str,
        identity: &str,
        operation: &str,
        resource: &str,
        expected: &str,
    ) {
        let request = Request::new(identity, operation, resource).unwrap();

        assert_eq!(
            expected,
            DefaultSubstituter.visit_resource(input, &request).unwrap()
        );
    }

    proptest! {
        #[test]
        fn iterator_does_not_crash(value in "[a-z\\{\\}]+") {
            let _ = VariableIter::new(&value).collect::<Vec<_>>();
        }
    }
}
