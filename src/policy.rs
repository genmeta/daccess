use std::{collections::HashMap, fmt, str::FromStr};

use radix_trie::{Trie, TrieCommon};
use serde::{Deserialize, Serialize};
use snafu::Snafu;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub enum Effect {
    Allow,
    Deny,
    Review,
}

#[derive(Debug, Eq, PartialEq, Snafu)]
pub enum PolicyError {
    #[snafu(display("invalid access rule effect {effect:?}"))]
    InvalidEffect { effect: String },
    #[snafu(display("unknown access rule method {method:?}: {reason}"))]
    UnknownMethod { method: String, reason: String },
    #[snafu(display("invalid access rule grantee {grantee:?}: {reason}"))]
    InvalidGroup { grantee: String, reason: String },
    #[snafu(display(
        "access rule grantee {grantee:?} has type {actual}, but the database declares type {expected}"
    ))]
    ParseError {
        grantee: String,
        expected: i32,
        actual: i32,
    },
}

impl Effect {
    pub(crate) fn as_str(self) -> &'static str {
        self.into()
    }
}

impl From<Effect> for &'static str {
    fn from(value: Effect) -> Self {
        match value {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
            Effect::Review => "review",
        }
    }
}

impl From<Effect> for String {
    fn from(value: Effect) -> Self {
        String::from(<&'static str>::from(value))
    }
}

impl TryFrom<String> for Effect {
    type Error = PolicyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl FromStr for Effect {
    type Err = PolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "review" => Ok(Self::Review),
            _ => Err(PolicyError::InvalidEffect {
                effect: value.to_owned(),
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub enum Method {
    Specified(http::Method),
    Unspecified,
}

impl Method {
    pub(crate) fn to_string(&self) -> String {
        match self {
            Self::Specified(method) => method.as_str().to_owned(),
            Self::Unspecified => String::from("*"),
        }
    }
}

impl FromStr for Method {
    type Err = PolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "*" {
            return Ok(Self::Unspecified);
        }
        if value.bytes().any(|byte| byte.is_ascii_lowercase()) {
            return Err(PolicyError::UnknownMethod {
                method: value.to_owned(),
                reason: String::from("method must be uppercase"),
            });
        }
        http::Method::from_bytes(value.as_bytes())
            .map(Self::Specified)
            .map_err(|error| PolicyError::UnknownMethod {
                method: value.to_owned(),
                reason: error.to_string(),
            })
    }
}

impl From<Method> for String {
    fn from(value: Method) -> Self {
        value.to_string()
    }
}

impl TryFrom<String> for Method {
    type Error = PolicyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Grantee {
    One(String),
    Group { title: String, issuer: String },
    Named,
    Anony,
    All,
}

impl Grantee {
    pub(crate) fn key(&self) -> i32 {
        match self {
            Self::One(_) => 0,
            Self::Group { .. } => 1,
            Self::Named => 2,
            Self::Anony => 3,
            Self::All => 4,
        }
    }

    pub(crate) fn conflicts(&self) -> Vec<Self> {
        match self {
            Self::All => vec![Self::Named, Self::Anony],
            Self::Named | Self::Anony => vec![Self::All],
            Self::One(_) | Self::Group { .. } => Vec::new(),
        }
    }
}

impl FromStr for Grantee {
    type Err = PolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "**" => Ok(Self::Named),
            "?" => Ok(Self::Anony),
            "*?" => Ok(Self::All),
            _ if value.contains('@') => {
                let (title, issuer) = value.split_once('@').expect("separator was checked");
                if title.is_empty() || issuer.is_empty() {
                    return Err(PolicyError::InvalidGroup {
                        grantee: value.to_owned(),
                        reason: String::from("group title and issuer must not be empty"),
                    });
                }
                Ok(Self::Group {
                    title: title.to_owned(),
                    issuer: issuer.to_owned(),
                })
            }
            _ if !value.is_empty() => Ok(Self::One(value.to_owned())),
            _ => Err(PolicyError::InvalidGroup {
                grantee: value.to_owned(),
                reason: String::from("grantee must not be empty"),
            }),
        }
    }
}

impl TryFrom<(i32, String)> for Grantee {
    type Error = PolicyError;

    fn try_from((kind, value): (i32, String)) -> Result<Self, Self::Error> {
        let grantee = value.parse::<Self>()?;
        if grantee.key() == kind {
            Ok(grantee)
        } else {
            Err(PolicyError::ParseError {
                grantee: value,
                expected: kind,
                actual: grantee.key(),
            })
        }
    }
}

impl fmt::Display for Grantee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::One(name) => f.write_str(name),
            Self::Group { title, issuer } => write!(f, "{title}@{issuer}"),
            Self::Named => f.write_str("**"),
            Self::Anony => f.write_str("?"),
            Self::All => f.write_str("*?"),
        }
    }
}

#[derive(Default)]
pub struct Policies(Trie<String, HashMap<Method, Trie<String, Effect>>>);

impl Policies {
    pub(crate) fn insert(&mut self, method: Method, api: &str, effect: Effect, grantee: Grantee) {
        let api = canonical_api(api);
        if self.0.get(&api).is_none() {
            self.0.insert(api.clone(), HashMap::new());
        }
        self.0
            .get_mut(&api)
            .expect("API policy was just inserted")
            .entry(method)
            .or_default()
            .insert(grantee.to_string(), effect);
    }

    pub fn modify(&mut self, method: Method, api: &str, effect: Effect, grantee: Grantee) {
        let api = canonical_api(api);
        for conflict in grantee.conflicts() {
            self.remove(method.clone(), &api, conflict);
        }
        self.insert(method, &api, effect, grantee);
    }

    pub fn remove(&mut self, method: Method, api: &str, grantee: Grantee) {
        let api = canonical_api(api);
        let Some(methods) = self.0.get_mut(&api) else {
            return;
        };
        let remove_method = match methods.get_mut(&method) {
            Some(grantees) => {
                grantees.remove(&grantee.to_string());
                grantees.is_empty()
            }
            None => false,
        };
        if remove_method {
            methods.remove(&method);
        }
        if methods.is_empty() {
            self.0.remove(&api);
        }
    }

    pub fn evaluate(
        &self,
        method: &http::Method,
        api: &str,
        grantees: &[Grantee],
    ) -> (Effect, Method, String, Grantee) {
        for api in api_ancestors(api) {
            let Some(methods) = self.0.get(&api) else {
                continue;
            };

            for method in [Method::Specified(method.clone()), Method::Unspecified] {
                let Some(index) = methods.get(&method) else {
                    continue;
                };
                for grantee in grantees {
                    if let Some(effect) = index.get(&grantee.to_string()) {
                        return (*effect, method, database_api(&api), grantee.clone());
                    }
                }
            }
        }
        (
            Effect::Deny,
            Method::Unspecified,
            String::from("/"),
            Grantee::All,
        )
    }
}

fn canonical_api(api: &str) -> String {
    let api = database_api(api);
    if api == "/" {
        return api;
    }
    format!("{api}/")
}

pub(crate) fn database_api(api: &str) -> String {
    if api == "/" {
        String::from("/")
    } else {
        api.trim_end_matches('/').to_owned()
    }
}

fn api_ancestors(api: &str) -> Vec<String> {
    let mut api = canonical_api(api);
    let mut ancestors = Vec::new();

    loop {
        ancestors.push(api.clone());
        if api == "/" {
            return ancestors;
        }
        api.pop();
        let parent = api.rfind('/').unwrap_or(0);
        api.truncate(parent + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_values_have_one_canonical_conversion_path() {
        assert_eq!("*".parse(), Ok(Method::Unspecified));
        assert_eq!("GET".parse(), Ok(Method::Specified(http::Method::GET)));
        assert!(matches!(
            "get".parse::<Method>(),
            Err(PolicyError::UnknownMethod { .. })
        ));

        assert_eq!("allow".parse(), Ok(Effect::Allow));
        assert_eq!(<&'static str>::from(Effect::Review), "review");
        assert!(matches!(
            "unknown".parse::<Effect>(),
            Err(PolicyError::InvalidEffect { .. })
        ));

        assert_eq!(
            "alice.example".parse(),
            Ok(Grantee::One("alice.example".into()))
        );
        assert_eq!(
            "student@example.edu".parse(),
            Ok(Grantee::Group {
                title: "student".into(),
                issuer: "example.edu".into(),
            })
        );
        assert_eq!(Grantee::try_from((4, "*?".into())), Ok(Grantee::All));
        assert!(matches!(
            Grantee::try_from((0, "*?".into())),
            Err(PolicyError::ParseError { .. })
        ));
        assert!(matches!(
            "@example.edu".parse::<Grantee>(),
            Err(PolicyError::InvalidGroup { .. })
        ));
    }

    #[test]
    fn falls_back_when_longest_api_has_no_matching_grantee() {
        let mut policies = Policies::default();
        policies.modify(
            Method::Specified(http::Method::GET),
            "/files/private",
            Effect::Deny,
            Grantee::One(String::from("alice.example")),
        );
        policies.modify(
            Method::Specified(http::Method::GET),
            "/files",
            Effect::Allow,
            Grantee::Named,
        );

        assert_eq!(
            policies
                .evaluate(
                    &http::Method::GET,
                    "/files/private/report",
                    &[Grantee::One(String::from("bob.example")), Grantee::Named],
                )
                .0,
            Effect::Allow
        );
    }

    #[test]
    fn observes_path_segment_boundaries() {
        let mut policies = Policies::default();
        policies.modify(Method::Unspecified, "/api/a", Effect::Allow, Grantee::All);

        assert_eq!(
            policies
                .evaluate(&http::Method::GET, "/api/abc", &[Grantee::All])
                .0,
            Effect::Deny
        );
        policies.remove(Method::Unspecified, "/api/a", Grantee::All);
        assert_eq!(
            policies
                .evaluate(&http::Method::GET, "/api/a", &[Grantee::All])
                .0,
            Effect::Deny
        );
    }
}
