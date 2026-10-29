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
