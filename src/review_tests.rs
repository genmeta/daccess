use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

use crate::{
    AccessService, Action, AuthResult, Effect, Grantee, Headers, Method, ReviewStatus, SubjectId,
};

fn headers(path: &str) -> Headers {
    Headers {
        method: http::Method::PUT,
        path: path.into(),
        fields: http::HeaderMap::new(),
    }
}

async fn service() -> AccessService {
    let service = AccessService::load_from_db(
        "sqlite::memory:",
        "owner.example",
        &SubjectId::new(b"owner").unwrap(),
    )
    .await
    .unwrap();
    service
        .set_policy(
            Method::Specified(http::Method::PUT),
            "/std",
            Effect::Review,
            Grantee::Named,
        )
        .await
        .unwrap();
    service
}

async fn pending(service: &AccessService, subject: &SubjectId) -> i64 {
    match service
        .auth(
            headers("/std/message"),
            Some("alice.example"),
            Some(subject),
        )
        .await
        .unwrap()
    {
        AuthResult::Reviewing(review) => review.id(),
        other => panic!("expected review, got {other:?}"),
    }
}

async fn rule_count(service: &AccessService) -> i64 {
    service
        .database()
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT count(*) AS n FROM access_rules".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "n")
        .unwrap()
}

#[tokio::test]
async fn once_is_scoped_to_identity_method_and_path_without_comparing_query_or_body() {
    let service = service().await;
    let subject = SubjectId::new(b"alice").unwrap();
    let rules = rule_count(&service).await;
    let id = pending(&service, &subject).await;
    service
        .decide_review(id, Action::Allow, false)
        .await
        .unwrap();
    service
        .decide_review(id, Action::Allow, false)
        .await
        .unwrap();
    assert_eq!(
        service
            .review_status(id, "alice.example", &subject)
            .await
            .unwrap(),
        ReviewStatus::Allowed
    );
    let other = SubjectId::new(b"other").unwrap();
    assert!(matches!(
        service
            .auth(headers("/std/message"), Some("alice.example"), Some(&other))
            .await
            .unwrap(),
        AuthResult::Reviewing(_)
    ));
    assert!(matches!(
        service
            .auth(
                headers("/std/message/child"),
                Some("alice.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Reviewing(_)
    ));
    let mut wrong_method = headers("/std/message");
    wrong_method.method = http::Method::GET;
    assert!(matches!(
        service
            .auth(wrong_method, Some("alice.example"), Some(&subject))
            .await
            .unwrap(),
        AuthResult::Denied
    ));
    assert!(matches!(
        service
            .auth(
                headers("/std/message/?different=query"),
                Some("alice.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Allowed
    ));
    assert_eq!(
        service
            .review_status(id, "alice.example", &subject)
            .await
            .unwrap(),
        ReviewStatus::Consumed
    );
    let next = pending(&service, &subject).await;
    assert_ne!(id, next);
    assert_eq!(
        service
            .review_status(id, "alice.example", &subject)
            .await
            .unwrap(),
        ReviewStatus::Consumed
    );
    assert_eq!(rule_count(&service).await, rules);
}

#[tokio::test]
async fn concurrent_calls_can_only_consume_one_allowance() {
    let service = service().await;
    let subject = SubjectId::new(b"alice").unwrap();
    let id = pending(&service, &subject).await;
    service
        .decide_review(id, Action::Allow, false)
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        service.auth(
            headers("/std/message"),
            Some("alice.example"),
            Some(&subject)
        ),
        service.auth(
            headers("/std/message"),
            Some("alice.example"),
            Some(&subject)
        ),
    );
    let results = [first.unwrap(), second.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, AuthResult::Allowed))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, AuthResult::Reviewing(_)))
            .count(),
        1
    );
}

#[tokio::test]
async fn denying_once_keeps_the_old_result_and_allows_a_new_round() {
    let service = service().await;
    let subject = SubjectId::new(b"alice").unwrap();
    let rules = rule_count(&service).await;
    let id = pending(&service, &subject).await;
    service
        .decide_review(id, Action::Deny, false)
        .await
        .unwrap();
    assert_ne!(pending(&service, &subject).await, id);
    assert_eq!(
        service
            .review_status(id, "alice.example", &subject)
            .await
            .unwrap(),
        ReviewStatus::Denied
    );
    assert_eq!(rule_count(&service).await, rules);
    assert!(
        service
            .decide_review(id, Action::Allow, true)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_live_once_decision_releases_only_the_selected_waiter() {
    let service = service().await;
    let subject = SubjectId::new(b"alice").unwrap();
    let mut request = headers("/std/message");
    request
        .fields
        .insert("if-reviewed", "waiting".parse().unwrap());
    let AuthResult::Waiting(first) = service
        .auth(request.clone(), Some("alice.example"), Some(&subject))
        .await
        .unwrap()
    else {
        panic!("expected waiter")
    };
    let AuthResult::Waiting(second) = service
        .auth(request, Some("alice.example"), Some(&subject))
        .await
        .unwrap()
    else {
        panic!("expected waiter")
    };
    let live = service.reviews.pending();
    service
        .decide_live_review(live[0].id, Action::Allow, false)
        .await
        .unwrap();
    assert_eq!(first.await.unwrap(), Action::Allow);
    assert_eq!(service.reviews.pending().len(), 1);
    drop(second);
    assert!(service.reviews.pending().is_empty());
    assert!(matches!(
        service
            .auth(
                headers("/std/message"),
                Some("alice.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Reviewing(_)
    ));
}

#[tokio::test]
async fn policy_edits_and_expiry_revoke_unused_allowances() {
    let service = service().await;
    let subject = SubjectId::new(b"alice").unwrap();
    let id = pending(&service, &subject).await;
    service
        .decide_review(id, Action::Allow, false)
        .await
        .unwrap();
    service
        .database()
        .execute_unprepared("UPDATE access_reviews SET grant_expires_at=1 WHERE remember=0")
        .await
        .unwrap();
    assert_eq!(
        service
            .review_status(id, "alice.example", &subject)
            .await
            .unwrap(),
        ReviewStatus::Expired
    );
    let id = pending(&service, &subject).await;
    service
        .decide_review(id, Action::Allow, false)
        .await
        .unwrap();
    service
        .set_policy(
            Method::Specified(http::Method::PUT),
            "/std",
            Effect::Deny,
            Grantee::Named,
        )
        .await
        .unwrap();
    assert_eq!(
        service
            .review_status(id, "alice.example", &subject)
            .await
            .unwrap(),
        ReviewStatus::Expired
    );
    assert!(matches!(
        service
            .auth(
                headers("/std/message"),
                Some("alice.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Denied
    ));
}

#[tokio::test]
async fn remembered_decisions_remain_durable_acl_rules() {
    for action in [Action::Allow, Action::Deny] {
        let service = service().await;
        let subject = SubjectId::new(b"alice").unwrap();
        let id = pending(&service, &subject).await;
        service.decide_review(id, action, true).await.unwrap();
        for _ in 0..2 {
            let result = service
                .auth(
                    headers("/std/message"),
                    Some("alice.example"),
                    Some(&subject),
                )
                .await
                .unwrap();
            assert!(matches!(
                (action, result),
                (Action::Allow, AuthResult::Allowed) | (Action::Deny, AuthResult::Denied)
            ));
        }
    }
}

#[tokio::test]
async fn restart_preserves_pending_unused_and_consumed_decisions() {
    let directory = tempfile::tempdir().unwrap();
    let uri = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("access.db").display()
    );
    let owner = SubjectId::new(b"owner").unwrap();
    let subject = SubjectId::new(b"alice").unwrap();
    let service = AccessService::load_from_db(&uri, "owner.example", &owner)
        .await
        .unwrap();
    service
        .set_policy(
            Method::Specified(http::Method::PUT),
            "/std",
            Effect::Review,
            Grantee::Named,
        )
        .await
        .unwrap();
    let id = pending(&service, &subject).await;
    drop(service);
    let service = AccessService::load_from_db(&uri, "owner.example", &owner)
        .await
        .unwrap();
    assert_eq!(pending(&service, &subject).await, id);
    service
        .decide_review(id, Action::Allow, false)
        .await
        .unwrap();
    // Editing an unrelated endpoint must not discard this grant.
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/other",
            Effect::Deny,
            Grantee::Named,
        )
        .await
        .unwrap();
    drop(service);
    let service = AccessService::load_from_db(&uri, "owner.example", &owner)
        .await
        .unwrap();
    assert_eq!(
        service
            .review_status(id, "alice.example", &subject)
            .await
            .unwrap(),
        ReviewStatus::Allowed
    );
    assert!(matches!(
        service
            .auth(
                headers("/std/message"),
                Some("alice.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Allowed
    ));
    drop(service);
    let service = AccessService::load_from_db(&uri, "owner.example", &owner)
        .await
        .unwrap();
    assert_eq!(
        service
            .review_status(id, "alice.example", &subject)
            .await
            .unwrap(),
        ReviewStatus::Consumed
    );
    assert_ne!(pending(&service, &subject).await, id);
}

#[tokio::test]
async fn review_protocol_requires_an_explicit_decision_mode() {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let service = std::sync::Arc::new(service().await);
    let subject = SubjectId::new(b"alice").unwrap();
    let id = pending(&service, &subject).await;
    let app = crate::api::router(service.clone());
    let response = app
        .clone()
        .oneshot(
            http::Request::builder()
                .uri("/std/acl/review/list")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        body["decision_modes"],
        serde_json::json!(["once", "always"])
    );
    let response = app
        .oneshot(
            http::Request::builder()
                .method("PATCH")
                .uri("/std/acl/review")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"id":id,"action":"allow"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
    assert_eq!(
        service
            .review_status(id, "alice.example", &subject)
            .await
            .unwrap(),
        ReviewStatus::Pending
    );
}

#[tokio::test]
async fn migration_preserves_historical_decisions_and_the_id_high_water_mark() {
    let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
    for sql in [
        include_str!("migrations/0.sql"),
        include_str!("migrations/1.sql"),
        include_str!("migrations/2.sql"),
    ] {
        db.execute_unprepared(sql).await.unwrap();
    }
    db.execute_unprepared("UPDATE module SET version=2; INSERT INTO access_reviews(id,request_id,visitor,visitor_sid,method,api,stage,reason,expired_after,updated_at,created_at) VALUES(1,'historical','alice.example',X'616c696365','PUT','/std/message',1,'review',2000000000,2,1),(100,'deleted','alice.example',X'616c696365','PUT','/other',0,'review',2000000000,2,1); DELETE FROM access_reviews WHERE id=100;").await.unwrap();
    AccessService::migrate(&db).await.unwrap();
    AccessService::migrate(&db).await.unwrap();
    let service = AccessService::new(db, "owner.example");
    let subject = SubjectId::new(b"alice").unwrap();
    assert_eq!(
        service
            .review_status(1, "alice.example", &subject)
            .await
            .unwrap(),
        ReviewStatus::Allowed
    );
    service
        .set_policy(
            Method::Specified(http::Method::PUT),
            "/std",
            Effect::Review,
            Grantee::Named,
        )
        .await
        .unwrap();
    assert!(pending(&service, &subject).await > 100);
    let historical = service
        .database()
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT remember,grant_expires_at FROM access_reviews WHERE id=1",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(historical.try_get::<i64>("", "remember").unwrap(), 1);
    assert_eq!(
        historical
            .try_get::<Option<i64>>("", "grant_expires_at")
            .unwrap(),
        None
    );
}
