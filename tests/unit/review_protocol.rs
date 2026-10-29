use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use tower::ServiceExt;

use super::*;
use crate::{AccessService, AuthResult, Effect, Grantee, Method};

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
            Method::Specified(http::Method::POST),
            "/deploy",
            Effect::Review,
            Grantee::Named,
        )
        .await
        .unwrap();
    service
}

fn headers(mode: &str) -> Headers {
    let mut fields = http::HeaderMap::new();
    fields.insert("if-reviewed", mode.parse().unwrap());
    Headers {
        method: http::Method::POST,
        path: "/deploy?version=1".into(),
        fields,
    }
}

#[tokio::test]
async fn waiting_is_memory_only_until_approval_saves_acl_and_releases_matching_requests() {
    let service = std::sync::Arc::new(service().await);
    let subject = SubjectId::new(b"alice").unwrap();
    let AuthResult::Waiting(first) = service
        .auth(headers("waiting"), Some("alice.example"), Some(&subject))
        .await
        .unwrap()
    else {
        panic!("expected live review")
    };
    let AuthResult::Waiting(second) = service
        .auth(headers("waiting"), Some("alice.example"), Some(&subject))
        .await
        .unwrap()
    else {
        panic!("expected live review")
    };
    assert_eq!(
        service.pending_persistent_reviews(0, 10).await.unwrap().0,
        0
    );
    let live = service.reviews.pending();
    assert_eq!(live.len(), 2);
    let app = crate::management_router(service.clone());
    let decide = |id| {
        http::Request::builder()
            .method("PATCH")
            .uri("/std/acl/review")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"kind":"live","id":id,"action":"allow","remember":true})
                    .to_string(),
            ))
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(decide(live[0].id))
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(first.await.unwrap(), Action::Allow);
    assert_eq!(second.await.unwrap(), Action::Allow);
    assert!(matches!(
        service
            .auth(headers("waiting"), Some("alice.example"), Some(&subject))
            .await
            .unwrap(),
        AuthResult::Allowed
    ));
    assert_eq!(app.oneshot(decide(live[0].id)).await.unwrap().status(), 404);
    let AuthResult::Waiting(cancelled) = service
        .auth(
            headers("waiting"),
            Some("bob.example"),
            Some(&SubjectId::new(b"bob").unwrap()),
        )
        .await
        .unwrap()
    else {
        panic!("expected live review")
    };
    drop(cancelled);
    assert!(service.reviews.pending().is_empty());
    let count = service
        .database()
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT count(*) AS n FROM access_reviews",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(count.try_get::<i64>("", "n").unwrap(), 0);
}

#[tokio::test]
async fn break_deduplicates_metadata_changes_and_approval_writes_durable_acl() {
    let service = service().await;
    let subject = SubjectId::new(b"alice").unwrap();
    let AuthResult::Reviewing(review) = service
        .auth(headers("break"), Some("alice.example"), Some(&subject))
        .await
        .unwrap()
    else {
        panic!("expected persistent review")
    };
    let mut retry = headers("break");
    retry.fields.insert("x-trace", "different".parse().unwrap());
    retry.path = "/deploy?version=2".into();
    assert!(
        matches!(service.auth(retry.clone(), Some("alice.example"), Some(&subject)).await.unwrap(), AuthResult::Reviewing(other) if review.id() == other.id())
    );
    service
        .decide_review(review.id(), Action::Allow, true)
        .await
        .unwrap();
    assert!(matches!(
        service
            .auth(retry.clone(), Some("alice.example"), Some(&subject))
            .await
            .unwrap(),
        AuthResult::Allowed
    ));
    assert!(matches!(
        service
            .auth(retry, Some("alice.example"), Some(&subject))
            .await
            .unwrap(),
        AuthResult::Allowed
    ));
    assert!(service.reviews.pending().is_empty());
}

#[tokio::test]
async fn invalid_mode_and_anonymous_reviews_never_create_requests() {
    let service = service().await;
    assert!(
        service
            .auth(
                headers("other"),
                Some("alice.example"),
                Some(&SubjectId::new(b"alice").unwrap())
            )
            .await
            .is_err()
    );
    for mode in ["waiting", "break"] {
        assert!(matches!(
            service.auth(headers(mode), None, None).await.unwrap(),
            AuthResult::Denied
        ));
    }
    assert!(service.reviews.pending().is_empty());
    assert_eq!(
        service.pending_persistent_reviews(0, 10).await.unwrap().0,
        0
    );
}
