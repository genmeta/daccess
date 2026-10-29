use std::sync::Arc;

use sea_orm::{ConnectionTrait, Database};
use tower::ServiceExt;

use super::*;
use crate::SubjectId;

async fn service() -> AccessService {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.execute_unprepared(include_str!("../../../src/migrations/0.sql"))
        .await
        .unwrap();
    AccessService::migrate(&db).await.unwrap();
    AccessService::new(db, "owner.example")
}

#[tokio::test]
async fn lists_and_decides_a_persistent_review() {
    let service = service().await;
    service.db.execute_unprepared("INSERT INTO access_reviews (request_id, visitor, visitor_sid, method, api, stage, reason, expired_after, updated_at, created_at) VALUES ('r1', 'alice.example', X'01', 'GET', '/api', 0, 'review', 4070995200, 4070908800, 4070908800)").await.unwrap();
    let (total, reviews) = service.pending_persistent_reviews(0, 20).await.unwrap();
    assert_eq!(total, 1);
    let id = match &reviews[0] {
        ReviewRecord::Persistent { id, .. } => *id,
    };
    service
        .decide_review(id, Action::Allow, true)
        .await
        .unwrap();
    assert_eq!(
        service.pending_persistent_reviews(0, 20).await.unwrap().0,
        0
    );
}

#[tokio::test]
async fn status_is_scoped_to_the_original_visitor_identity() {
    let service = Arc::new(service().await);
    service.db.execute_unprepared("INSERT INTO access_reviews (request_id, visitor, visitor_sid, method, api, stage, reason, expired_after, updated_at, created_at) VALUES ('r1', 'alice.example', X'01', 'GET', '/api', 1, 'review', 4070995200, 4070908800, 4070908800)").await.unwrap();
    let app = crate::api::router(service.clone());
    let request = http::Request::builder()
        .uri("/std/acl/status?id=1")
        .body(axum::body::Body::empty())
        .unwrap();
    let denied = app.clone().oneshot(request).await.unwrap();
    assert_eq!(denied.status(), http::StatusCode::FORBIDDEN);

    let mut request = http::Request::builder()
        .uri("/std/acl/status?id=1")
        .body(axum::body::Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(Visitor::new("alice.example", SubjectId::new([1]).unwrap()));
    let allowed = app.oneshot(request).await.unwrap();
    assert_eq!(allowed.status(), http::StatusCode::OK);
}
