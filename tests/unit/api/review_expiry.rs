use axum::body::Body;
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::*;
#[tokio::test]
async fn expired_reviews_are_queryable_and_only_expired_pending_records_can_be_deleted() {
    let service = std::sync::Arc::new(
        AccessService::load_from_db(
            "sqlite::memory:",
            "owner.example",
            &crate::SubjectId::new(b"owner".to_vec()).unwrap(),
        )
        .await
        .unwrap(),
    );
    let time = Utc::now().timestamp();
    service.database().execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            "INSERT INTO access_reviews(id,request_id,visitor,visitor_sid,method,api,stage,reason,expired_after,created_at,updated_at) VALUES(1,'expired','alice',?,'GET','/private',3,'expired',?,?,?),(2,'pending','alice',?,'GET','/private',0,'pending',?,?,?),(3,'decided','alice',?,'GET','/private',1,'decided',?,?,?)",
            vec![b"alice".to_vec().into(),(time-1).into(),(time-30).into(),(time-30).into(),b"alice".to_vec().into(),(time+30).into(),time.into(),time.into(),b"alice".to_vec().into(),(time-1).into(),(time-30).into(),(time-30).into()])).await.unwrap();
    let app = crate::api::router(service);
    let response = app
        .clone()
        .oneshot(
            http::Request::builder()
                .uri("/std/acl/review/list?status=expired")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let value: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(value["total"], 1);
    assert_eq!(value["items"][0]["id"], 1);
    assert_eq!(value["items"][0]["requested_at"], time - 30);
    for (id, status) in [(2, 404), (3, 404), (1, 204), (1, 404)] {
        assert_eq!(
            app.clone()
                .oneshot(
                    http::Request::builder()
                        .method("DELETE")
                        .uri(format!("/std/acl/review?id={id}"))
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            status
        );
    }
    assert_eq!(
        app.oneshot(
            http::Request::builder()
                .uri("/std/acl/review/list?status=other")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        400
    );
}
