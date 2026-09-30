pub mod access;
pub mod contact;
pub mod review;

use std::sync::Arc;

use axum::{Router, routing::get};
pub use contact::{
    ContactPatch, ContactRecord, GrantedAccess, GrantedMethods, NewContact, RequestedAccess,
};
pub use review::ReviewRecord;

use crate::AccessService;

#[derive(Clone)]
pub(crate) struct ApiState {
    pub(crate) service: Arc<AccessService>,
}

pub fn router(service: Arc<AccessService>) -> Router {
    Router::new()
        .route("/contacts", get(contact::list).delete(contact::delete_many))
        .route("/contact", axum::routing::post(contact::create))
        .route("/contact/self", get(contact::self_status))
        .route(
            "/contact/{name}",
            get(contact::get)
                .patch(contact::patch)
                .delete(contact::delete),
        )
        .route("/acl/access", get(access::list_all_rules_by_api))
        .route(
            "/acl/access/{*api}",
            get(access::list_rules_by_api).post(access::set_by_api),
        )
        .route("/acl/apis", get(access::list_apis))
        .route("/acl/allow", get(access::list_all_rules_by_name))
        .route(
            "/acl/allow/{name}",
            get(access::list_rules_by_name)
                .patch(access::set_by_name)
                .delete(access::delete_by_name),
        )
        .route("/acl/review", axum::routing::patch(review::decide))
        .route("/acl/reviews", get(review::list_persistent))
        .route("/acl/review/{id}/status", get(review::status))
        .with_state(ApiState { service })
}

/// The caller-owned contact status endpoint is authorized by its verified
/// visitor identity in the handler, rather than ordinary application rules.
pub fn is_contact_status_path(method: &http::Method, path: &str) -> bool {
    method == http::Method::GET && path == "/contact/self"
}

pub(crate) type ApiError = (http::StatusCode, String);

pub(crate) fn internal(error: impl std::fmt::Display) -> ApiError {
    (http::StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

pub(crate) fn bad_request(error: impl std::fmt::Display) -> ApiError {
    (http::StatusCode::BAD_REQUEST, error.to_string())
}

pub(crate) fn database(error: sea_orm::DbErr) -> ApiError {
    let status = if matches!(
        error.sql_err(),
        Some(sea_orm::SqlErr::UniqueConstraintViolation(_))
    ) {
        http::StatusCode::CONFLICT
    } else {
        match error {
            sea_orm::DbErr::RecordNotFound(_) => http::StatusCode::NOT_FOUND,
            sea_orm::DbErr::RecordNotUpdated => http::StatusCode::CONFLICT,
            sea_orm::DbErr::Type(_) => http::StatusCode::BAD_REQUEST,
            _ => http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    };
    (status, error.to_string())
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;
    use radix_trie::TrieCommon;
    use sea_orm::{ConnectionTrait, Database};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn management_router_exposes_contact_rule_and_review_endpoints() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(include_str!("migrations/0.sql"))
            .await
            .unwrap();
        db.execute_unprepared(include_str!("migrations/1.sql"))
            .await
            .unwrap();
        let service = Arc::new(AccessService::new(db, "owner.example"));
        service.contacts.write().await.insert(
            String::from("owner.example"),
            crate::SubjectId::new(b"owner-subject".to_vec()).unwrap(),
        );
        let app = router(service);
        let mut create = http::Request::builder()
            .method(http::Method::POST)
            .uri("/contact")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(r#"{"application_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","description":"Alice","requested_access":{},"offers":{}}"#))
            .unwrap();
        create.extensions_mut().insert(crate::Visitor::new(
            "alice.example",
            crate::SubjectId::new(b"01".to_vec()).unwrap(),
        ));
        let created = app.clone().oneshot(create).await.unwrap();
        assert_eq!(created.status(), http::StatusCode::CREATED);
        let receipt: serde_json::Value =
            serde_json::from_slice(&created.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(receipt["status"], "active");

        let response = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri("/contacts")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("alice.example")
        );
        assert_eq!(
            app.clone()
                .oneshot(
                    http::Request::builder()
                        .uri("/acl/access")
                        .body(axum::body::Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            http::StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(
                    http::Request::builder()
                        .uri("/acl/reviews")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status(),
            http::StatusCode::OK
        );
    }
}
