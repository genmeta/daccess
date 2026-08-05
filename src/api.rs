pub mod access;
pub mod contact;
pub mod review;

use std::{future::Future, pin::Pin, sync::Arc};

use axum::{Router, routing::get};
pub use contact::{
    ContactPatch, ContactRecord, GrantedAccess, GrantedMethods, NewContact, RequestedAccess,
};
pub use review::{ReviewRecord, ReviewTarget};

use crate::AccessService;

pub type NotifyError = Box<dyn std::error::Error + Send + Sync>;

pub trait ContactNotifier: Send + Sync {
    fn granted_update<'a>(
        &'a self,
        contact: &'a str,
        modified_since: i64,
        body: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<(), NotifyError>> + Send + 'a>>;
}

#[derive(Clone)]
pub(crate) struct ApiState {
    pub(crate) service: Arc<AccessService>,
    pub(crate) notifier: Option<Arc<dyn ContactNotifier>>,
}

pub fn router(service: Arc<AccessService>) -> Router {
    router_with_notifier(service, None)
}

pub fn router_with_notifier(
    service: Arc<AccessService>,
    notifier: Option<Arc<dyn ContactNotifier>>,
) -> Router {
    Router::new()
        .route("/contacts", get(contact::list).delete(contact::delete_many))
        .route(
            "/contact",
            axum::routing::post(contact::create).patch(contact::apply_granted_update),
        )
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
        .route("/acl/reviews/live", get(review::list_live))
        .route("/acl/reviews/persistent", get(review::list_persistent))
        .with_state(ApiState { service, notifier })
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
    use sea_orm::{ConnectionTrait, Database};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn management_router_exposes_contact_rule_and_review_endpoints() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(include_str!("migrations/0.sql"))
            .await
            .unwrap();
        let app = router(Arc::new(AccessService::new(db, "owner.example")));
        let mut create = http::Request::builder()
            .method(http::Method::POST)
            .uri("/contact")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(r#"{"name":"alice.example","subject_id":"01","description":"Alice","requested_access":{},"offers":{},"created_at":1893455900,"updated_at":1893456000,"expired_after":1893715200}"#))
            .unwrap();
        create.extensions_mut().insert(crate::Visitor::new(
            "alice.example",
            crate::SubjectId::new(b"01".to_vec()).unwrap(),
        ));
        assert_eq!(
            app.clone().oneshot(create).await.unwrap().status(),
            http::StatusCode::CREATED
        );

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
        for uri in ["/acl/reviews/live", "/acl/reviews/persistent"] {
            assert_eq!(
                app.clone()
                    .oneshot(
                        http::Request::builder()
                            .uri(uri)
                            .body(axum::body::Body::empty())
                            .unwrap()
                    )
                    .await
                    .unwrap()
                    .status(),
                http::StatusCode::OK
            );
        }
    }
}
