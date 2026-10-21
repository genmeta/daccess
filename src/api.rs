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
        .route("/std/contact/list", get(contact::list))
        .route(
            "/std/contact",
            get(contact::get)
                .post(contact::create)
                .patch(contact::patch)
                .delete(contact::delete),
        )
        .route(
            "/std/acl/access",
            get(access::list_rules_by_api).post(access::set_by_api),
        )
        .route("/std/acl/apis", get(access::list_apis))
        .route(
            "/std/acl/allow",
            get(access::list_rules_by_name)
                .patch(access::set_by_name)
                .delete(access::delete_by_name),
        )
        .route(
            "/std/acl/review",
            axum::routing::patch(review::decide).delete(review::delete),
        )
        .route("/std/acl/review/list", get(review::list_persistent))
        .route("/std/acl/status", get(review::status))
        .with_state(ApiState { service })
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
    async fn outbound_contact_record_is_internal_retryable_and_never_grants_access() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        for migration in [
            include_str!("migrations/0.sql"),
            include_str!("migrations/1.sql"),
            include_str!("migrations/2.sql"),
        ] {
            db.execute_unprepared(migration).await.unwrap();
        }
        let service = Arc::new(AccessService::new(db, "owner.example"));
        let draft = NewContact {
            name: "alice.example".into(),
            subject_id: crate::SubjectId::new(b"alice-subject".to_vec()).unwrap(),
            class: "Human".into(),
            description: "Alice".into(),
            requested_access: Default::default(),
            offers: serde_json::from_value(serde_json::json!({"/private":{"allow":["GET"]}}))
                .unwrap(),
            created_at: 1893455900,
            updated_at: 1893456000,
            expired_after: 1893715200,
        };
        service
            .record_outbound_contact(draft.clone())
            .await
            .unwrap();
        service
            .record_outbound_contact(draft.clone())
            .await
            .unwrap();
        let before = service.find_contact_by_name("alice.example").await.unwrap();
        assert_eq!(before.status, crate::ContactStatus::Pending as i32);
        assert!(before.granted_access.is_empty());
        let mut changed = draft.clone();
        changed.subject_id = crate::SubjectId::new(b"other-subject".to_vec()).unwrap();
        assert!(service.record_outbound_contact(changed).await.is_err());
        service
            .patch_contact(
                "alice.example",
                ContactPatch::LocalUpdate {
                    status: Some(crate::ContactStatus::Active),
                    alias: None,
                },
            )
            .await
            .unwrap();
        service
            .record_outbound_contact(draft.clone())
            .await
            .unwrap();
        assert_eq!(
            service
                .find_contact_by_name("alice.example")
                .await
                .unwrap()
                .status,
            crate::ContactStatus::Active as i32
        );
        service
            .patch_contact(
                "alice.example",
                ContactPatch::LocalUpdate {
                    status: Some(crate::ContactStatus::Blocked),
                    alias: None,
                },
            )
            .await
            .unwrap();
        assert!(
            service
                .record_outbound_contact(draft.clone())
                .await
                .is_err()
        );
        service
            .delete_contacts(&["alice.example".into()])
            .await
            .unwrap();
        let mut stale = draft;
        stale.created_at = 0;
        assert!(service.record_outbound_contact(stale).await.is_err());
        assert!(service.find_contact_by_name("alice.example").await.is_err());
        let response = router(service)
            .oneshot(
                http::Request::builder()
                    .method("PUT")
                    .uri("/std/contact?name=alice.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn query_targets_reject_ambiguous_or_missing_values_and_old_routes_are_removed() {
        let service = Arc::new(
            AccessService::load_from_db(
                "sqlite::memory:",
                "owner.example",
                &crate::SubjectId::new(b"owner").unwrap(),
            )
            .await
            .unwrap(),
        );
        let app = router(service);
        for (method, path, body) in [
            ("GET", "/std/acl/access?api=", ""),
            ("GET", "/std/acl/access?api=std/message", ""),
            ("GET", "/std/acl/access?api=/one&api=/two", ""),
            (
                "POST",
                "/std/acl/access",
                r#"{"method":"GET","effect":"allow","grantee":"**"}"#,
            ),
            ("GET", "/std/acl/allow?name=", ""),
            ("GET", "/std/acl/allow?name=alice&name=bob", ""),
            (
                "PATCH",
                "/std/acl/allow",
                r#"{"api":"/files","method":"GET","effect":"allow"}"#,
            ),
            (
                "DELETE",
                "/std/acl/allow?name=",
                r#"{"api":"/files","method":"GET"}"#,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    http::Request::builder()
                        .method(method)
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                http::StatusCode::BAD_REQUEST,
                "{method} {path}"
            );
        }
        for target in [
            "",
            "?id=",
            "?id=0",
            "?id=-1",
            "?id=abc",
            "?id=9223372036854775808",
            "?id=1&id=2",
        ] {
            for (method, path) in [("GET", "/std/acl/status"), ("DELETE", "/std/acl/review")] {
                let response = app
                    .clone()
                    .oneshot(
                        http::Request::builder()
                            .method(method)
                            .uri(format!("{path}{target}"))
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    http::StatusCode::BAD_REQUEST,
                    "{method} {path}{target}"
                );
            }
        }
        for path in [
            "/std/acl/access/std/message",
            "/std/acl/allow/alice",
            "/std/acl/reviews",
            "/std/acl/status/1",
            "/std/acl/review/1",
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(
                        http::Request::builder()
                            .uri(path)
                            .body(axum::body::Body::empty())
                            .unwrap()
                    )
                    .await
                    .unwrap()
                    .status(),
                http::StatusCode::NOT_FOUND,
                "{path}"
            );
        }
        // All supported Grantee forms survive standard query decoding.
        for name in ["%3F", "*%3F", "**", "editors%40issuer", "alice.smith~"] {
            let response = app
                .clone()
                .oneshot(
                    http::Request::builder()
                        .uri(format!("/std/acl/allow?name={name}"))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), http::StatusCode::OK, "{name}");
        }
    }

    #[tokio::test]
    async fn management_router_exposes_contact_rule_and_review_endpoints() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        for migration in [
            include_str!("migrations/0.sql"),
            include_str!("migrations/1.sql"),
            include_str!("migrations/2.sql"),
        ] {
            db.execute_unprepared(migration).await.unwrap();
        }
        let service = Arc::new(AccessService::new(db, "owner.example"));
        service.contacts.write().await.insert(
            String::from("owner.example"),
            crate::SubjectId::new(b"owner-subject".to_vec()).unwrap(),
        );
        let app = router(service);
        for path in [
            "/contact",
            "/contact/self",
            "/contacts",
            "/acl/access",
            "/acl/reviews",
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(
                        http::Request::builder()
                            .uri(path)
                            .body(axum::body::Body::empty())
                            .unwrap()
                    )
                    .await
                    .unwrap()
                    .status(),
                http::StatusCode::NOT_FOUND,
                "{path}"
            );
        }

        let mut create = http::Request::builder()
            .method(http::Method::POST)
            .uri("/std/contact")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(r#"{"from":"alice.example","to":"owner.example","application_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","description":"Alice","requested_access":{},"offers":{}}"#))
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
        assert_eq!(receipt["status"], "pending");

        let response = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri("/std/contact/list")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let listed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(listed["items"][0]["id"].as_i64().unwrap() > 0);
        assert_eq!(listed["items"][0]["incoming"], true);
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("alice.example")
        );
        assert_eq!(
            app.clone()
                .oneshot(
                    http::Request::builder()
                        .uri("/std/acl/access")
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
                        .uri("/std/acl/review/list")
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
