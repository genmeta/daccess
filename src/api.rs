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
        .route("/std/contact/application", axum::routing::post(contact::create))
        .route("/std/contact/status", get(contact::self_status))
        .route(
            "/std/contact",
            get(contact::get)
                .put(contact::put)
                .patch(contact::patch)
                .delete(contact::delete),
        )
        .route("/std/acl/access", get(access::list_all_rules_by_api))
        .route(
            "/std/acl/access/{*api}",
            get(access::list_rules_by_api).post(access::set_by_api),
        )
        .route("/std/acl/apis", get(access::list_apis))
        .route("/std/acl/allow", get(access::list_all_rules_by_name))
        .route(
            "/std/acl/allow/{name}",
            get(access::list_rules_by_name)
                .patch(access::set_by_name)
                .delete(access::delete_by_name),
        )
        .route("/std/acl/review", axum::routing::patch(review::decide))
        .route("/std/acl/reviews", get(review::list_persistent))
        .route("/std/acl/review/{id}", axum::routing::delete(
            |axum::extract::State(state): axum::extract::State<ApiState>, axum::extract::Path(id): axum::extract::Path<i64>| async move {
                use sea_orm::ConnectionTrait;
                let result = state.service.database().execute_raw(sea_orm::Statement::from_sql_and_values(sea_orm::DatabaseBackend::Sqlite,
                    "DELETE FROM access_reviews WHERE id=? AND stage=0 AND expired_after<=CAST(strftime('%s','now') AS INTEGER)", [id.into()])).await.map_err(database)?;
                if result.rows_affected()==0 { Err((http::StatusCode::NOT_FOUND,"expired pending review not found".into())) }
                else { Ok(http::StatusCode::NO_CONTENT) }
            }
        ))
        .route("/std/acl/status/{id}", get(review::status))
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
    async fn contact_put_uses_adapter_authorization_and_is_retryable_without_granting_access() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        for migration in [
            include_str!("migrations/0.sql"),
            include_str!("migrations/1.sql"),
            include_str!("migrations/2.sql"),
        ] {
            db.execute_unprepared(migration).await.unwrap();
        }
        let service = Arc::new(AccessService::new(db, "owner.example"));
        let owner_sid = crate::SubjectId::new(b"owner-subject".to_vec()).unwrap();
        service
            .contacts
            .write()
            .await
            .insert("owner.example".into(), owner_sid.clone());
        let app = router(service.clone());
        let payload = serde_json::json!({"subject_id":"alice-subject", "description":"Alice", "status":"active", "offers":{"/private":{"allow":["GET"]}}});
        let request = |caller: Option<(&str, &str)>, value: &serde_json::Value| {
            let mut request = http::Request::builder()
                .method("PUT")
                .uri("/std/contact?name=alice.example")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(value.to_string()))
                .unwrap();
            if let Some((name, subject)) = caller {
                request.extensions_mut().insert(crate::Visitor::new(
                    name,
                    crate::SubjectId::new(subject.as_bytes()).unwrap(),
                ));
            }
            request
        };
        let caller = Some(("manager.example", "manager-subject"));
        assert_eq!(
            app.clone()
                .oneshot(request(caller, &payload))
                .await
                .unwrap()
                .status(),
            http::StatusCode::CREATED
        );
        let before = service.find_contact_by_name("alice.example").await.unwrap();
        assert_eq!(before.status, crate::ContactStatus::Active as i32);
        assert!(before.granted_access.is_empty());
        assert_eq!(
            app.clone()
                .oneshot(request(caller, &payload))
                .await
                .unwrap()
                .status(),
            http::StatusCode::NO_CONTENT
        );
        let after = service.find_contact_by_name("alice.example").await.unwrap();
        assert_eq!(after.subject_id, before.subject_id);
        assert_eq!(after.status, before.status);
        assert_eq!(after.granted_access, before.granted_access);
        let listed = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri("/std/contact/list")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let listed: serde_json::Value =
            serde_json::from_slice(&listed.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert!(listed["items"][0]["id"].as_i64().unwrap() > 0);
        assert_eq!(listed["items"][0]["incoming"], false);
        let mut derived = payload.clone();
        derived["granted_access"] = serde_json::json!({});
        assert_eq!(
            app.clone()
                .oneshot(request(caller, &derived))
                .await
                .unwrap()
                .status(),
            http::StatusCode::UNPROCESSABLE_ENTITY
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
        assert_eq!(
            app.oneshot(request(caller, &payload))
                .await
                .unwrap()
                .status(),
            http::StatusCode::CONFLICT
        );
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
            .uri("/std/contact/application")
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
                        .uri("/std/acl/reviews")
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
