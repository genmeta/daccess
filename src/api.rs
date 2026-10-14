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
        .route(
            "/std/contacts",
            get(contact::list).delete(contact::delete_many),
        )
        .route("/std/contact", axum::routing::post(contact::create))
        .route("/std/contact/self", get(contact::self_status))
        .route(
            "/std/contact/{name}",
            get(contact::get)
                .put(put_contact)
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
        .route("/std/acl/review/{id}/status", get(review::status))
        .with_state(ApiState { service })
}

// Owner-managed contact resource. Remote application submission and polling
// are deliberately absent: those use the existing visitor-owned endpoints.
async fn put_contact(
    axum::extract::State(state): axum::extract::State<ApiState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    visitor: Option<axum::Extension<crate::Visitor>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<http::StatusCode, ApiError> {
    use crate::{ContactStatus, SubjectId};
    let service = &state.service;
    let visitor = visitor
        .as_ref()
        .ok_or((http::StatusCode::FORBIDDEN, "owner required".into()))?;
    if visitor.name() != service.owner_name
        || service.contacts.read().await.get(visitor.name()) != Some(visitor.subject_id())
    {
        return Err((http::StatusCode::FORBIDDEN, "owner required".into()));
    }
    if name == service.owner_name
        || name.is_empty()
        || name.len() > 253
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
    {
        return Err(bad_request("invalid contact name"));
    }
    let fields = body
        .as_object()
        .ok_or_else(|| bad_request("contact must be an object"))?;
    for key in fields.keys() {
        if ![
            "subject_id",
            "class",
            "description",
            "status",
            "requested_access",
            "offers",
            "expired_after",
        ]
        .contains(&key.as_str())
        {
            return Err(bad_request(format!("unknown contact field: {key}")));
        }
    }
    let subject = body["subject_id"]
        .as_str()
        .ok_or_else(|| bad_request("subject_id is required"))?;
    let subject =
        SubjectId::new(subject.as_bytes()).map_err(|_| bad_request("invalid subject_id"))?;
    let class = fields.get("class").map_or(Ok(""), |v| {
        v.as_str().ok_or_else(|| bad_request("invalid class"))
    })?;
    let description = body["description"]
        .as_str()
        .ok_or_else(|| bad_request("description is required"))?;
    let status = fields
        .get("status")
        .map_or(Ok(ContactStatus::Pending), |v| {
            serde_json::from_value(v.clone()).map_err(bad_request)
        })?;
    if !matches!(status, ContactStatus::Pending | ContactStatus::Active) {
        return Err(bad_request("status must be pending or active"));
    }
    let requested_access: RequestedAccess = serde_json::from_value(
        fields
            .get("requested_access")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
    )
    .map_err(bad_request)?;
    let offers: GrantedAccess = serde_json::from_value(
        fields
            .get("offers")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
    )
    .map_err(bad_request)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(internal)?
        .as_secs();
    let now = i64::try_from(now).map_err(internal)?;
    let existing = match service.find_contact_by_name(&name).await {
        Ok(record) => Some(record),
        Err(sea_orm::DbErr::RecordNotFound(_)) => None,
        Err(error) => return Err(database(error)),
    };
    let expires = fields.get("expired_after").map_or_else(
        || {
            Ok(existing
                .as_ref()
                .map_or(now + 7 * 86_400, |record| record.expired_after))
        },
        |v| {
            v.as_i64()
                .ok_or_else(|| bad_request("invalid expired_after"))
        },
    )?;
    if expires <= now || description.chars().count() > 80 {
        return Err(bad_request("invalid expiry or description"));
    }
    let same = existing.as_ref().is_some_and(|record| {
        record.subject_id == subject
            && record.class == class
            && record.description == description
            && record.requested_access == requested_access
            && record.offers == offers
            && record.expired_after == expires
    });
    if let Some(record) = &existing {
        if !matches!(record.status, 0 | 2 | 3)
            || (record.status == 0 && !same)
            || (record.status == 2 && status != ContactStatus::Active)
        {
            return Err((
                http::StatusCode::CONFLICT,
                "contact cannot be replaced in its current state".into(),
            ));
        }
    }
    if !same {
        service
            .create_contact(NewContact {
                name: name.clone(),
                subject_id: subject,
                class: class.to_owned(),
                description: description.to_owned(),
                requested_access,
                offers,
                created_at: existing.as_ref().map_or(now, |record| record.created_at),
                updated_at: now,
                expired_after: expires,
            })
            .await
            .map_err(database)?;
    }
    // The resource may remain pending if activation fails; an identical retry
    // completes it through the library's existing status transition.
    if status == ContactStatus::Active
        && !existing.as_ref().is_some_and(|record| record.status == 2)
    {
        service
            .patch_contact(
                &name,
                ContactPatch::LocalUpdate {
                    status: Some(status),
                    alias: None,
                },
            )
            .await
            .map_err(database)?;
    }
    Ok(if existing.is_none() {
        http::StatusCode::CREATED
    } else {
        http::StatusCode::NO_CONTENT
    })
}

/// The caller-owned contact status endpoint is authorized by its verified
/// visitor identity in the handler, rather than ordinary application rules.
pub fn is_contact_status_path(method: &http::Method, path: &str) -> bool {
    method == http::Method::GET && path == "/std/contact/self"
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
    async fn contact_put_requires_owner_and_is_retryable_without_granting_access() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        for migration in [
            include_str!("migrations/0.sql"),
            include_str!("migrations/1.sql"),
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
                .uri("/std/contact/alice.example")
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
        for caller in [
            None,
            Some(("alice.example", "alice-subject")),
            Some(("owner.example", "wrong-subject")),
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(request(caller, &payload))
                    .await
                    .unwrap()
                    .status(),
                http::StatusCode::FORBIDDEN
            );
        }
        let caller = Some(("owner.example", "owner-subject"));
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
        assert_eq!(
            service.find_contact_by_name("alice.example").await.unwrap(),
            before
        );
        let listed = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri("/std/contacts")
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
            http::StatusCode::BAD_REQUEST
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
        assert!(is_contact_status_path(
            &http::Method::GET,
            "/std/contact/self"
        ));
        assert!(!is_contact_status_path(&http::Method::GET, "/contact/self"));
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
                    .uri("/std/contacts")
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
