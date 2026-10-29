use std::sync::Arc;

use http_body_util::BodyExt;
use sea_orm::{ConnectionTrait, Database};
use tower::ServiceExt;

use super::*;

async fn service() -> AccessService {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.execute_unprepared(include_str!("../../../src/service/sql/schema.sql"))
        .await
        .unwrap();
    db.execute_unprepared(include_str!(
        "../../../src/service/sql/migrations/v1_add_application_receipts.sql"
    ))
    .await
    .unwrap();
    AccessService::new(db, "owner.example")
}

#[tokio::test]
async fn set_list_update_and_delete_rule_stay_in_sync() {
    let service = service().await;
    let grantee = Grantee::Named;
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/api/",
            Effect::Allow,
            grantee.clone(),
        )
        .await
        .unwrap();
    let rules = service.list_rules_by_api("/api").await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules["GET"].allow, ["**"]);
    assert!(rules["GET"].review.is_empty());
    assert!(rules["GET"].deny.is_empty());
    assert_eq!(
        service
            .policies
            .read()
            .await
            .evaluate(
                &http::Method::GET,
                "/api/item",
                std::slice::from_ref(&grantee)
            )
            .0,
        Effect::Allow
    );
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/api",
            Effect::Review,
            grantee.clone(),
        )
        .await
        .unwrap();
    let rules = service.list_rules_by_api("/api").await.unwrap();
    assert_eq!(rules["GET"].review, ["**"]);
    service
        .remove_policy(
            Method::Specified(http::Method::GET),
            "/api",
            grantee.clone(),
        )
        .await
        .unwrap();
    assert!(service.list_rules_by_api("/api").await.unwrap().is_empty());
    assert_eq!(
        service
            .policies
            .read()
            .await
            .evaluate(&http::Method::GET, "/api", &[grantee])
            .0,
        Effect::Deny
    );
}

#[tokio::test]
async fn invalid_api_does_not_touch_database_or_memory() {
    let service = service().await;
    assert!(
        service
            .set_policy(Method::Unspecified, "relative", Effect::Allow, Grantee::All)
            .await
            .is_err()
    );
    let (total, apis) = service
        .list_apis(0, 20, Sort::UpdatedAt, Order::Desc)
        .await
        .unwrap();
    assert_eq!(total, 0);
    assert!(apis.is_empty());
    assert_eq!(
        service
            .policies
            .read()
            .await
            .evaluate(&http::Method::GET, "/", &[Grantee::All])
            .0,
        Effect::Deny
    );
}

#[tokio::test]
async fn anyone_and_named_rules_remain_mutually_exclusive() {
    let service = service().await;
    service
        .set_policy(Method::Unspecified, "/", Effect::Allow, Grantee::All)
        .await
        .unwrap();
    service
        .set_policy(Method::Unspecified, "/", Effect::Review, Grantee::Named)
        .await
        .unwrap();
    let rules = service.list_rules_by_api("/").await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules["*"].review, ["**"]);
    assert!(rules["*"].allow.is_empty());
    assert!(rules["*"].deny.is_empty());
}

#[tokio::test]
async fn http_lists_apis_by_page_and_one_api_complete_rules() {
    let service = Arc::new(service().await);
    for (api, method) in [
        ("/older", http::Method::GET),
        ("/newer", http::Method::GET),
        ("/newer", http::Method::POST),
    ] {
        service
            .set_policy(
                Method::Specified(method),
                api,
                Effect::Allow,
                Grantee::Named,
            )
            .await
            .unwrap();
    }
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/newer",
            Effect::Review,
            Grantee::Group {
                title: String::from("admin"),
                issuer: String::from("example"),
            },
        )
        .await
        .unwrap();
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/newer",
            Effect::Deny,
            Grantee::Anony,
        )
        .await
        .unwrap();
    service
        .db
        .execute_unprepared(
            "UPDATE access_rules SET updated_at = CASE api WHEN '/older' THEN 1 ELSE 2 END",
        )
        .await
        .unwrap();

    let app = crate::api::router(service);
    let response = app
        .clone()
        .oneshot(
            http::Request::builder()
                .uri("/std/acl/apis?page=1&page_size=1")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["page"], 1);
    assert_eq!(body["page_size"], 1);
    assert_eq!(body["total"], 2);
    assert_eq!(body["items"][0]["api"], "/newer");

    let response = app
        .clone()
        .oneshot(
            http::Request::builder()
                .uri("/std/acl/apis?page=2&page_size=1")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["items"][0]["api"], "/older");

    let response = app
        .clone()
        .oneshot(
            http::Request::builder()
                .uri("/std/acl/apis?page_size=1&sort=api&order=desc")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["items"][0]["api"], "/older");

    let response = app
        .oneshot(
            http::Request::builder()
                .uri("/std/acl/access?api=/newer")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "GET": {
                "allow": ["**"],
                "review": ["admin@example"],
                "deny": ["?"]
            },
            "POST": {
                "allow": ["**"],
                "review": [],
                "deny": []
            }
        })
    );
}

#[tokio::test]
async fn http_lists_all_rules_as_api_method_effect_tree() {
    let service = Arc::new(service().await);
    for (method, effect, grantee) in [
        (
            Method::Specified(http::Method::GET),
            Effect::Allow,
            Grantee::Named,
        ),
        (
            Method::Specified(http::Method::GET),
            Effect::Review,
            Grantee::Group {
                title: String::from("admin"),
                issuer: String::from("example"),
            },
        ),
        (
            Method::Specified(http::Method::GET),
            Effect::Deny,
            Grantee::Anony,
        ),
        (
            Method::Specified(http::Method::POST),
            Effect::Allow,
            Grantee::All,
        ),
    ] {
        service
            .set_policy(method, "/api/2", effect, grantee)
            .await
            .unwrap();
    }

    let app = crate::api::router(service);
    let response = app
        .clone()
        .oneshot(
            http::Request::builder()
                .uri("/std/acl/access")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "/api/2": {
                "GET": {
                    "allow": ["**"],
                    "review": ["admin@example"],
                    "deny": ["?"]
                },
                "POST": {
                    "allow": ["*?"],
                    "review": [],
                    "deny": []
                }
            }
        })
    );

    let response = app
        .oneshot(
            http::Request::builder()
                .uri("/std/acl/access?api=/api/2")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["GET"]["allow"], serde_json::json!(["**"]));
    assert_eq!(body["POST"]["allow"], serde_json::json!(["*?"]));
}

#[tokio::test]
async fn http_lists_all_allow_rules_by_grantee_and_api() {
    let service = Arc::new(service().await);
    service
        .db
        .execute_unprepared(
            "INSERT INTO contacts \
                 (name, subject_id, status, expired_after, updated_at, created_at) \
                 VALUES ('alice.smith~', X'01', 2, 100, 1, 1)",
        )
        .await
        .unwrap();
    for (method, effect) in [
        (http::Method::GET, Effect::Allow),
        (http::Method::POST, Effect::Allow),
        (http::Method::PATCH, Effect::Review),
        (http::Method::DELETE, Effect::Deny),
    ] {
        service
            .set_policy(
                Method::Specified(method),
                "/api/v2",
                effect,
                Grantee::One(String::from("alice.smith~")),
            )
            .await
            .unwrap();
    }

    let response = crate::api::router(service)
        .oneshot(
            http::Request::builder()
                .uri("/std/acl/allow")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "alice.smith~": {
                "/api/v2": {
                    "allow": ["GET", "POST"],
                    "review": ["PATCH"],
                    "deny": ["DELETE"]
                }
            }
        })
    );
}

#[tokio::test]
async fn http_lists_one_contacts_rules_by_api_page() {
    let service = Arc::new(service().await);
    service
        .db
        .execute_unprepared(
            "INSERT INTO contacts \
                 (name, subject_id, status, expired_after, updated_at, created_at) \
                 VALUES ('alice.smith~', X'01', 2, 100, 1, 1)",
        )
        .await
        .unwrap();
    for (api, method, effect) in [
        ("/api/1", http::Method::GET, Effect::Deny),
        ("/api/2", http::Method::GET, Effect::Allow),
        ("/api/2", http::Method::PATCH, Effect::Review),
    ] {
        service
            .set_policy(
                Method::Specified(method),
                api,
                effect,
                Grantee::One(String::from("alice.smith~")),
            )
            .await
            .unwrap();
    }
    service
        .db
        .execute_unprepared(
            "UPDATE access_rules SET updated_at = CASE api WHEN '/api/1' THEN 1 ELSE 2 END",
        )
        .await
        .unwrap();

    let response = crate::api::router(service)
        .oneshot(
            http::Request::builder()
                .uri("/std/acl/allow?name=alice.smith~&page=1&page_size=1")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["total"], 2);
    assert_eq!(body["page"], 1);
    assert_eq!(body["page_size"], 1);
    assert_eq!(
        body["items"],
        serde_json::json!({
            "/api/2": {
                "GET": {
                    "allow": ["alice.smith~"],
                    "review": [],
                    "deny": []
                },
                "PATCH": {
                    "allow": [],
                    "review": ["alice.smith~"],
                    "deny": []
                }
            }
        })
    );
}

#[tokio::test]
async fn management_apis_always_keep_one_named_or_group_administrator() {
    let service = Arc::new(service().await);
    service
        .db
        .execute_unprepared(
            r#"INSERT INTO contacts
                   (name, subject_id, status, expired_after, updated_at, created_at)
                   VALUES ('alice.example', X'01', 2, 100, 1, 1),
                          ('bob.example', X'02', 2, 100, 1, 1)"#,
        )
        .await
        .unwrap();
    let app = crate::api::router(service);
    let rule = |method: http::Method, api: &str, effect: &str, grantee: &str| {
        let (uri, body) = if method == http::Method::POST {
            (
                format!("/std/acl/access?api={api}"),
                format!(r#"{{"method":"GET","effect":"{effect}","grantee":"{grantee}"}}"#),
            )
        } else {
            (
                format!("/std/acl/allow?name={grantee}"),
                format!(r#"{{"method":"GET","api":"{api}","effect":"{effect}"}}"#),
            )
        };
        http::Request::builder()
            .method(method)
            .uri(uri)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body))
            .unwrap()
    };

    assert_eq!(
        app.clone()
            .oneshot(rule(
                http::Method::POST,
                "/business",
                "deny",
                "owner.example",
            ))
            .await
            .unwrap()
            .status(),
        http::StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.clone()
            .oneshot(rule(
                http::Method::POST,
                "/business",
                "allow",
                "bob.example",
            ))
            .await
            .unwrap()
            .status(),
        http::StatusCode::NO_CONTENT
    );
    let delete_business_administrator = http::Request::builder()
        .method(http::Method::DELETE)
        .uri("/std/contact?name=bob.example")
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(delete_business_administrator)
            .await
            .unwrap()
            .status(),
        http::StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.clone()
            .oneshot(rule(
                http::Method::POST,
                "/std/acl",
                "deny",
                "owner.example",
            ))
            .await
            .unwrap()
            .status(),
        http::StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.clone()
            .oneshot(rule(
                http::Method::POST,
                "/std/acl",
                "allow",
                "alice.example",
            ))
            .await
            .unwrap()
            .status(),
        http::StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.clone()
            .oneshot(rule(
                http::Method::POST,
                "/std/acl",
                "deny",
                "owner.example",
            ))
            .await
            .unwrap()
            .status(),
        http::StatusCode::NO_CONTENT
    );

    let delete = http::Request::builder()
        .method(http::Method::DELETE)
        .uri("/std/acl/allow?name=alice.example")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            r#"{"method":"GET","api":"/std/acl"}"#,
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(delete).await.unwrap().status(),
        http::StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.clone()
            .oneshot(rule(
                http::Method::PATCH,
                "/std/acl",
                "review",
                "alice.example",
            ))
            .await
            .unwrap()
            .status(),
        http::StatusCode::BAD_REQUEST
    );
    let delete_contact = http::Request::builder()
        .method(http::Method::DELETE)
        .uri("/std/contact?name=alice.example")
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(delete_contact).await.unwrap().status(),
        http::StatusCode::BAD_REQUEST
    );

    assert_eq!(
        app.clone()
            .oneshot(rule(
                http::Method::POST,
                "/std/acl",
                "allow",
                "admin@example",
            ))
            .await
            .unwrap()
            .status(),
        http::StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.clone()
            .oneshot(rule(
                http::Method::PATCH,
                "/std/acl",
                "review",
                "alice.example",
            ))
            .await
            .unwrap()
            .status(),
        http::StatusCode::NO_CONTENT
    );

    let delete_group = http::Request::builder()
        .method(http::Method::DELETE)
        .uri("/std/acl/allow?name=admin%40example")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            r#"{"method":"GET","api":"/std/acl"}"#,
        ))
        .unwrap();
    assert_eq!(
        app.oneshot(delete_group).await.unwrap().status(),
        http::StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn concurrent_changes_cannot_remove_every_management_api_administrator() {
    let service = service().await;
    let method = Method::Specified(http::Method::GET);
    service
        .db
        .execute_unprepared(
            r#"INSERT INTO contacts
                   (name, subject_id, status, expired_after, updated_at, created_at)
                   VALUES ('alice.example', X'01', 2, 100, 1, 1),
                          ('bob.example', X'02', 2, 100, 1, 1)"#,
        )
        .await
        .unwrap();
    for name in ["alice.example", "bob.example"] {
        service
            .set_policy(
                method.clone(),
                "/std/acl",
                Effect::Allow,
                Grantee::One(name.into()),
            )
            .await
            .unwrap();
    }
    service
        .set_policy(
            method.clone(),
            "/std/acl",
            Effect::Deny,
            Grantee::One("owner.example".into()),
        )
        .await
        .unwrap();

    let (alice, bob) = tokio::join!(
        service.remove_policy(
            method.clone(),
            "/std/acl",
            Grantee::One("alice.example".into()),
        ),
        service.remove_policy(method, "/std/acl", Grantee::One("bob.example".into()),),
    );

    assert_ne!(alice.is_ok(), bob.is_ok());
    let administrators = service
            .db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS count FROM access_rules WHERE method = 'GET' AND api = '/std/acl' AND effect = 'allow' AND grantee_type IN (0, 1)",
            ))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(i64::try_get(&administrators, "", "count").unwrap(), 1);
}
