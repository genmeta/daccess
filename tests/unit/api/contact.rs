use std::sync::Arc;

use http_body_util::BodyExt;
use radix_trie::TrieCommon;
use sea_orm::{ConnectionTrait, Database, TryGetable};
use tower::ServiceExt;

use super::*;

const APPLICATION_CREATED_AT: i64 = 1_893_455_900;
const APPLICATION_UPDATED_AT: i64 = 1_893_456_000;
const APPLICATION_EXPIRED_AFTER: i64 = 1_893_715_200;

async fn service() -> AccessService {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    for migration in [
        include_str!("../../../src/migrations/0.sql"),
        include_str!("../../../src/migrations/1.sql"),
        include_str!("../../../src/migrations/2.sql"),
    ] {
        db.execute_unprepared(migration).await.unwrap();
    }
    let service = AccessService::new(db, "owner.example");
    service.contacts.write().await.insert(
        String::from("owner.example"),
        SubjectId::new(b"owner-subject".to_vec()).unwrap(),
    );
    *service.policies.write().await = AccessService::policies_from_db(&service.db, "owner.example")
        .await
        .unwrap();
    service
}

fn request(method: http::Method, uri: &str, body: &'static str) -> http::Request<axum::body::Body> {
    let reading = method == http::Method::GET && uri.starts_with("/std/contact?");
    let mut request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    if reading {
        request.extensions_mut().insert(crate::Visitor::new(
            "owner.example",
            SubjectId::new(b"owner-subject").unwrap(),
        ));
    }
    request
}

fn as_visitor(
    mut request: http::Request<axum::body::Body>,
    name: &str,
) -> http::Request<axum::body::Body> {
    request.extensions_mut().insert(crate::Visitor::new(
        name,
        SubjectId::new(b"verified-subject".to_vec()).unwrap(),
    ));
    request
}

fn requested(api: &str) -> RequestedAccess {
    [(api.into(), vec![Method::Specified(http::Method::GET)])].into()
}

fn granted(api: &str, effect: Effect) -> GrantedAccess {
    let method = Method::Specified(http::Method::GET);
    let methods = match effect {
        Effect::Allow => GrantedMethods {
            allow: vec![method],
            review: Vec::new(),
            deny: Vec::new(),
        },
        Effect::Review => GrantedMethods {
            allow: Vec::new(),
            review: vec![method],
            deny: Vec::new(),
        },
        Effect::Deny => GrantedMethods {
            allow: Vec::new(),
            review: Vec::new(),
            deny: vec![method],
        },
    };
    [(api.into(), methods)].into()
}

#[test]
fn access_shapes_serialize_as_aggregated_maps() {
    let requested: RequestedAccess = [
        (
            String::from("/api/1"),
            vec![
                Method::Specified(http::Method::GET),
                Method::Specified(http::Method::POST),
            ],
        ),
        (String::from("/api/2"), vec![Method::Unspecified]),
    ]
    .into();
    assert_eq!(
        serde_json::to_value(requested).unwrap(),
        serde_json::json!({"/api/1":["GET","POST"],"/api/2":["*"]})
    );
    let granted: GrantedAccess = [(
        String::from("/api/1"),
        GrantedMethods {
            allow: vec![Method::Specified(http::Method::GET)],
            review: vec![Method::Specified(http::Method::POST)],
            deny: vec![Method::Specified(http::Method::DELETE)],
        },
    )]
    .into();
    assert_eq!(
        serde_json::to_value(granted).unwrap(),
        serde_json::json!({"/api/1":{"allow":["GET"],"review":["POST"],"deny":["DELETE"]}})
    );
}

fn contact() -> NewContact {
    NewContact {
        name: "alice.example".into(),
        subject_id: SubjectId::new([1]).unwrap(),
        class: "human".into(),
        description: "Alice".into(),
        requested_access: requested("/requested"),
        offers: granted("/granted", Effect::Allow),
        created_at: APPLICATION_CREATED_AT,
        updated_at: APPLICATION_UPDATED_AT,
        expired_after: APPLICATION_EXPIRED_AFTER,
    }
}

#[test]
fn contact_subject_id_text_preserves_text_and_binary_bytes() {
    let owner_hash = "abcdef0123456789".repeat(4);
    for text in ["verified-subject", "主体标识", owner_hash.as_str()] {
        let subject_id = SubjectId::new(text.as_bytes()).unwrap();
        assert_eq!(contact_subject_id_text(&subject_id), text);
    }
    for (bytes, expected) in [
        (vec![0xff], "hex:ff"),
        (vec![0xfe], "hex:fe"),
        (vec![0x00, 0x80, 0xff, 0x41], "hex:0080ff41"),
        (b"line\nbreak".to_vec(), "hex:6c696e650a627265616b"),
    ] {
        let subject_id = SubjectId::new(bytes).unwrap();
        assert_eq!(contact_subject_id_text(&subject_id), expected);
    }
}

#[tokio::test]
async fn contact_queries_show_binary_subject_ids_without_changing_storage() {
    let service = Arc::new(service().await);
    let subject_id = SubjectId::new(vec![0x00, 0x80, 0xff, 0x41]).unwrap();
    let mut item = contact();
    item.subject_id = subject_id.clone();
    service.create_contact(item).await.unwrap();
    let app = crate::api::router(service.clone());

    for path in ["/std/contact?name=alice.example", "/std/contact/list"] {
        let response = app
            .clone()
            .oneshot(request(http::Method::GET, path, ""))
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let item = if path == "/std/contact/list" {
            &json["items"][0]
        } else {
            &json
        };
        assert_eq!(item["subject_id"], "hex:0080ff41");
    }

    let stored = service.find_contact_by_name("alice.example").await.unwrap();
    assert_eq!(stored.subject_id, subject_id);
}

#[tokio::test]
async fn create_stores_pending_contact_without_a_callback_rule() {
    let service = service().await;
    service.create_contact(contact()).await.unwrap();

    let stored = service.find_contact_by_name("alice.example").await.unwrap();
    assert_eq!(stored.status, 0);
    assert_eq!(stored.class, "human");
    assert_eq!(stored.description, "Alice");
    assert_eq!(stored.created_at, APPLICATION_CREATED_AT);
    assert_eq!(stored.updated_at, APPLICATION_UPDATED_AT);
    assert_eq!(stored.expired_after, APPLICATION_EXPIRED_AFTER);
    assert_eq!(stored.requested_access, requested("/requested"));
    assert!(stored.granted_access.is_empty());
    assert_eq!(stored.offers, granted("/granted", Effect::Allow));
    let count = service
        .db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) count FROM access_rules WHERE grantee='alice.example'",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(i64::try_get(&count, "", "count").unwrap(), 0);
}

#[tokio::test]
async fn expired_application_has_no_callback_rule() {
    let service = service().await;
    service.create_contact(contact()).await.unwrap();

    assert_eq!(
        service
            .policies
            .read()
            .await
            .evaluate(
                &http::Method::PATCH,
                "/std/contact",
                &[Grantee::One("alice.example".into())]
            )
            .0,
        Effect::Deny
    );
    service
            .db
            .execute_unprepared(
                "UPDATE contacts SET created_at = 1, updated_at = 2, expired_after = 3 WHERE name = 'alice.example'",
            )
            .await
            .unwrap();
    assert_eq!(
        service
            .find_contact_by_name("alice.example")
            .await
            .unwrap()
            .status,
        4
    );
    assert_eq!(
        service
            .policies
            .read()
            .await
            .evaluate(
                &http::Method::PATCH,
                "/std/contact",
                &[Grantee::One("alice.example".into())]
            )
            .0,
        Effect::Deny
    );
}

#[tokio::test]
async fn frozen_contacts_reject_repeated_applications() {
    for status in [0, 4, 5] {
        let service = service().await;
        service.create_contact(contact()).await.unwrap();
        service
            .db
            .execute_unprepared(&format!(
                "UPDATE contacts SET status = {status} WHERE name = 'alice.example'"
            ))
            .await
            .unwrap();
        let mut repeated = contact();
        repeated.description = "must not replace Alice".into();

        assert!(service.create_contact(repeated).await.is_err());
        let stored = service.find_contact_by_name("alice.example").await.unwrap();
        assert_eq!(stored.status, status);
        assert_eq!(stored.description, "Alice");
        assert_eq!(stored.updated_at, APPLICATION_UPDATED_AT);
    }
}

#[tokio::test]
async fn active_and_transfered_contacts_accept_application_updates_without_state_changes() {
    for status in [2, 3] {
        let service = service().await;
        service.create_contact(contact()).await.unwrap();
        service
            .db
            .execute_unprepared(&format!(
                "UPDATE contacts SET status = {status} WHERE name = 'alice.example'"
            ))
            .await
            .unwrap();
        let mut update = contact();
        update.description = "Updated introduction".into();
        update.updated_at += 10;

        service.create_contact(update).await.unwrap();
        let stored = service.find_contact_by_name("alice.example").await.unwrap();
        assert_eq!(stored.status, status);
        assert_eq!(stored.description, "Updated introduction");
        assert_eq!(stored.updated_at, APPLICATION_UPDATED_AT + 10);
    }
}

#[tokio::test]
async fn create_rejects_descriptions_longer_than_eighty_characters() {
    let service = service().await;
    let mut valid = contact();
    valid.description = "介".repeat(80);
    service.create_contact(valid).await.unwrap();

    let mut invalid = contact();
    invalid.name = "too-long.example".into();
    invalid.description = "介".repeat(81);
    assert!(service.create_contact(invalid).await.is_err());

    let mut invalid = contact();
    invalid.name = "invalid.example".into();
    invalid.requested_access = requested("relative");
    assert!(service.create_contact(invalid).await.is_err());
    let contacts = service.contacts.read().await;
    assert_eq!(contacts.len(), 2);
    assert!(contacts.get("owner.example").is_some());
    assert!(contacts.get("alice.example").is_some());
    assert!(contacts.get("too-long.example").is_none());
    assert!(contacts.get("invalid.example").is_none());
}

#[tokio::test]
async fn internal_contact_record_preserves_supplied_timestamps() {
    let service = service().await;
    let mut application = contact();
    application.expired_after = application.updated_at + 60;
    service.create_contact(application).await.unwrap();
    assert_eq!(
        service
            .find_contact_by_name("alice.example")
            .await
            .unwrap()
            .expired_after,
        APPLICATION_UPDATED_AT + 60
    );

    let mut invalid = contact();
    invalid.name = "invalid-time.example".into();
    invalid.expired_after = invalid.updated_at;
    assert!(service.create_contact(invalid).await.is_err());
}

#[tokio::test]
async fn expired_pending_application_is_retained_and_cannot_be_approved() {
    let service = service().await;
    service.create_contact(contact()).await.unwrap();
    service
            .db
            .execute_unprepared(
                "UPDATE contacts SET created_at = 1, updated_at = 2, expired_after = 3 WHERE name = 'alice.example'",
            )
            .await
            .unwrap();

    let stored = service.find_contact_by_name("alice.example").await.unwrap();
    assert_eq!(stored.status, 4);
    assert!(
        service
            .patch_contact(
                "alice.example",
                ContactPatch::LocalUpdate {
                    status: Some(ContactStatus::Active),
                    alias: None,
                },
            )
            .await
            .is_err()
    );
    assert_eq!(
        service
            .find_contact_by_name("alice.example")
            .await
            .unwrap()
            .status,
        4
    );
}

#[tokio::test]
async fn expired_application_rejects_local_approval() {
    let service = Arc::new(service().await);
    service.create_contact(contact()).await.unwrap();
    service
            .db
            .execute_unprepared(
                "UPDATE contacts SET created_at = 1, updated_at = 2, expired_after = 3 WHERE name = 'alice.example'",
            )
            .await
            .unwrap();
    let app = crate::api::router(service.clone());

    let local = as_visitor(
        request(
            http::Method::PATCH,
            "/std/contact?name=alice.example",
            r#"{"status":"active"}"#,
        ),
        "owner.example",
    );
    assert_eq!(
        app.clone().oneshot(local).await.unwrap().status(),
        http::StatusCode::CONFLICT
    );

    let stored = service.find_contact_by_name("alice.example").await.unwrap();
    assert_eq!(stored.status, ContactStatus::Expired as i32);
    assert!(stored.updated_at > 2);
}

#[tokio::test]
async fn blocked_contact_can_be_restored_from_its_local_rule_snapshot() {
    let service = service().await;
    service.create_contact(contact()).await.unwrap();
    service
        .db
        .execute_unprepared("UPDATE contacts SET status = 5 WHERE name = 'alice.example'")
        .await
        .unwrap();

    service
        .patch_contact(
            "alice.example",
            ContactPatch::LocalUpdate {
                status: Some(ContactStatus::Active),
                alias: None,
            },
        )
        .await
        .unwrap();
    let stored = service.find_contact_by_name("alice.example").await.unwrap();
    assert_eq!(stored.status, ContactStatus::Active as i32);
}

#[tokio::test]
async fn self_status_requires_a_matching_verified_visitor() {
    let service = Arc::new(service().await);
    service.create_contact(contact()).await.unwrap();
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/local",
            Effect::Allow,
            Grantee::One("alice.example".into()),
        )
        .await
        .unwrap();
    service
        .patch_contact(
            "alice.example",
            ContactPatch::LocalUpdate {
                status: Some(ContactStatus::Active),
                alias: None,
            },
        )
        .await
        .unwrap();
    let app = crate::api::router(service);

    let mut anonymous = request(http::Method::GET, "/std/contact?name=alice.example", "");
    anonymous.extensions_mut().remove::<crate::Visitor>();
    assert_eq!(
        app.clone().oneshot(anonymous).await.unwrap().status(),
        http::StatusCode::FORBIDDEN
    );

    let mut self_request = request(http::Method::GET, "/std/contact?name=alice.example", "");
    self_request.extensions_mut().insert(crate::Visitor::new(
        "alice.example",
        SubjectId::new(vec![1]).unwrap(),
    ));
    let response = app.clone().oneshot(self_request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["status"], "active");
    assert_eq!(
        body["granted_access"]["/local"]["allow"],
        serde_json::json!(["GET"])
    );

    let mismatch = as_visitor(
        request(http::Method::GET, "/std/contact?name=alice.example", ""),
        "alice.example",
    );
    assert_eq!(
        app.clone().oneshot(mismatch).await.unwrap().status(),
        http::StatusCode::FORBIDDEN
    );

    let missing = as_visitor(
        request(http::Method::GET, "/std/contact?name=mallory.example", ""),
        "mallory.example",
    );
    assert_eq!(
        app.oneshot(missing).await.unwrap().status(),
        http::StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn active_contact_exposes_only_current_local_grants_to_self() {
    for status in [ContactStatus::Pending, ContactStatus::Blocked] {
        let service = service().await;
        service.create_contact(contact()).await.unwrap();
        service
            .db
            .execute_unprepared(&format!(
                "UPDATE contacts SET status = {} WHERE name = 'alice.example'",
                status as i32
            ))
            .await
            .unwrap();
        let app = crate::api::router(Arc::new(service));
        let mut request = request(http::Method::GET, "/std/contact?name=alice.example", "");
        request.extensions_mut().insert(crate::Visitor::new(
            "alice.example",
            SubjectId::new(vec![1]).unwrap(),
        ));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["granted_access"], serde_json::json!({}));
    }
}

#[tokio::test]
async fn local_approval_activates_contact_without_a_callback_rule() {
    let service = service().await;
    service.create_contact(contact()).await.unwrap();
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/local",
            Effect::Review,
            Grantee::One("alice.example".into()),
        )
        .await
        .unwrap();
    service
        .patch_contact(
            "alice.example",
            ContactPatch::LocalUpdate {
                status: Some(ContactStatus::Active),
                alias: None,
            },
        )
        .await
        .unwrap();

    let stored = service.find_contact_by_name("alice.example").await.unwrap();
    assert_eq!(stored.status, ContactStatus::Active as i32);
    assert_eq!(stored.updated_at, APPLICATION_UPDATED_AT);
    assert_eq!(stored.requested_access, requested("/requested"));
    assert!(stored.granted_access.is_empty());
    assert_eq!(stored.offers, granted("/granted", Effect::Allow));
    let rows = service
        .db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT method, api, effect FROM access_rules \
                 WHERE grantee = 'alice.example' ORDER BY api, method",
        ))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(String::try_get(&rows[0], "", "api").unwrap(), "/local");
    assert_eq!(String::try_get(&rows[0], "", "effect").unwrap(), "review");
    assert_eq!(
        service
            .policies
            .read()
            .await
            .evaluate(
                &http::Method::GET,
                "/local",
                &[Grantee::One("alice.example".into())]
            )
            .0,
        Effect::Review
    );
}

#[tokio::test]
async fn self_status_returns_rules_without_replicating_them_into_contact_storage() {
    let service = service().await;
    service.create_contact(contact()).await.unwrap();
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/local",
            Effect::Allow,
            Grantee::One("alice.example".into()),
        )
        .await
        .unwrap();
    service
        .patch_contact(
            "alice.example",
            ContactPatch::LocalUpdate {
                status: Some(ContactStatus::Active),
                alias: None,
            },
        )
        .await
        .unwrap();
    let app = crate::api::router(Arc::new(service));
    let mut request = request(http::Method::GET, "/std/contact?name=alice.example", "");
    request.extensions_mut().insert(crate::Visitor::new(
        "alice.example",
        SubjectId::new(vec![1]).unwrap(),
    ));
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        body["granted_access"]["/local"]["allow"],
        serde_json::json!(["GET"])
    );
}

#[tokio::test]
async fn delete_removes_contact_database_rules_and_memory_rules() {
    let service = service().await;
    service.create_contact(contact()).await.unwrap();
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/local",
            Effect::Allow,
            Grantee::One("alice.example".into()),
        )
        .await
        .unwrap();
    service
        .patch_contact(
            "alice.example",
            ContactPatch::LocalUpdate {
                status: Some(ContactStatus::Active),
                alias: None,
            },
        )
        .await
        .unwrap();
    service
        .delete_contacts(&[String::from("alice.example")])
        .await
        .unwrap();
    assert!(service.find_contact_by_name("alice.example").await.is_err());
    assert!(service.contacts.read().await.get("alice.example").is_none());
    assert_eq!(
        service
            .policies
            .read()
            .await
            .evaluate(
                &http::Method::GET,
                "/local",
                &[Grantee::One("alice.example".into())]
            )
            .0,
        Effect::Deny
    );
    assert!(
        service
            .delete_contacts(&[String::from("alice.example")])
            .await
            .is_err()
    );

    let rules = service
        .db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS count FROM access_rules WHERE grantee = 'alice.example'",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(i64::try_get(&rules, "", "count").unwrap(), 0);

    service.create_contact(contact()).await.unwrap();
    assert_eq!(
        service
            .find_contact_by_name("alice.example")
            .await
            .unwrap()
            .status,
        0
    );
}

#[tokio::test]
async fn http_contact_endpoints_cover_create_list_get_and_batch_delete() {
    let service = Arc::new(service().await);
    let app = crate::api::router(service.clone());
    let owner = as_visitor(
        request(
            http::Method::POST,
            "/std/contact",
            r#"{"from":"owner.example","to":"owner.example","application_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","description":"Owner"}"#,
        ),
        "owner.example",
    );
    assert_eq!(
        app.clone().oneshot(owner).await.unwrap().status(),
        http::StatusCode::BAD_REQUEST
    );
    let create = as_visitor(
        request(
            http::Method::POST,
            "/std/contact",
            r#"{"from":"alice.example","to":"owner.example","application_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","class":"agent","description":"Alice","requested_access":{"/api/messages":["POST"]},"offers":{}}"#,
        ),
        "alice.example",
    );
    assert_eq!(
        app.clone().oneshot(create).await.unwrap().status(),
        http::StatusCode::CREATED
    );
    let retry = as_visitor(
        request(
            http::Method::POST,
            "/std/contact",
            r#"{"from":"alice.example","to":"owner.example","application_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","class":"agent","description":"Alice","requested_access":{"/api/messages":["POST"]},"offers":{}}"#,
        ),
        "alice.example",
    );
    assert_eq!(
        app.clone().oneshot(retry).await.unwrap().status(),
        http::StatusCode::OK
    );
    let status = as_visitor(
        request(http::Method::GET, "/std/contact?name=alice.example", ""),
        "alice.example",
    );
    let status = app.clone().oneshot(status).await.unwrap();
    assert_eq!(status.status(), http::StatusCode::OK);
    let status: serde_json::Value =
        serde_json::from_slice(&status.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(status["name"], "alice.example");
    assert_eq!(status["status"], "pending");
    let duplicate = as_visitor(
        request(
            http::Method::POST,
            "/std/contact",
            r#"{"from":"alice.example","to":"owner.example","application_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","class":"service","description":"Updated Alice","requested_access":{"/api/messages":["POST"]},"offers":{}}"#,
        ),
        "alice.example",
    );
    assert_eq!(
        app.clone().oneshot(duplicate).await.unwrap().status(),
        http::StatusCode::CREATED
    );

    let get = request(http::Method::GET, "/std/contact?name=alice.example", "");
    let response = app.clone().oneshot(get).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["subject_id"], "verified-subject");
    assert_eq!(body["class"], "service");
    assert_eq!(body["description"], "Updated Alice");
    assert_eq!(body["status"], "pending");
    assert_eq!(body["updated_at"], body["created_at"]);
    assert_eq!(
        body["valid_before"].as_i64().unwrap() - body["created_at"].as_i64().unwrap(),
        7 * 86_400
    );

    let list = request(http::Method::GET, "/std/contact/list", "");
    assert_eq!(
        app.clone().oneshot(list).await.unwrap().status(),
        http::StatusCode::OK
    );

    let delete = request(
        http::Method::DELETE,
        "/std/contact",
        r#"{"names":["alice.example"]}"#,
    );
    assert_eq!(
        app.clone().oneshot(delete).await.unwrap().status(),
        http::StatusCode::NO_CONTENT
    );
    assert!(service.find_contact_by_name("alice.example").await.is_err());
    let missing = request(http::Method::GET, "/std/contact?name=alice.example", "");
    assert_eq!(
        app.oneshot(missing).await.unwrap().status(),
        http::StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn new_application_supersedes_pending_receipts_without_replaying_old_payloads() {
    for without_permissions in [false, true] {
        let service = service().await;
        let first_id = "a".repeat(64);
        let next_id = "b".repeat(64);
        let first_hash = "1".repeat(64);
        let next_hash = "2".repeat(64);
        service
            .create_application(contact(), &first_id, &first_hash)
            .await
            .unwrap();
        let mut replacement = contact();
        replacement.description = "Latest introduction".into();
        replacement.created_at += 10;
        replacement.updated_at += 10;
        replacement.expired_after += 10;
        replacement.requested_access = if without_permissions {
            RequestedAccess::new()
        } else {
            requested("/latest")
        };
        replacement.offers = granted("/latest-offer", Effect::Allow);
        let (receipt, created) = service
            .create_application(replacement.clone(), &next_id, &next_hash)
            .await
            .unwrap();
        assert!(created);
        assert_eq!(receipt.status, "pending");
        let latest = service.find_contact_by_name("alice.example").await.unwrap();
        assert_eq!(latest.description, replacement.description);
        assert_eq!(latest.requested_access, replacement.requested_access);
        assert_eq!(latest.offers, replacement.offers);
        assert_eq!(latest.created_at, replacement.created_at);
        assert_eq!(latest.expired_after, replacement.expired_after);
        assert_eq!(latest.status, ContactStatus::Pending as i32);
        let (old, created) = service
            .create_application(contact(), &first_id, &first_hash)
            .await
            .unwrap();
        assert!(!created);
        assert_eq!(old.status, "revoked");
        assert_eq!(
            service.find_contact_by_name("alice.example").await.unwrap(),
            latest
        );
        let (retry, created) = service
            .create_application(replacement.clone(), &next_id, &next_hash)
            .await
            .unwrap();
        assert!(!created);
        assert_eq!(retry.received_at, receipt.received_at);
        assert_eq!(retry.expired_after, receipt.expired_after);
        assert!(
            service
                .create_application(replacement, &next_id, &first_hash)
                .await
                .is_err()
        );
        service
            .patch_contact(
                "alice.example",
                ContactPatch::LocalUpdate {
                    status: Some(ContactStatus::Active),
                    alias: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            service
                .db
                .query_one_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "SELECT status FROM contact_applications WHERE application_id=?",
                    [first_id.into()]
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get::<String>("", "status")
                .unwrap(),
            "revoked"
        );
        assert_eq!(
            service
                .db
                .query_one_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "SELECT status FROM contact_applications WHERE application_id=?",
                    [next_id.into()]
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get::<String>("", "status")
                .unwrap(),
            "active"
        );
    }
}

#[tokio::test]
async fn replacement_application_respects_blocking_and_active_subject_identity() {
    for blocked in [false, true] {
        let service = service().await;
        let mut initial = contact();
        initial.requested_access.clear();
        let first_id = "a".repeat(64);
        let hash = "1".repeat(64);
        service
            .create_application(initial, &first_id, &hash)
            .await
            .unwrap();
        service
            .patch_contact(
                "alice.example",
                ContactPatch::LocalUpdate {
                    status: Some(ContactStatus::Active),
                    alias: None,
                },
            )
            .await
            .unwrap();
        if blocked {
            service
                .patch_contact(
                    "alice.example",
                    ContactPatch::LocalUpdate {
                        status: Some(ContactStatus::Blocked),
                        alias: None,
                    },
                )
                .await
                .unwrap();
        }
        let before = service.find_contact_by_name("alice.example").await.unwrap();
        let mut replacement = contact();
        if !blocked {
            replacement.subject_id = SubjectId::new([2]).unwrap();
        }
        let next_id = "b".repeat(64);
        assert!(
            service
                .create_application(replacement, &next_id, &hash)
                .await
                .is_err()
        );
        assert_eq!(
            service.find_contact_by_name("alice.example").await.unwrap(),
            before
        );
        assert!(
            service
                .db
                .query_one_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "SELECT 1 FROM contact_applications WHERE application_id=?",
                    [next_id.into()]
                ))
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn http_lists_contacts_by_page_and_selected_sort() {
    let service = Arc::new(service().await);
    service
            .db
            .execute_unprepared(
                r#"INSERT INTO contacts
                   (name, subject_id, alias, class, grants, requests, status, expired_after, updated_at, created_at)
                   VALUES
                   ('charlie.example', X'01', 'beta',  'service', '{}', '{}', 2, 100, 30, 5),
                   ('alice.example',   X'02', 'gamma', 'human',   '{}', '{}', 2, 100, 10, 10),
                   ('bob.example',     X'03', 'alpha', 'admin',   '{}', '{}', 2, 100, 20, 20)"#,
            )
            .await
            .unwrap();
    let app = crate::api::router(service);

    for (sort, expected) in [
        ("name", "alice.example"),
        ("names", "alice.example"),
        ("alias", "bob.example"),
        ("updated_at", "alice.example"),
        ("created_at", "charlie.example"),
        ("class", "bob.example"),
    ] {
        let response = app
            .clone()
            .oneshot(request(
                http::Method::GET,
                &format!("/std/contact/list?page=1&page_size=1&sort={sort}&order=asc"),
                "",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["total"], 3);
        assert_eq!(body["page"], 1);
        assert_eq!(body["page_size"], 1);
        assert_eq!(body["items"][0]["name"], expected);
    }

    let second_page = app
        .clone()
        .oneshot(request(
            http::Method::GET,
            "/std/contact/list?page=2&page_size=1&sort=name&order=asc",
            "",
        ))
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&second_page.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(body["items"][0]["name"], "bob.example");

    for uri in [
        "/std/contact/list?page=1&page_size=100&sort=name&order=asc",
        "/std/contact/list?page=1&page_size=100&sort=name&order=asc&modified_since=0&search=example",
    ] {
        let response = app
            .clone()
            .oneshot(request(http::Method::GET, uri, ""))
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["page"], 1);
        assert_eq!(body["page_size"], 100);
        assert_eq!(body["total"], 3);
        assert_eq!(
            body["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["alice.example", "bob.example", "charlie.example"]
        );
    }

    for (uri, expected) in [
        ("/std/contact/list?page_size=1", "charlie.example"),
        (
            "/std/contact/list?page_size=1&sort=name&order=desc",
            "charlie.example",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(request(http::Method::GET, uri, ""))
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["items"][0]["name"], expected);
    }

    for uri in [
        "/std/contact/list?page=0",
        "/std/contact/list?page=-1",
        "/std/contact/list?page=1.5",
        "/std/contact/list?page=abc",
        "/std/contact/list?page=18446744073709551616",
        "/std/contact/list?page_size=0",
        "/std/contact/list?page_size=101",
        "/std/contact/list?sort=unknown",
        "/std/contact/list?order=sideways",
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request(http::Method::GET, uri, ""))
                .await
                .unwrap()
                .status(),
            http::StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn local_approval_activates_without_waiting_for_a_peer() {
    let service = Arc::new(service().await);
    service.create_contact(contact()).await.unwrap();
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/local",
            Effect::Allow,
            Grantee::One("alice.example".into()),
        )
        .await
        .unwrap();
    let app = crate::api::router(service.clone());
    let approval = request(
        http::Method::PATCH,
        "/std/contact?name=alice.example",
        r#"{"status":"active"}"#,
    );
    assert_eq!(
        app.oneshot(as_visitor(approval, "admin.example"))
            .await
            .unwrap()
            .status(),
        http::StatusCode::NO_CONTENT
    );

    let stored = service.find_contact_by_name("alice.example").await.unwrap();
    assert_eq!(stored.status, ContactStatus::Active as i32);
    assert_eq!(stored.requested_access, requested("/requested"));
    assert!(stored.granted_access.is_empty());
}

#[tokio::test]
async fn local_patch_requires_a_field_and_a_valid_transition() {
    let service = Arc::new(service().await);
    service.create_contact(contact()).await.unwrap();
    let app = crate::api::router(service);

    let without_visitor = request(
        http::Method::PATCH,
        "/std/contact?name=alice.example",
        r#"{"alias":"Alice"}"#,
    );
    assert_eq!(
        app.clone().oneshot(without_visitor).await.unwrap().status(),
        http::StatusCode::NO_CONTENT
    );

    for (body, expected) in [
        (r#"{}"#, http::StatusCode::BAD_REQUEST),
        (r#"{"status":"active"}"#, http::StatusCode::NO_CONTENT),
    ] {
        let approval = request(http::Method::PATCH, "/std/contact?name=alice.example", body);
        assert_eq!(
            app.clone()
                .oneshot(as_visitor(approval, "admin.example"))
                .await
                .unwrap()
                .status(),
            expected
        );
    }
}

#[tokio::test]
async fn administrator_can_block_and_restore_an_active_contact() {
    let service = Arc::new(service().await);
    service.create_contact(contact()).await.unwrap();
    service
        .db
        .execute_unprepared(
            "UPDATE contacts SET status = 2, offers = '{}' WHERE name = 'alice.example'",
        )
        .await
        .unwrap();
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/local",
            Effect::Review,
            Grantee::One("alice.example".into()),
        )
        .await
        .unwrap();
    let app = crate::api::router(service.clone());

    let block = request(
        http::Method::PATCH,
        "/std/contact?name=alice.example",
        r#"{"status":"blocked","alias":"Alice"}"#,
    );
    assert_eq!(
        app.clone()
            .oneshot(as_visitor(block, "admin.example"))
            .await
            .unwrap()
            .status(),
        http::StatusCode::NO_CONTENT
    );
    let blocked = service.find_contact_by_name("alice.example").await.unwrap();
    assert_eq!(blocked.status, ContactStatus::Blocked as i32);
    assert_eq!(blocked.alias.as_deref(), Some("Alice"));
    assert_eq!(
        blocked.offers["/local"].review,
        [Method::Specified(http::Method::GET)]
    );
    assert_eq!(
        service
            .policies
            .read()
            .await
            .evaluate(
                &http::Method::GET,
                "/local",
                &[Grantee::One("alice.example".into())]
            )
            .0,
        Effect::Deny
    );

    let unblock = request(
        http::Method::PATCH,
        "/std/contact?name=alice.example",
        r#"{"status":"active"}"#,
    );
    assert_eq!(
        app.oneshot(as_visitor(unblock, "admin.example"))
            .await
            .unwrap()
            .status(),
        http::StatusCode::NO_CONTENT
    );
    let active = service.find_contact_by_name("alice.example").await.unwrap();
    assert_eq!(active.status, ContactStatus::Active as i32);
    assert!(active.offers.is_empty());
    assert_eq!(active.alias.as_deref(), Some("Alice"));
    assert_eq!(
        service
            .policies
            .read()
            .await
            .evaluate(
                &http::Method::GET,
                "/local",
                &[Grantee::One("alice.example".into())]
            )
            .0,
        Effect::Review
    );

    let clear_alias = request(
        http::Method::PATCH,
        "/std/contact?name=alice.example",
        r#"{"alias":""}"#,
    );
    assert_eq!(
        crate::api::router(service.clone())
            .oneshot(as_visitor(clear_alias, "admin.example"))
            .await
            .unwrap()
            .status(),
        http::StatusCode::NO_CONTENT
    );
    assert!(
        service
            .find_contact_by_name("alice.example")
            .await
            .unwrap()
            .alias
            .is_none()
    );
}

#[tokio::test]
async fn pending_contact_cannot_be_blocked() {
    let service = Arc::new(service().await);
    service.create_contact(contact()).await.unwrap();
    let app = crate::api::router(service.clone());
    let block = request(
        http::Method::PATCH,
        "/std/contact?name=alice.example",
        r#"{"status":"blocked"}"#,
    );

    assert_eq!(
        app.oneshot(as_visitor(block, "admin.example"))
            .await
            .unwrap()
            .status(),
        http::StatusCode::CONFLICT
    );
    assert_eq!(
        service
            .find_contact_by_name("alice.example")
            .await
            .unwrap()
            .status,
        ContactStatus::Pending as i32
    );
}

#[tokio::test]
async fn last_management_administrator_cannot_be_blocked() {
    let service = Arc::new(service().await);
    service.create_contact(contact()).await.unwrap();
    service
        .db
        .execute_unprepared(
            "UPDATE contacts SET status = 2, offers = '{}' WHERE name = 'alice.example'",
        )
        .await
        .unwrap();
    let method = Method::Specified(http::Method::PATCH);
    service
        .set_policy(
            method.clone(),
            "/std/acl/review",
            Effect::Allow,
            Grantee::One("alice.example".into()),
        )
        .await
        .unwrap();
    service
        .set_policy(
            method.clone(),
            "/std/acl/review",
            Effect::Deny,
            Grantee::One("owner.example".into()),
        )
        .await
        .unwrap();
    let app = crate::api::router(service.clone());
    let block = request(
        http::Method::PATCH,
        "/std/contact?name=alice.example",
        r#"{"status":"blocked"}"#,
    );

    assert_eq!(
        app.oneshot(as_visitor(block, "owner.example"))
            .await
            .unwrap()
            .status(),
        http::StatusCode::BAD_REQUEST
    );
    let contact = service.find_contact_by_name("alice.example").await.unwrap();
    assert_eq!(contact.status, ContactStatus::Active as i32);
    assert!(contact.offers.is_empty());
    assert_eq!(
        service
            .policies
            .read()
            .await
            .evaluate(
                &http::Method::PATCH,
                "/std/acl/review",
                &[Grantee::One("alice.example".into())]
            )
            .0,
        Effect::Allow
    );
}

#[tokio::test]
async fn local_approval_accepts_a_transfered_contact() {
    let service = Arc::new(service().await);
    service.create_contact(contact()).await.unwrap();
    service
        .db
        .execute_unprepared("UPDATE contacts SET status = 3 WHERE name = 'alice.example'")
        .await
        .unwrap();
    let app = crate::api::router(service.clone());
    let approval = as_visitor(
        request(
            http::Method::PATCH,
            "/std/contact?name=alice.example",
            r#"{"status":"active"}"#,
        ),
        "owner.example",
    );

    assert_eq!(
        app.oneshot(approval).await.unwrap().status(),
        http::StatusCode::NO_CONTENT
    );
    assert_eq!(
        service
            .find_contact_by_name("alice.example")
            .await
            .unwrap()
            .status,
        2
    );
}
#[test]
fn expiry_accepts_a_duration_or_deadline_and_rejects_ambiguous_values() {
    assert_eq!(
        Expiry {
            expires_after: Some(60),
            valid_before: None
        }
        .resolve(100, 0)
        .unwrap(),
        160
    );
    assert_eq!(
        Expiry {
            expires_after: None,
            valid_before: Some(160)
        }
        .resolve(100, 0)
        .unwrap(),
        160
    );
    assert_eq!(
        Expiry {
            expires_after: None,
            valid_before: None
        }
        .resolve(100, 60)
        .unwrap(),
        60
    );
    assert!(
        Expiry {
            expires_after: Some(60),
            valid_before: Some(160)
        }
        .resolve(100, 0)
        .is_err()
    );
    assert!(
        Expiry {
            expires_after: Some(i64::MAX),
            valid_before: None
        }
        .resolve(100, 0)
        .is_err()
    );
    assert!(
        Expiry {
            expires_after: None,
            valid_before: Some(100)
        }
        .resolve(100, 0)
        .is_err()
    );
}

#[tokio::test]
async fn incremental_list_reports_updates_and_deletions_after_the_snapshot() {
    let service = Arc::new(service().await);
    service.create_contact(contact()).await.unwrap();
    service
        .patch_contact(
            "alice.example",
            ContactPatch::LocalUpdate {
                status: None,
                alias: Some("Alice".into()),
            },
        )
        .await
        .unwrap();
    let app = crate::api::router(service.clone());
    let response = app
        .clone()
        .oneshot(request(
            http::Method::GET,
            "/std/contact/list?modified_since=0&search=Alice",
            "",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let json: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(json["items"][0]["alias"], "Alice");
    assert!(json["items"][0]["valid_before"].is_i64());
    service
        .delete_contacts(&["alice.example".into()])
        .await
        .unwrap();
    let response = app
        .oneshot(request(
            http::Method::GET,
            "/std/contact/list?modified_since=0",
            "",
        ))
        .await
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(json["items"], serde_json::json!([]));
    assert_eq!(json["deleted"][0]["name"], "alice.example");
}
