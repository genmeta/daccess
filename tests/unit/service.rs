use sea_orm::{Database, TryGetable};

use super::*;

fn headers(method: http::Method, path: &str) -> Headers {
    Headers {
        method,
        path: path.to_owned(),
        fields: http::HeaderMap::new(),
    }
}

async fn service() -> AccessService {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    AccessService::migrate(&db).await.unwrap();
    AccessService::new(db, "owner.example")
}

async fn rules(service: &AccessService) -> Vec<(String, String)> {
    service
        .db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT grantee, effect FROM access_rules ORDER BY grantee",
        ))
        .await
        .unwrap()
        .into_iter()
        .map(|row| {
            (
                String::try_get(&row, "", "grantee").unwrap(),
                String::try_get(&row, "", "effect").unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn old_post_rules_and_approvals_never_authorize_message_put() {
    let service = AccessService::load_from_db(
        "sqlite::memory:",
        "owner.example",
        &SubjectId::new(b"owner").unwrap(),
    )
    .await
    .unwrap();
    let subject = SubjectId::new(b"alice").unwrap();
    service
        .set_policy(
            Method::Specified(http::Method::POST),
            "/std/message",
            Effect::Allow,
            Grantee::Named,
        )
        .await
        .unwrap();
    assert!(matches!(
        service
            .auth(
                headers(http::Method::POST, "/std/message"),
                Some("alice.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Allowed
    ));
    assert!(matches!(
        service
            .auth(
                headers(http::Method::PUT, "/std/message"),
                Some("alice.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Denied
    ));
    service.db.execute_unprepared("INSERT INTO access_reviews(request_id,visitor,visitor_sid,method,api,stage,reason,expired_after,updated_at,created_at) VALUES('old-post','alice.example',X'616c696365','POST','/std/message',0,'old request',4070995200,1,1)").await.unwrap();
    service
        .decide_review(1, crate::Action::Allow, true)
        .await
        .unwrap();
    assert!(matches!(
        service
            .auth(
                headers(http::Method::PUT, "/std/message"),
                Some("alice.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Denied
    ));
    service
        .set_policy(
            Method::Specified(http::Method::PUT),
            "/std/message",
            Effect::Review,
            Grantee::Named,
        )
        .await
        .unwrap();
    assert!(matches!(
        service
            .auth(
                headers(http::Method::PUT, "/std/message"),
                Some("alice.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Reviewing(_)
    ));
}

#[tokio::test]
async fn version_zero_migration_creates_and_constrains_the_schema() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.execute_unprepared(AccessService::MIGRATIONS[0])
        .await
        .unwrap();
    let service = AccessService::new(db, "owner.example");
    let tables = service
        .db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS count FROM sqlite_master \
                 WHERE type = 'table' AND name IN \
                 ('module', 'contacts', 'access_rules', 'access_reviews')",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(i64::try_get(&tables, "", "count").unwrap(), 4);

    let module = service
        .db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT module_name, version FROM module",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        String::try_get(&module, "", "module_name").unwrap(),
        "access"
    );
    assert_eq!(i64::try_get(&module, "", "version").unwrap(), 0);
    assert!(
        service
            .db
            .execute_unprepared("INSERT INTO module (module_name, version) VALUES ('another', 0)")
            .await
            .is_err()
    );

    service
            .db
            .execute_unprepared(
                r#"INSERT INTO contacts
                   (name, subject_id, class, grants, requests, status, expired_after, updated_at, created_at)
                   VALUES
                   ('pending.example', X'01', '', '{}', '{}', 3, 1767484800, 1767225600, 1767225600),
                   ('admin.example', X'02', 'admin', '{}', '{}', 0, 1767484800, 1767225600, 1767225600)"#,
            )
            .await
            .unwrap();
    assert!(
            service
                .db
                .execute_unprepared(
                    r#"INSERT INTO contacts
                       (name, subject_id, grants, requests, status, expired_after, updated_at, created_at)
                       VALUES
                       ('bad-json.example', X'03', '[]', '{}', 0, 1767484800, 1767225600, 1767225600)"#,
                )
                .await
                .is_err()
        );
    let classes = service
        .db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT class FROM contacts ORDER BY name",
        ))
        .await
        .unwrap();
    assert_eq!(String::try_get(&classes[0], "", "class").unwrap(), "admin");
    assert_eq!(String::try_get(&classes[1], "", "class").unwrap(), "");
    assert!(
        service
            .db
            .execute_unprepared(
                r#"INSERT INTO contacts
                       (name, subject_id, status, expired_after, updated_at, created_at)
                       VALUES
                       ('legacy-status.example', X'04', 1, 1767484800, 1767225600, 1767225600)"#,
            )
            .await
            .is_err()
    );
    assert!(
        service
            .db
            .execute_unprepared(
                r#"INSERT INTO contacts
                       (name, subject_id, status, expired_after, updated_at, created_at)
                       VALUES
                       ('blocked.example', X'05', 5, 1767484800, 1767225600, 1767225600)"#,
            )
            .await
            .is_ok()
    );
    assert!(
        service
            .db
            .execute_unprepared(
                r#"INSERT INTO contacts
                       (name, subject_id, status, expired_after, updated_at, created_at)
                       VALUES
                       ('bad-status.example', X'06', 6, 1767484800, 1767225600, 1767225600)"#,
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn schema_accepts_a_64_byte_subject_id_and_rejects_a_longer_one() {
    let service = service().await;
    let owner_hash = "30".repeat(64);
    let too_long = "30".repeat(65);

    service
            .db
            .execute_unprepared(&format!(
                r#"INSERT INTO contacts
                   (name, subject_id, status, expired_after, updated_at, created_at)
                   VALUES ('owner-hash.example', X'{owner_hash}', 0, 1767484800, 1767225600, 1767225600)"#
            ))
            .await
            .unwrap();
    assert!(
            service
                .db
                .execute_unprepared(&format!(
                    r#"INSERT INTO contacts
                       (name, subject_id, status, expired_after, updated_at, created_at)
                       VALUES ('too-long.example', X'{too_long}', 0, 1767484800, 1767225600, 1767225600)"#
                ))
                .await
                .is_err()
        );
}

#[tokio::test]
async fn schema_stores_timestamps_as_integers() {
    let service = service().await;
    service
        .db
        .execute_unprepared(
            r#"INSERT INTO contacts
                   (name, subject_id, status, expired_after, updated_at, created_at)
                   VALUES ('timestamp.example', X'01', 0, 1767484800, 1767225600, 1767225600);
                   INSERT INTO access_rules
                   (method, api, effect, grantee_type, grantee, updated_at, created_at)
                   VALUES ('GET', '/', 'allow', 0, 'timestamp.example', 1767225600, 1767225600);
                   INSERT INTO access_reviews
                   (request_id, visitor, visitor_sid, method, api, stage, reason,
                    expired_after, updated_at, created_at)
                   VALUES ('timestamp-review', 'timestamp.example', X'01', 'GET', '/', 0,
                           'timestamp storage test', 1767312000, 1767225600, 1767225600)"#,
        )
        .await
        .unwrap();
    let row = service
            .db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                r#"SELECT
                       typeof(expired_after) AS contact_expired_after_type,
                       typeof(updated_at) AS contact_updated_at_type,
                       typeof(created_at) AS contact_created_at_type,
                       (SELECT typeof(updated_at) FROM access_rules LIMIT 1) AS rule_updated_at_type,
                       (SELECT typeof(created_at) FROM access_rules LIMIT 1) AS rule_created_at_type,
                       (SELECT typeof(expired_after) FROM access_reviews LIMIT 1) AS review_expired_after_type,
                       (SELECT typeof(updated_at) FROM access_reviews LIMIT 1) AS review_updated_at_type,
                       (SELECT typeof(created_at) FROM access_reviews LIMIT 1) AS review_created_at_type
                   FROM contacts WHERE name = 'timestamp.example'"#,
            ))
            .await
            .unwrap()
            .unwrap();
    for column in [
        "contact_expired_after_type",
        "contact_updated_at_type",
        "contact_created_at_type",
        "rule_updated_at_type",
        "rule_created_at_type",
        "review_expired_after_type",
        "review_updated_at_type",
        "review_created_at_type",
    ] {
        assert_eq!(String::try_get(&row, "", column).unwrap(), "integer");
    }
    assert!(
        service
            .db
            .execute_unprepared(
                "UPDATE contacts SET updated_at = '2026-01-01' WHERE name = 'timestamp.example'"
            )
            .await
            .is_err()
    );
    assert!(
        service
            .db
            .execute_unprepared(
                "UPDATE contacts SET expired_after = '2026-01-04' WHERE name = 'timestamp.example'"
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn load_from_db_initializes_a_fresh_database() {
    let service = AccessService::load_from_db(
        "sqlite::memory:",
        "me.example",
        &SubjectId::new([1]).unwrap(),
    )
    .await
    .unwrap();
    let module = service
        .db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT version FROM module",
        ))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(i64::try_get(&module, "", "version").unwrap(), 3);
    let columns = service
        .db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            String::from("PRAGMA table_info(access_reviews)"),
        ))
        .await
        .unwrap();
    assert!(
        columns
            .iter()
            .any(|row| String::try_get(row, "", "name").unwrap() == "request_id")
    );
    assert_eq!(
        service
            .contacts
            .read()
            .await
            .get("me.example")
            .unwrap()
            .as_bytes(),
        &[1]
    );
    assert!(matches!(
        service
            .auth(
                headers(http::Method::GET, "/std/contact/list"),
                Some("me.example"),
                Some(&SubjectId::new([1]).unwrap())
            )
            .await
            .unwrap(),
        AuthResult::Allowed
    ));
    assert!(matches!(
        service
            .auth(
                headers(http::Method::GET, "/std/contact/list"),
                Some("other.example"),
                Some(&SubjectId::new([2]).unwrap())
            )
            .await
            .unwrap(),
        AuthResult::Denied
    ));
    assert!(matches!(
        service
            .auth(
                headers(http::Method::GET, "/std/contact/list"),
                Some("me.example"),
                Some(&SubjectId::new([2]).unwrap())
            )
            .await
            .unwrap(),
        AuthResult::Reviewing(..)
    ));
}

#[tokio::test]
async fn migration_rejects_unsupported_schema_versions() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.execute_unprepared(AccessService::MIGRATIONS[0])
        .await
        .unwrap();
    db.execute_unprepared("UPDATE module SET version = 99")
        .await
        .unwrap();

    assert!(AccessService::migrate(&db).await.is_err());
}

#[tokio::test]
async fn load_builds_defaults_then_applies_database_rules() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.execute_unprepared(AccessService::MIGRATIONS[0])
        .await
        .unwrap();
    db.execute_unprepared(
        r#"INSERT INTO contacts
               (name, subject_id, status, expired_after, updated_at, created_at)
               VALUES ('me.example', X'01', 0, 1767484800, 1767225600, 1767225600);

               INSERT INTO access_rules
               (method, api, effect, grantee_type, grantee, updated_at, created_at)
               VALUES
               ('*', '/named', 'allow', 2, '**', 1767225600, 1767225600),
               ('GET', '/self', 'deny', 0, 'me.example', 1767225600, 1767225600),
               ('POST', '/group', 'allow', 1, 'student@hit.edu', 1767225600, 1767225600)"#,
    )
    .await
    .unwrap();

    let service = AccessService::load(db, "me.example", &SubjectId::new([1]).unwrap())
        .await
        .unwrap();
    let policies = service.policies.read().await;

    assert_eq!(
        service
            .contacts
            .read()
            .await
            .get("me.example")
            .unwrap()
            .as_bytes(),
        &[1]
    );
    assert!(service.contacts.read().await.get("other.example").is_none());
    assert_eq!(
        policies
            .evaluate(
                &http::Method::GET,
                "/named",
                &[
                    Grantee::One(String::from("me.example")),
                    Grantee::Named,
                    Grantee::All
                ]
            )
            .0,
        Effect::Allow
    );
    assert_eq!(
        policies
            .evaluate(
                &http::Method::GET,
                "/named",
                &[
                    Grantee::One(String::from("other.example")),
                    Grantee::Named,
                    Grantee::All
                ]
            )
            .0,
        Effect::Allow
    );
    assert_eq!(
        policies
            .evaluate(
                &http::Method::GET,
                "/named",
                &[Grantee::Anony, Grantee::All]
            )
            .0,
        Effect::Deny
    );
    assert_eq!(
        policies
            .evaluate(
                &http::Method::GET,
                "/self",
                &[Grantee::One(String::from("me.example")), Grantee::All]
            )
            .0,
        Effect::Deny
    );
    assert_eq!(
        policies
            .evaluate(
                &http::Method::POST,
                "/group",
                &[
                    Grantee::One(String::from("student.example")),
                    Grantee::Group {
                        title: String::from("student"),
                        issuer: String::from("hit.edu"),
                    },
                    Grantee::Named,
                    Grantee::All,
                ]
            )
            .0,
        Effect::Allow
    );
    assert_eq!(
        policies
            .evaluate(
                &http::Method::POST,
                "/group",
                &[
                    Grantee::One(String::from("other.example")),
                    Grantee::Named,
                    Grantee::All
                ]
            )
            .0,
        Effect::Deny
    );
}

#[tokio::test]
async fn removing_last_explicit_scope_rule_restores_parent_defaults() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.execute_unprepared(AccessService::MIGRATIONS[0])
        .await
        .unwrap();
    db.execute_unprepared(
        r#"INSERT INTO access_rules
               (method, api, effect, grantee_type, grantee, updated_at, created_at)
               VALUES ('*', '/std/acl', 'allow', 0, 'me.example', 1, 1)"#,
    )
    .await
    .unwrap();
    let subject_id = SubjectId::new([1]).unwrap();
    let service = AccessService::load(db, "me.example", &subject_id)
        .await
        .unwrap();

    service
        .remove_policy(
            Method::Unspecified,
            "/std/acl",
            Grantee::One(String::from("me.example")),
        )
        .await
        .unwrap();

    assert!(matches!(
        service
            .auth(
                headers(http::Method::GET, "/std/acl/apis"),
                Some("me.example"),
                Some(&subject_id),
            )
            .await
            .unwrap(),
        AuthResult::Allowed
    ));
}

#[tokio::test]
async fn anyone_replaces_named_and_anonymous_in_database_and_memory() {
    let service = service().await;

    service
        .set_policy(Method::Unspecified, "/files", Effect::Allow, Grantee::Named)
        .await
        .unwrap();
    service
        .set_policy(Method::Unspecified, "/files", Effect::Deny, Grantee::Anony)
        .await
        .unwrap();
    assert_eq!(
        rules(&service).await,
        vec![
            (String::from("**"), String::from("allow")),
            (String::from("?"), String::from("deny")),
        ]
    );

    service
        .set_policy(Method::Unspecified, "/files", Effect::Review, Grantee::All)
        .await
        .unwrap();

    assert_eq!(
        rules(&service).await,
        vec![(String::from("*?"), String::from("review"))]
    );
    assert_eq!(
        service
            .policies
            .read()
            .await
            .evaluate(&http::Method::GET, "/files/report", &[Grantee::All])
            .0,
        Effect::Review
    );
}

#[tokio::test]
async fn replacing_effect_updates_one_database_row() {
    let service = service().await;

    service
        .set_policy(Method::Unspecified, "/files", Effect::Allow, Grantee::Named)
        .await
        .unwrap();
    service
        .set_policy(Method::Unspecified, "/files", Effect::Deny, Grantee::Named)
        .await
        .unwrap();

    assert_eq!(
        rules(&service).await,
        vec![(String::from("**"), String::from("deny"))]
    );
}

#[tokio::test]
async fn named_replaces_anyone_and_can_coexist_with_anonymous() {
    let service = service().await;

    service
        .set_policy(Method::Unspecified, "/files", Effect::Allow, Grantee::All)
        .await
        .unwrap();
    service
        .set_policy(Method::Unspecified, "/files", Effect::Deny, Grantee::Named)
        .await
        .unwrap();
    service
        .set_policy(
            Method::Unspecified,
            "/files",
            Effect::Review,
            Grantee::Anony,
        )
        .await
        .unwrap();

    assert_eq!(
        rules(&service).await,
        vec![
            (String::from("**"), String::from("deny")),
            (String::from("?"), String::from("review")),
        ]
    );
}

#[tokio::test]
async fn database_failure_leaves_memory_unchanged() {
    let service = service().await;
    service
        .set_policy(Method::Unspecified, "/files", Effect::Allow, Grantee::Named)
        .await
        .unwrap();
    service
        .db
        .execute_unprepared(
            r#"CREATE TRIGGER reject_deny
                   BEFORE UPDATE OF effect ON access_rules
                   WHEN NEW.effect = 'deny'
                   BEGIN
                       SELECT RAISE(ABORT, 'deny rejected');
                   END"#,
        )
        .await
        .unwrap();

    assert!(
        service
            .set_policy(Method::Unspecified, "/files", Effect::Deny, Grantee::Named,)
            .await
            .is_err()
    );
    assert_eq!(
        service
            .policies
            .read()
            .await
            .evaluate(&http::Method::GET, "/files", &[Grantee::Named])
            .0,
        Effect::Allow
    );
    assert_eq!(
        rules(&service).await,
        vec![(String::from("**"), String::from("allow"))]
    );
}

#[tokio::test]
async fn auth_uses_the_longest_api_path_with_a_matching_method() {
    let service = service().await;
    service
        .set_policy(Method::Unspecified, "/files", Effect::Allow, Grantee::Named)
        .await
        .unwrap();
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/files/private",
            Effect::Deny,
            Grantee::Named,
        )
        .await
        .unwrap();

    let get = service
        .auth(
            headers(http::Method::GET, "/files/private/report?download=true"),
            Some("alice.example"),
            Some(&SubjectId::new([1]).unwrap()),
        )
        .await
        .unwrap();
    let post = service
        .auth(
            headers(http::Method::POST, "/files/private/report"),
            Some("alice.example"),
            Some(&SubjectId::new([1]).unwrap()),
        )
        .await
        .unwrap();

    assert!(matches!(get, AuthResult::Denied));
    assert!(matches!(post, AuthResult::Allowed));
}

#[tokio::test]
async fn auth_changes_allow_to_review_when_subject_id_changed() {
    let service = service().await;
    service.db.execute_unprepared("INSERT INTO contacts(name,subject_id,class,description,status,expired_after,created_at,updated_at) VALUES('alice.example',X'01','','',2,4070995200,1,1)").await.unwrap();
    service
        .contacts
        .write()
        .await
        .insert(String::from("alice.example"), SubjectId::new([1]).unwrap());
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/profile",
            Effect::Allow,
            Grantee::One("alice.example".into()),
        )
        .await
        .unwrap();

    let result = service
        .auth(
            headers(http::Method::GET, "/profile"),
            Some("alice.example"),
            Some(&SubjectId::new([2]).unwrap()),
        )
        .await
        .unwrap();

    assert!(matches!(result, AuthResult::Reviewing(..)));
    let row = service
        .db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT visitor_sid, reason FROM access_reviews",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        Vec::<u8>::try_get(&row, "", "visitor_sid").unwrap(),
        vec![2]
    );
    assert_eq!(
        String::try_get(&row, "", "reason").unwrap(),
        "subject_id changed"
    );
}

#[tokio::test]
async fn review_is_persisted_without_a_caller_supplied_request_id() {
    let service = service().await;
    service
        .set_policy(
            Method::Specified(http::Method::POST),
            "/deploy",
            Effect::Review,
            Grantee::Named,
        )
        .await
        .unwrap();

    let result = service
        .auth(
            headers(http::Method::POST, "/deploy/task"),
            Some("alice.example"),
            Some(&SubjectId::new([1]).unwrap()),
        )
        .await
        .unwrap();
    assert!(matches!(result, AuthResult::Reviewing(..)));

    let row = service
        .db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS count FROM access_reviews",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(i64::try_get(&row, "", "count").unwrap(), 1);
}

#[tokio::test]
async fn identical_review_requests_reuse_one_persistent_record() {
    let service = service().await;
    service
        .set_policy(
            Method::Specified(http::Method::POST),
            "/deploy",
            Effect::Review,
            Grantee::Named,
        )
        .await
        .unwrap();

    let request_headers = headers(http::Method::POST, "/deploy/task");
    let request_id = RequestId::for_request(
        &request_headers,
        "alice.example",
        &SubjectId::new([1]).unwrap(),
    );
    let result = service
        .auth(
            request_headers,
            Some("alice.example"),
            Some(&SubjectId::new([1]).unwrap()),
        )
        .await
        .unwrap();
    let review_id = match result {
        AuthResult::Reviewing(review) => review.id(),
        _ => panic!("expected pending review"),
    };

    let row = service
        .db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT id, request_id, visitor, visitor_sid, method, api, stage, reason \
                 FROM access_reviews",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(i64::try_get(&row, "", "id").unwrap(), review_id);
    assert_eq!(
        String::try_get(&row, "", "request_id").unwrap(),
        request_id.as_str()
    );
    assert_eq!(
        String::try_get(&row, "", "visitor").unwrap(),
        "alice.example"
    );
    assert_eq!(String::try_get(&row, "", "method").unwrap(), "POST");
    assert_eq!(String::try_get(&row, "", "api").unwrap(), "/deploy/task");
    assert_eq!(i32::try_get(&row, "", "stage").unwrap(), 0);
    assert_eq!(
        Vec::<u8>::try_get(&row, "", "visitor_sid").unwrap(),
        vec![1]
    );
    assert_eq!(
        String::try_get(&row, "", "reason").unwrap(),
        "matched review rule: POST /deploy **"
    );

    let retry = service
        .auth(
            headers(http::Method::POST, "/deploy/task"),
            Some("alice.example"),
            Some(&SubjectId::new([1]).unwrap()),
        )
        .await
        .unwrap();
    assert!(matches!(
        retry,
        AuthResult::Reviewing(review) if review.id() == review_id
    ));

    let count = service
        .db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS count FROM access_reviews",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(i64::try_get(&count, "", "count").unwrap(), 1);
}

#[tokio::test]
async fn old_review_decisions_cannot_authorize_without_an_acl_rule() {
    let service = service().await;
    service
        .set_policy(
            Method::Specified(http::Method::POST),
            "/deploy",
            Effect::Review,
            Grantee::Named,
        )
        .await
        .unwrap();
    let request_headers = headers(http::Method::POST, "/deploy");
    let request_id = RequestId::for_request(
        &request_headers,
        "alice.example",
        &SubjectId::new([1]).unwrap(),
    );
    service
        .db
        .execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            r#"INSERT INTO access_reviews
                   (request_id, visitor, visitor_sid, method, api, stage, reason,
                    expired_after, updated_at, created_at)
                   VALUES (?, 'alice.example', X'01', 'POST', '/deploy', 1,
                    'matched review rule: POST /deploy **',
                    CAST(strftime('%s', 'now', '+1 day') AS INTEGER),
                    CAST(strftime('%s', 'now') AS INTEGER),
                    CAST(strftime('%s', 'now') AS INTEGER))"#,
            [request_id.as_str().into()],
        ))
        .await
        .unwrap();

    let result = service
        .auth(
            request_headers,
            Some("alice.example"),
            Some(&SubjectId::new([1]).unwrap()),
        )
        .await
        .unwrap();

    assert!(matches!(result, AuthResult::Reviewing(_)));
    let count = service
        .db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS count FROM access_reviews",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(i64::try_get(&count, "", "count").unwrap(), 2);
}
#[tokio::test]
async fn broad_allow_is_independent_of_contact_identity_history_and_remains_revocable() {
    let service = service().await;
    service
        .contacts
        .write()
        .await
        .insert("alice.example".into(), SubjectId::new([1]).unwrap());
    service
        .set_policy(
            Method::Specified(http::Method::GET),
            "/std/acl/status",
            Effect::Allow,
            Grantee::Named,
        )
        .await
        .unwrap();
    let subject = SubjectId::new([2]).unwrap();
    assert!(matches!(
        service
            .auth(
                headers(http::Method::GET, "/std/acl/status?id=12"),
                Some("alice.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Allowed
    ));
    service
        .remove_policy(
            Method::Specified(http::Method::GET),
            "/std/acl/status",
            Grantee::Named,
        )
        .await
        .unwrap();
    assert!(matches!(
        service
            .auth(
                headers(http::Method::GET, "/std/acl/status?id=12"),
                Some("alice.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Denied
    ));
}
#[tokio::test]
async fn review_approval_survives_reload_and_remains_revocable_and_identity_bound() {
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
    let subject = SubjectId::new(b"alice").unwrap();
    let AuthResult::Reviewing(review) = service
        .auth(
            headers(http::Method::POST, "/deploy"),
            Some("alice.example"),
            Some(&subject),
        )
        .await
        .unwrap()
    else {
        panic!("expected review")
    };
    service
        .decide_review(review.id(), crate::Action::Allow, true)
        .await
        .unwrap();
    assert_eq!(
        service
            .find_contact_by_name("alice.example")
            .await
            .unwrap()
            .status,
        crate::ContactStatus::Pending as i32
    );
    let reloaded = AccessService::load(
        service.db.clone(),
        "owner.example",
        &SubjectId::new(b"owner").unwrap(),
    )
    .await
    .unwrap();
    for _ in 0..3 {
        assert!(matches!(
            reloaded
                .auth(
                    headers(http::Method::POST, "/deploy"),
                    Some("alice.example"),
                    Some(&subject)
                )
                .await
                .unwrap(),
            AuthResult::Allowed
        ));
    }
    assert!(matches!(
        reloaded
            .auth(
                headers(http::Method::POST, "/deploy"),
                Some("alice.example"),
                Some(&SubjectId::new(b"replacement").unwrap())
            )
            .await
            .unwrap(),
        AuthResult::Reviewing(_)
    ));
    assert!(matches!(
        reloaded
            .auth(
                headers(http::Method::POST, "/deploy"),
                Some("bob.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Reviewing(_)
    ));
    assert!(matches!(
        reloaded
            .auth(
                headers(http::Method::GET, "/deploy"),
                Some("alice.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Denied
    ));
    reloaded
        .remove_policy(
            Method::Specified(http::Method::POST),
            "/deploy",
            Grantee::One("alice.example".into()),
        )
        .await
        .unwrap();
    assert!(matches!(
        reloaded
            .auth(
                headers(http::Method::POST, "/deploy"),
                Some("alice.example"),
                Some(&subject)
            )
            .await
            .unwrap(),
        AuthResult::Reviewing(_)
    ));
}
