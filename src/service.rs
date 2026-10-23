use std::collections::HashSet;

use radix_trie::Trie;
use sea_orm::{
    ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, DbErr, Statement,
    TransactionTrait, TryGetable,
};
use tokio::sync::RwLock;

use crate::{
    Effect, Grantee, Headers, Method, PendingReview, Policies, ReviewStatus, SubjectId,
    policy::{PolicyError, database_api},
    review::{LiveReviews, RequestId},
};

pub struct AccessService {
    pub(crate) db: DatabaseConnection,
    pub(crate) owner_name: String,
    pub(crate) contacts: RwLock<Trie<String, SubjectId>>,
    pub(crate) policies: RwLock<Policies>,
    pub(crate) reviews: LiveReviews,
}

impl AccessService {
    const MIGRATIONS: [&'static str; 4] = [
        include_str!("migrations/0.sql"),
        include_str!("migrations/1.sql"),
        include_str!("migrations/2.sql"),
        include_str!("migrations/3.sql"),
    ];
    const VERSION: u32 = 3;

    pub fn new(db: DatabaseConnection, owner_name: impl Into<String>) -> Self {
        Self {
            db,
            owner_name: owner_name.into(),
            contacts: RwLock::new(Trie::new()),
            policies: RwLock::new(Policies::default()),
            reviews: LiveReviews::default(),
        }
    }

    pub async fn load_from_db(
        dbname: &str,
        name: &str,
        subject_id: &SubjectId,
    ) -> Result<Self, DbErr> {
        let db = Database::connect(dbname).await?;
        Self::migrate(&db).await?;
        Self::load(db, name, subject_id).await
    }

    pub(crate) async fn migrate(db: &DatabaseConnection) -> Result<(), DbErr> {
        let module_exists = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'module'",
            ))
            .await?
            .is_some();

        if !module_exists {
            let transaction = db.begin().await?;
            if transaction
                .query_one_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    "SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1",
                ))
                .await?
                .is_some()
            {
                return Err(DbErr::Type(String::from(
                    "unrecognized access database format",
                )));
            }
            transaction.execute_unprepared(Self::MIGRATIONS[0]).await?;
            transaction.commit().await?;
        }

        let module = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT version FROM module",
            ))
            .await?
            .ok_or_else(|| DbErr::Type(String::from("module table is empty")))?;
        let version = i64::try_get(&module, "", "version")?;
        if !(0..=i64::from(Self::VERSION)).contains(&version) {
            return Err(DbErr::Type(format!(
                "unsupported access database version {version}"
            )));
        }
        for next in (version + 1)..=i64::from(Self::VERSION) {
            let transaction = db.begin().await?;
            transaction
                .execute_unprepared(Self::MIGRATIONS[next as usize])
                .await?;
            transaction
                .execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE module SET version = ? WHERE module_name = 'access'",
                    [next.into()],
                ))
                .await?;
            transaction.commit().await?;
        }
        Ok(())
    }

    async fn load(
        db: DatabaseConnection,
        owner_name: &str,
        owner_subject_id: &SubjectId,
    ) -> Result<Self, DbErr> {
        let contact_rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT name, subject_id FROM contacts ORDER BY id ASC",
            ))
            .await?;
        let mut contacts = Trie::new();
        contacts.insert(owner_name.to_owned(), owner_subject_id.clone());
        for row in contact_rows {
            let name = String::try_get(&row, "", "name")?;
            let value = Vec::<u8>::try_get(&row, "", "subject_id")?;
            let subject_id = SubjectId::new(value).map_err(|_| {
                DbErr::Type(format!("invalid subject_id stored for contact {name:?}"))
            })?;
            contacts.insert(name, subject_id);
        }

        let policies = Self::policies_from_db(&db, owner_name).await?;

        Ok(Self {
            db,
            owner_name: owner_name.to_owned(),
            contacts: RwLock::new(contacts),
            policies: RwLock::new(policies),
            reviews: LiveReviews::default(),
        })
    }

    pub(crate) async fn policies_from_db(
        db: &impl ConnectionTrait,
        owner_name: &str,
    ) -> Result<Policies, DbErr> {
        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT method, api, effect, grantee_type, grantee \
                 FROM access_rules ORDER BY id ASC",
            ))
            .await?;
        let mut policies = Policies::default();
        policies.insert(Method::Unspecified, "/", Effect::Deny, Grantee::All);
        policies.insert(
            Method::Unspecified,
            "/",
            Effect::Allow,
            Grantee::One(owner_name.to_owned()),
        );
        let mut initialized = HashSet::new();

        for row in rows {
            let method = String::try_get(&row, "", "method")?.parse::<Method>()?;
            let api = String::try_get(&row, "", "api")?;
            if initialized.insert((method.clone(), api.clone())) {
                policies.insert(method.clone(), &api, Effect::Deny, Grantee::All);
                policies.insert(
                    method.clone(),
                    &api,
                    Effect::Allow,
                    Grantee::One(owner_name.to_owned()),
                );
            }

            let effect = String::try_get(&row, "", "effect")?.parse()?;
            let grantee_type = i32::try_get(&row, "", "grantee_type")?;
            let grantee = Grantee::try_from((grantee_type, String::try_get(&row, "", "grantee")?))?;
            policies.insert(method, &api, effect, grantee);
        }

        Ok(policies)
    }

    pub async fn auth(
        &self,
        headers: Headers,
        name: Option<&str>,
        subject_id: Option<&SubjectId>,
    ) -> Result<AuthResult, DbErr> {
        let mode = crate::ReviewMode::from_headers(&headers.fields)?;
        if name.is_some() != subject_id.is_some() {
            return Err(DbErr::Type(String::from(
                "name and subject_id must either both be present or both be absent",
            )));
        }
        let api = headers
            .path
            .split_once('?')
            .map_or(headers.path.as_str(), |v| v.0);
        if !api.starts_with('/') {
            return Err(DbErr::Type(format!(
                "invalid request path {:?}",
                headers.path
            )));
        }
        let api = database_api(api);

        let grantees = match name {
            Some(name) => vec![Grantee::One(name.to_owned()), Grantee::Named, Grantee::All],
            None => vec![Grantee::Anony, Grantee::All],
        };
        // Keep registration and policy evaluation atomic with respect to a review decision.
        let policies = self.policies.read().await;
        let (policy_effect, policy_method, policy_api, policy_grantee) =
            policies.evaluate(&headers.method, &api, &grantees);
        let subject_changed = match (name, subject_id) {
            (Some(name), Some(subject_id)) => self
                .contacts
                .read()
                .await
                .get(name)
                .is_some_and(|known| known != subject_id),
            _ => false,
        };
        let reason = match policy_effect {
            Effect::Allow
                if subject_changed
                    && matches!(policy_grantee, Grantee::One(_) | Grantee::Group { .. }) =>
            {
                String::from("subject_id changed")
            }
            Effect::Allow => return Ok(AuthResult::Allowed),
            Effect::Deny => return Ok(AuthResult::Denied),
            Effect::Review => format!(
                "matched review rule: {} {} {}",
                policy_method.to_string(),
                policy_api,
                policy_grantee
            ),
        };

        let Some((visitor, visitor_sid)) = name.zip(subject_id) else {
            // A review must be queryable only by the authenticated subject that
            // initiated it. Anonymous review requests therefore fail closed.
            return Ok(AuthResult::Denied);
        };
        let consumed = self.db.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "UPDATE access_reviews SET consumed_at=CAST(strftime('%s','now') AS INTEGER),updated_at=CAST(strftime('%s','now') AS INTEGER) WHERE id=(SELECT id FROM access_reviews WHERE visitor=? AND visitor_sid=? AND method=? AND api=? AND stage=1 AND remember=0 AND consumed_at IS NULL AND invalidated_at IS NULL AND grant_expires_at>CAST(strftime('%s','now') AS INTEGER) ORDER BY id LIMIT 1) AND consumed_at IS NULL AND invalidated_at IS NULL",
            [visitor.into(), visitor_sid.as_bytes().to_vec().into(), headers.method.as_str().into(), api.as_str().into()],
        )).await?.rows_affected();
        if consumed == 1 {
            return Ok(AuthResult::Allowed);
        }
        if mode == crate::ReviewMode::Waiting {
            return Ok(AuthResult::Waiting(self.reviews.add(
                visitor,
                visitor_sid,
                &headers,
                reason,
            )));
        }
        let request_id = RequestId::for_request(&headers, visitor, visitor_sid);
        let id = self
            .persistent_review(
                visitor,
                visitor_sid,
                request_id.as_str(),
                headers.method.as_str(),
                &api,
                &reason,
            )
            .await?;
        Ok(AuthResult::Reviewing(PendingReview::new(id)))
    }

    async fn persistent_review(
        &self,
        visitor: &str,
        visitor_sid: &SubjectId,
        request_id: &str,
        method: &str,
        api: &str,
        reason: &str,
    ) -> Result<i64, DbErr> {
        // A resolved round keeps its ID and outcome. Only pending rounds deduplicate.
        self.db.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "UPDATE access_reviews SET stage=3,updated_at=CAST(strftime('%s','now') AS INTEGER) WHERE visitor=? AND visitor_sid=? AND method=? AND api=? AND stage=0 AND expired_after<=CAST(strftime('%s','now') AS INTEGER)",
            [visitor.into(), visitor_sid.as_bytes().to_vec().into(), method.into(), api.into()],
        )).await?;
        let row = self.db.query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO access_reviews(request_id,visitor,visitor_sid,method,api,stage,reason,expired_after,updated_at,created_at) VALUES(?,?,?,?,?,0,?,CAST(strftime('%s','now','+1 day') AS INTEGER),CAST(strftime('%s','now') AS INTEGER),CAST(strftime('%s','now') AS INTEGER)) ON CONFLICT(visitor,visitor_sid,method,api) WHERE stage=0 DO UPDATE SET reason=excluded.reason RETURNING id",
            [request_id.into(),visitor.into(),visitor_sid.as_bytes().to_vec().into(),method.into(),api.into(),reason.into()],
        )).await?.ok_or_else(|| DbErr::RecordNotInserted)?;
        row.try_get("", "id")
    }

    pub fn database(&self) -> &DatabaseConnection {
        &self.db
    }

    pub async fn review_status(
        &self,
        id: i64,
        visitor: &str,
        subject_id: &SubjectId,
    ) -> Result<ReviewStatus, DbErr> {
        self.review_status_details(id, visitor, subject_id)
            .await
            .map(|details| details.0)
    }

    pub(crate) async fn review_status_details(
        &self,
        id: i64,
        visitor: &str,
        subject_id: &SubjectId,
    ) -> Result<(ReviewStatus, Option<bool>, Option<i64>), DbErr> {
        let row = self.db.query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT stage,expired_after,remember,grant_expires_at,consumed_at,invalidated_at FROM access_reviews WHERE id=? AND visitor=? AND visitor_sid=?",
            [id.into(),visitor.into(),subject_id.as_bytes().to_vec().into()],
        )).await?.ok_or_else(|| DbErr::RecordNotFound(format!("review {id}")))?;
        let stage: i32 = row.try_get("", "stage")?;
        let remember = row
            .try_get::<Option<i32>>("", "remember")?
            .map(|value| value != 0);
        let grant_expires: Option<i64> = row.try_get("", "grant_expires_at")?;
        let expired_after: i64 = row.try_get("", "expired_after")?;
        let time = chrono::Utc::now().timestamp();
        let status = match stage {
            0 if expired_after > time => ReviewStatus::Pending,
            0 | 3 => ReviewStatus::Expired,
            1 if remember == Some(false) => {
                if row.try_get::<Option<i64>>("", "consumed_at")?.is_some() {
                    ReviewStatus::Consumed
                } else if row.try_get::<Option<i64>>("", "invalidated_at")?.is_some()
                    || grant_expires.is_none_or(|expires| expires <= time)
                {
                    ReviewStatus::Expired
                } else {
                    ReviewStatus::Allowed
                }
            }
            1 => ReviewStatus::Allowed,
            2 => ReviewStatus::Denied,
            _ => return Err(DbErr::Type(format!("invalid review stage {stage}"))),
        };
        Ok((
            status,
            remember,
            if remember == Some(false) && stage == 1 {
                grant_expires
            } else {
                Some(expired_after)
            },
        ))
    }
}

#[derive(Debug)]
pub enum AuthResult {
    Allowed,
    Denied,
    Reviewing(PendingReview),
    Waiting(crate::LiveReview),
}

impl From<PolicyError> for DbErr {
    fn from(error: PolicyError) -> Self {
        Self::Type(error.to_string())
    }
}

#[cfg(test)]
mod tests {
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
                .execute_unprepared(
                    "INSERT INTO module (module_name, version) VALUES ('another', 0)"
                )
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
}
