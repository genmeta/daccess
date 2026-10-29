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
#[path = "../tests/unit/service.rs"]
mod tests;
