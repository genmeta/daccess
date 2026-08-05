use std::collections::BTreeMap;

use sea_orm::{
    ConnectionTrait, DatabaseBackend, DbErr, Order, Statement, TransactionTrait, TryGetable,
};
use serde::{Deserialize, Serialize};

use crate::{
    AccessService, ContactStatus, Effect, Grantee, Method, SubjectId,
    pagination::{Page, PageQuery, order_sql},
    policy::database_api,
};

const MAX_DESCRIPTION_CHARS: usize = 80;

pub type RequestedAccess = BTreeMap<String, Vec<Method>>;
pub type GrantedAccess = BTreeMap<String, GrantedMethods>;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantedMethods {
    #[serde(default)]
    pub allow: Vec<Method>,
    #[serde(default)]
    pub review: Vec<Method>,
    #[serde(default)]
    pub deny: Vec<Method>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewContact {
    pub name: String,
    pub subject_id: SubjectId,
    pub class: String,
    pub description: String,
    pub requested_access: RequestedAccess,
    pub offers: GrantedAccess,
    pub created_at: i64,
    pub updated_at: i64,
    pub expired_after: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContactPatch {
    LocalUpdate {
        status: Option<ContactStatus>,
        alias: Option<String>,
    },
    GrantedUpdate {
        granted_access: GrantedAccess,
        modified_since: i64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactRecord {
    pub name: String,
    pub subject_id: SubjectId,
    pub alias: Option<String>,
    pub class: String,
    pub description: String,
    pub status: i32,
    pub created_at: i64,
    pub updated_at: i64,
    pub expired_after: i64,
    pub requested_access: RequestedAccess,
    pub granted_access: GrantedAccess,
    pub offers: GrantedAccess,
}

#[derive(Deserialize)]
pub(crate) struct NewContactBody {
    name: String,
    subject_id: String,
    #[serde(default)]
    class: String,
    description: String,
    #[serde(default)]
    requested_access: RequestedAccess,
    #[serde(default)]
    offers: GrantedAccess,
    created_at: i64,
    updated_at: i64,
    expired_after: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalContactPatchBody {
    status: Option<ContactStatus>,
    alias: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantedUpdateBody {
    granted_access: GrantedAccess,
}

#[derive(Serialize)]
pub(crate) struct ContactBody {
    name: String,
    subject_id: String,
    alias: Option<String>,
    class: String,
    description: String,
    status: i32,
    created_at: i64,
    updated_at: i64,
    expired_after: i64,
    requested_access: RequestedAccess,
    granted_access: GrantedAccess,
    offers: GrantedAccess,
}

#[derive(Deserialize)]
pub(crate) struct DeleteContactsBody {
    names: Vec<String>,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Sort {
    #[serde(alias = "names")]
    Name,
    Alias,
    #[default]
    UpdatedAt,
    CreatedAt,
    Class,
}

impl Sort {
    fn column(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Alias => "alias",
            Self::UpdatedAt => "updated_at",
            Self::CreatedAt => "created_at",
            Self::Class => "class",
        }
    }
}

impl AccessService {
    pub async fn create_contact(&self, contact: NewContact) -> Result<(), DbErr> {
        validate_description_length(&contact.description)?;
        validate_application_times(
            contact.created_at,
            contact.updated_at,
            contact.expired_after,
        )?;
        let requests = encode_requested_access(&contact.requested_access)?;
        let offers = encode_granted_access(&contact.offers)?;
        let mut policies = self.policies.write().await;
        let transaction = self.db.begin().await?;
        expire_pending_contacts(&transaction, Some(&contact.name)).await?;
        let result = transaction
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                r#"INSERT INTO contacts
                   (name, subject_id, class, offers, requests, description, status, expired_after, updated_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET
                       subject_id = excluded.subject_id,
                       class = excluded.class,
                       offers = excluded.offers,
                       requests = excluded.requests,
                       description = excluded.description,
                       expired_after = excluded.expired_after,
                       updated_at = excluded.updated_at,
                       created_at = excluded.created_at
                   WHERE contacts.status IN (2, 3)"#,
                [
                    contact.name.clone().into(),
                    contact.subject_id.as_bytes().to_vec().into(),
                    contact.class.into(),
                    offers.into(),
                    requests.into(),
                    contact.description.into(),
                    contact.expired_after.into(),
                    contact.updated_at.into(),
                    contact.created_at.into(),
                ],
            ))
            .await?;
        require_contact_update(&transaction, result.rows_affected(), &contact.name).await?;
        upsert_exact_rule(
            &transaction,
            &contact.name,
            &Method::Specified(http::Method::PATCH),
            "/contact",
            Effect::Allow,
        )
        .await?;
        transaction.commit().await?;
        policies.modify(
            Method::Specified(http::Method::PATCH),
            "/contact",
            Effect::Allow,
            Grantee::One(contact.name.clone()),
        );
        self.contacts
            .write()
            .await
            .insert(contact.name, contact.subject_id);
        Ok(())
    }

    pub async fn find_contact_by_name(&self, name: &str) -> Result<ContactRecord, DbErr> {
        expire_pending_contacts(&self.db, Some(name)).await?;
        let row = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT name, subject_id, alias, class, description, status, expired_after, updated_at, created_at, requests, grants, offers FROM contacts WHERE name = ?",
                [name.into()],
            ))
            .await?
            .ok_or_else(|| DbErr::RecordNotFound(format!("contact {name:?}")))?;
        decode_contact(row)
    }

    async fn list_contacts(
        &self,
        offset: i64,
        limit: i64,
        sort: Sort,
        order: Order,
    ) -> Result<(u64, Vec<ContactRecord>), DbErr> {
        expire_pending_contacts(&self.db, None).await?;
        let total = self
            .db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS total FROM contacts",
            ))
            .await?
            .expect("aggregate query always returns one row");
        let total = i64::try_get(&total, "", "total")? as u64;
        let tie_breaker = if matches!(sort, Sort::Name) {
            ""
        } else {
            ", name ASC"
        };
        let sql = format!(
            "SELECT name, subject_id, alias, class, description, status, expired_after, updated_at, created_at, requests, grants, offers FROM contacts \
             ORDER BY {} {}{} LIMIT ? OFFSET ?",
            sort.column(),
            order_sql(&order),
            tie_breaker,
        );
        let contacts = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                sql,
                [limit.into(), offset.into()],
            ))
            .await?
            .into_iter()
            .map(decode_contact)
            .collect::<Result<_, _>>()?;
        Ok((total, contacts))
    }

    pub async fn patch_contact(&self, name: &str, patch: ContactPatch) -> Result<(), DbErr> {
        let changes_policies = matches!(
            &patch,
            ContactPatch::GrantedUpdate { .. }
                | ContactPatch::LocalUpdate {
                    status: Some(ContactStatus::Blocked | ContactStatus::Active),
                    ..
                }
        );
        let mut policies = if changes_policies {
            Some(self.policies.write().await)
        } else {
            None
        };
        let transaction = self.db.begin().await?;
        expire_pending_contacts(&transaction, Some(name)).await?;
        let mut removed_rules = Vec::new();
        let mut added_rules = Vec::new();
        match patch {
            ContactPatch::GrantedUpdate {
                granted_access,
                modified_since,
            } => {
                let offers = transaction
                    .query_one_raw(Statement::from_sql_and_values(
                        DatabaseBackend::Sqlite,
                        "SELECT offers FROM contacts WHERE name = ?",
                        [name.into()],
                    ))
                    .await?
                    .ok_or_else(|| DbErr::RecordNotFound(format!("contact {name:?}")))?;
                let offers = decode_granted_access(String::try_get(&offers, "", "offers")?)?;
                let grants = encode_granted_access(&granted_access)?;
                let result = transaction
                    .execute_raw(Statement::from_sql_and_values(
                        DatabaseBackend::Sqlite,
                        format!(
                            "UPDATE contacts SET grants = ?, offers = '{{}}', status = 2 \
                         WHERE name = ? AND (status IN (2, 3) OR \
                           (status IN (0, {}) AND ? < expired_after))",
                            ContactStatus::Expired as i32
                        ),
                        [grants.into(), name.into(), modified_since.into()],
                    ))
                    .await?;
                require_contact_update(&transaction, result.rows_affected(), name).await?;
                added_rules = granted_rules(&offers);
                for (method, api, effect) in &added_rules {
                    upsert_exact_rule(&transaction, name, method, api, *effect).await?;
                }
            }
            ContactPatch::LocalUpdate { status, alias } => {
                let row = transaction
                    .query_one_raw(Statement::from_sql_and_values(
                        DatabaseBackend::Sqlite,
                        "SELECT status, offers FROM contacts WHERE name = ?",
                        [name.into()],
                    ))
                    .await?
                    .ok_or_else(|| DbErr::RecordNotFound(format!("contact {name:?}")))?;
                let old_status = i32::try_get(&row, "", "status")?;
                let old_status = ContactStatus::try_from(old_status)
                    .map_err(|_| DbErr::Type(format!("contact has invalid status {old_status}")))?;
                match (old_status, status) {
                    (
                        ContactStatus::Pending
                        | ContactStatus::Syncing
                        | ContactStatus::Active
                        | ContactStatus::Transfered,
                        Some(ContactStatus::Syncing),
                    ) => {
                        let result = transaction
                            .execute_raw(Statement::from_sql_and_values(
                                DatabaseBackend::Sqlite,
                                "UPDATE contacts SET status = 1 WHERE name = ?",
                                [name.into()],
                            ))
                            .await?;
                        require_contact_update(&transaction, result.rows_affected(), name).await?;
                    }
                    (
                        ContactStatus::Active | ContactStatus::Transfered,
                        Some(ContactStatus::Blocked),
                    ) => {
                        let snapshot = collect_granted_access(&transaction, name).await?;
                        removed_rules = query_exact_rules(&transaction, name).await?;
                        transaction
                            .execute_raw(Statement::from_sql_and_values(
                                DatabaseBackend::Sqlite,
                                "DELETE FROM access_rules WHERE grantee_type = 0 AND grantee = ?",
                                [name.into()],
                            ))
                            .await?;
                        for method in [http::Method::POST, http::Method::PATCH] {
                            let method = Method::Specified(method);
                            upsert_exact_rule(
                                &transaction,
                                name,
                                &method,
                                "/contact",
                                Effect::Deny,
                            )
                            .await?;
                            added_rules.push((method, String::from("/contact"), Effect::Deny));
                        }
                        transaction
                            .execute_raw(Statement::from_sql_and_values(
                                DatabaseBackend::Sqlite,
                                "UPDATE contacts SET offers = ?, status = 5 WHERE name = ?",
                                [encode_granted_access(&snapshot)?.into(), name.into()],
                            ))
                            .await?;
                        Self::validate_management_administrators(&transaction, &self.owner_name)
                            .await?;
                    }
                    (ContactStatus::Blocked, Some(ContactStatus::Active)) => {
                        let snapshot = decode_granted_access(String::try_get(&row, "", "offers")?)?;
                        removed_rules = query_exact_rules(&transaction, name).await?;
                        transaction
                            .execute_raw(Statement::from_sql_and_values(
                                DatabaseBackend::Sqlite,
                                "DELETE FROM access_rules WHERE grantee_type = 0 AND grantee = ?",
                                [name.into()],
                            ))
                            .await?;
                        added_rules = granted_rules(&snapshot);
                        for (method, api, effect) in &added_rules {
                            upsert_exact_rule(&transaction, name, method, api, *effect).await?;
                        }
                        transaction
                            .execute_raw(Statement::from_sql_and_values(
                                DatabaseBackend::Sqlite,
                                "UPDATE contacts SET offers = '{}', status = 2 WHERE name = ?",
                                [name.into()],
                            ))
                            .await?;
                    }
                    (
                        _,
                        Some(
                            ContactStatus::Pending
                            | ContactStatus::Transfered
                            | ContactStatus::Expired,
                        ),
                    ) => {
                        return Err(DbErr::Type(String::from(
                            "contact status must be syncing, blocked, or active",
                        )));
                    }
                    (_, Some(_)) => return Err(DbErr::RecordNotUpdated),
                    (_, None) => {}
                }
                if let Some(alias) = alias {
                    let result = if alias.is_empty() {
                        transaction
                            .execute_raw(Statement::from_sql_and_values(
                                DatabaseBackend::Sqlite,
                                "UPDATE contacts SET alias = NULL WHERE name = ?",
                                [name.into()],
                            ))
                            .await?
                    } else {
                        transaction
                            .execute_raw(Statement::from_sql_and_values(
                                DatabaseBackend::Sqlite,
                                "UPDATE contacts SET alias = ? WHERE name = ?",
                                [alias.into(), name.into()],
                            ))
                            .await?
                    };
                    require_contact(result.rows_affected(), name)?;
                }
            }
        }
        transaction.commit().await?;
        if let Some(policies) = policies.as_mut() {
            let grantee = Grantee::One(name.to_owned());
            for (method, api) in removed_rules {
                policies.remove(method, &api, grantee.clone());
            }
            for (method, api, effect) in added_rules {
                policies.modify(method, &api, effect, grantee.clone());
            }
        }
        Ok(())
    }

    async fn activate_contact(&self, name: &str) -> Result<(), DbErr> {
        let result = self
            .db
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE contacts SET grants = offers, offers = '{}', status = 2 WHERE name = ? AND status = 1",
                [name.into()],
            ))
            .await?;
        require_contact(result.rows_affected(), name)
    }

    pub async fn delete_contacts(&self, names: &[String]) -> Result<(), DbErr> {
        let mut policies = self.policies.write().await;
        let transaction = self.db.begin().await?;
        let mut removed_rules = Vec::new();
        for name in names {
            removed_rules.push((name.clone(), query_exact_rules(&transaction, name).await?));
            let result = transaction
                .execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "DELETE FROM contacts WHERE name = ?",
                    [name.as_str().into()],
                ))
                .await?;
            require_contact(result.rows_affected(), name)?;
        }
        Self::validate_management_administrators(&transaction, &self.owner_name).await?;
        transaction.commit().await?;
        let mut contacts = self.contacts.write().await;
        for name in names {
            contacts.remove(name);
        }
        drop(contacts);
        for (name, rules) in removed_rules {
            let grantee = Grantee::One(name);
            for (method, api) in rules {
                policies.remove(method, &api, grantee.clone());
            }
        }
        Ok(())
    }
}

fn granted_rules(access: &GrantedAccess) -> Vec<(Method, String, Effect)> {
    let mut rules = Vec::new();
    for (api, methods) in access {
        for (effect, methods) in [
            (Effect::Allow, &methods.allow),
            (Effect::Review, &methods.review),
            (Effect::Deny, &methods.deny),
        ] {
            rules.extend(
                methods
                    .iter()
                    .cloned()
                    .map(|method| (method, api.clone(), effect)),
            );
        }
    }
    rules
}

async fn upsert_exact_rule(
    db: &impl ConnectionTrait,
    name: &str,
    method: &Method,
    api: &str,
    effect: Effect,
) -> Result<(), DbErr> {
    db.execute_raw(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        r#"INSERT INTO access_rules
           (method, api, effect, grantee_type, grantee, updated_at, created_at)
           VALUES (?, ?, ?, 0, ?,
                   CAST(strftime('%s', 'now') AS INTEGER),
                   CAST(strftime('%s', 'now') AS INTEGER))
           ON CONFLICT(grantee, method, api) DO UPDATE SET
               effect = excluded.effect,
               grantee_type = excluded.grantee_type,
               updated_at = excluded.updated_at"#,
        [
            method.to_string().into(),
            database_api(api).into(),
            effect.as_str().into(),
            name.into(),
        ],
    ))
    .await?;
    Ok(())
}

fn require_contact(rows_affected: u64, name: &str) -> Result<(), DbErr> {
    (rows_affected != 0)
        .then_some(())
        .ok_or_else(|| DbErr::RecordNotFound(format!("contact {name:?}")))
}

async fn require_contact_update(
    db: &impl ConnectionTrait,
    rows_affected: u64,
    name: &str,
) -> Result<(), DbErr> {
    if rows_affected != 0 {
        return Ok(());
    }
    let exists = db
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT 1 FROM contacts WHERE name = ?",
            [name.into()],
        ))
        .await?
        .is_some();
    if exists {
        Err(DbErr::RecordNotUpdated)
    } else {
        Err(DbErr::RecordNotFound(format!("contact {name:?}")))
    }
}

async fn expire_pending_contacts(
    db: &impl ConnectionTrait,
    name: Option<&str>,
) -> Result<(), DbErr> {
    let now = "CAST(strftime('%s', 'now') AS INTEGER)";
    let expired = ContactStatus::Expired as i32;
    let statement = match name {
        Some(name) => Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            format!(
                "UPDATE contacts SET status = {expired} \
                 WHERE name = ? AND status = 0 AND expired_after <= {now}"
            ),
            [name.into()],
        ),
        None => Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "UPDATE contacts SET status = {expired} \
                 WHERE status = 0 AND expired_after <= {now}"
            ),
        ),
    };
    db.execute_raw(statement).await?;
    Ok(())
}

fn validate_description_length(description: &str) -> Result<(), DbErr> {
    if description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(DbErr::Type(format!(
            "contact description must not exceed {MAX_DESCRIPTION_CHARS} characters"
        )));
    }
    Ok(())
}

fn validate_application_times(
    created_at: i64,
    updated_at: i64,
    expired_after: i64,
) -> Result<(), DbErr> {
    if created_at > updated_at || updated_at >= expired_after {
        return Err(DbErr::Type(String::from(
            "contact timestamps must satisfy created_at <= updated_at < expired_after",
        )));
    }
    Ok(())
}

fn parse_modified_since(headers: &http::HeaderMap) -> Result<i64, crate::api::ApiError> {
    let value = headers
        .get(http::header::IF_MODIFIED_SINCE)
        .ok_or_else(|| crate::api::bad_request("If-Modified-Since header is required"))?
        .to_str()
        .map_err(crate::api::bad_request)?;
    chrono::DateTime::parse_from_rfc2822(value)
        .map(|date| date.timestamp())
        .map_err(|_| crate::api::bad_request("If-Modified-Since must be a valid HTTP-date"))
}

async fn query_exact_rules(
    db: &impl ConnectionTrait,
    name: &str,
) -> Result<Vec<(Method, String)>, DbErr> {
    db.query_all_raw(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT method, api FROM access_rules WHERE grantee = ?",
        [name.into()],
    ))
    .await?
    .into_iter()
    .map(|row| {
        Ok((
            String::try_get(&row, "", "method")?.parse()?,
            String::try_get(&row, "", "api")?,
        ))
    })
    .collect()
}

async fn collect_granted_access(
    db: &impl ConnectionTrait,
    name: &str,
) -> Result<GrantedAccess, DbErr> {
    let rows = db
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT method, api, effect FROM access_rules \
             WHERE grantee_type = 0 AND grantee = ? \
             ORDER BY api, effect, method",
            [name.into()],
        ))
        .await?;
    let mut access = GrantedAccess::new();
    for row in rows {
        let method = String::try_get(&row, "", "method")?.parse()?;
        let api = String::try_get(&row, "", "api")?;
        let effect = String::try_get(&row, "", "effect")?.parse()?;
        let methods = access.entry(api).or_default();
        match effect {
            Effect::Allow => methods.allow.push(method),
            Effect::Review => methods.review.push(method),
            Effect::Deny => methods.deny.push(method),
        }
    }
    Ok(access)
}

fn normalize_requested_access(access: &RequestedAccess) -> Result<RequestedAccess, DbErr> {
    let mut normalized = RequestedAccess::new();
    for (api, source) in access {
        if !api.starts_with('/') {
            return Err(DbErr::Type(format!("invalid access API {api:?}")));
        }
        let api = database_api(api);
        let methods = normalized.entry(api.clone()).or_default();
        for method in source {
            if methods.contains(method) {
                return Err(DbErr::Type(format!(
                    "duplicate requested access {} {api:?}",
                    method.to_string()
                )));
            }
            methods.push(method.clone());
        }
    }
    Ok(normalized)
}

fn normalize_granted_access(access: &GrantedAccess) -> Result<GrantedAccess, DbErr> {
    let mut normalized = GrantedAccess::new();
    for (api, source) in access {
        if !api.starts_with('/') {
            return Err(DbErr::Type(format!("invalid access API {api:?}")));
        }
        let api = database_api(api);
        let methods = normalized.entry(api.clone()).or_default();
        for (effect, source) in [
            (Effect::Allow, &source.allow),
            (Effect::Review, &source.review),
            (Effect::Deny, &source.deny),
        ] {
            for method in source {
                if methods.allow.contains(method)
                    || methods.review.contains(method)
                    || methods.deny.contains(method)
                {
                    return Err(DbErr::Type(format!(
                        "duplicate granted access {} {api:?}",
                        method.to_string()
                    )));
                }
                match effect {
                    Effect::Allow => methods.allow.push(method.clone()),
                    Effect::Review => methods.review.push(method.clone()),
                    Effect::Deny => methods.deny.push(method.clone()),
                }
            }
        }
    }
    Ok(normalized)
}

fn encode_requested_access(access: &RequestedAccess) -> Result<String, DbErr> {
    serde_json::to_string(&normalize_requested_access(access)?)
        .map_err(|error| DbErr::Type(error.to_string()))
}

fn encode_granted_access(access: &GrantedAccess) -> Result<String, DbErr> {
    serde_json::to_string(&normalize_granted_access(access)?)
        .map_err(|error| DbErr::Type(error.to_string()))
}

fn decode_requested_access(value: String) -> Result<RequestedAccess, DbErr> {
    let access = serde_json::from_str(&value).map_err(|error| DbErr::Type(error.to_string()))?;
    normalize_requested_access(&access)
}

fn decode_granted_access(value: String) -> Result<GrantedAccess, DbErr> {
    let access = serde_json::from_str(&value).map_err(|error| DbErr::Type(error.to_string()))?;
    normalize_granted_access(&access)
}

fn decode_contact(row: sea_orm::QueryResult) -> Result<ContactRecord, DbErr> {
    let subject_id = SubjectId::new(Vec::<u8>::try_get(&row, "", "subject_id")?)
        .map_err(|_| DbErr::Type(String::from("contact subject_id is invalid")))?;
    Ok(ContactRecord {
        name: String::try_get(&row, "", "name")?,
        subject_id,
        alias: Option::<String>::try_get(&row, "", "alias")?,
        class: String::try_get(&row, "", "class")?,
        description: String::try_get(&row, "", "description")?,
        status: i32::try_get(&row, "", "status")?,
        created_at: i64::try_get(&row, "", "created_at")?,
        updated_at: i64::try_get(&row, "", "updated_at")?,
        expired_after: i64::try_get(&row, "", "expired_after")?,
        requested_access: decode_requested_access(String::try_get(&row, "", "requests")?)?,
        granted_access: decode_granted_access(String::try_get(&row, "", "grants")?)?,
        offers: decode_granted_access(String::try_get(&row, "", "offers")?)?,
    })
}

pub(crate) async fn create(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    visitor: Option<axum::Extension<crate::Visitor>>,
    axum::Json(body): axum::Json<NewContactBody>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    let visitor = visitor
        .as_ref()
        .ok_or_else(|| crate::api::bad_request("verified visitor identity is required"))?;
    if body.name == state.service.owner_name.as_str() {
        return Err(crate::api::bad_request(
            "profile owner cannot be created as a contact",
        ));
    }
    if body.name != visitor.name() {
        return Err(crate::api::bad_request(
            "contact name must match the verified visitor",
        ));
    }
    validate_description_length(&body.description).map_err(crate::api::database)?;
    let subject_id = SubjectId::new(body.subject_id.into_bytes()).map_err(|_| {
        (
            http::StatusCode::BAD_REQUEST,
            String::from("invalid subject_id"),
        )
    })?;
    if &subject_id != visitor.subject_id() {
        return Err(crate::api::bad_request(
            "contact subject_id must match the verified visitor",
        ));
    }
    let contact = NewContact {
        name: body.name,
        subject_id,
        class: body.class,
        description: body.description,
        requested_access: validate_requested_access(body.requested_access)?,
        offers: validate_granted_access(body.offers)?,
        created_at: body.created_at,
        updated_at: body.updated_at,
        expired_after: body.expired_after,
    };
    state
        .service
        .create_contact(contact)
        .await
        .map_err(crate::api::database)?;
    Ok(http::StatusCode::CREATED)
}

pub(crate) async fn list(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Query(query): axum::extract::Query<PageQuery<Sort>>,
) -> Result<axum::Json<Page<Vec<ContactBody>>>, crate::api::ApiError> {
    let pagination = query.pagination();
    let (offset, limit) = pagination.offset_limit()?;
    let (total, contacts) = state
        .service
        .list_contacts(offset, limit, query.sort, query.order)
        .await
        .map_err(crate::api::database)?;
    Ok(axum::Json(Page::new(
        contacts.into_iter().map(ContactBody::from).collect(),
        total,
        pagination,
    )))
}

pub(crate) async fn get(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<axum::Json<ContactBody>, crate::api::ApiError> {
    state
        .service
        .find_contact_by_name(&name)
        .await
        .map(ContactBody::from)
        .map(axum::Json)
        .map_err(crate::api::database)
}

pub(crate) async fn patch(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    visitor: Option<axum::Extension<crate::Visitor>>,
    axum::Json(body): axum::Json<LocalContactPatchBody>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    visitor
        .as_ref()
        .ok_or_else(|| crate::api::bad_request("verified visitor identity is required"))?;
    if body.status.is_none() && body.alias.is_none() {
        return Err(crate::api::bad_request(
            "contact patch requires status or alias",
        ));
    }
    let status = body.status;
    let contact = if status == Some(ContactStatus::Syncing) {
        Some(
            state
                .service
                .find_contact_by_name(&name)
                .await
                .map_err(crate::api::database)?,
        )
    } else {
        None
    };
    state
        .service
        .patch_contact(
            &name,
            ContactPatch::LocalUpdate {
                status,
                alias: body.alias,
            },
        )
        .await
        .map_err(crate::api::database)?;
    let Some(contact) = contact else {
        return Ok(http::StatusCode::NO_CONTENT);
    };
    let granted_access = collect_granted_access(&state.service.db, &name)
        .await
        .map_err(crate::api::database)?;
    let notification =
        serde_json::to_vec(&GrantedUpdateBody { granted_access }).map_err(crate::api::internal)?;
    let notifier = state.notifier.as_ref().ok_or_else(|| {
        (
            http::StatusCode::SERVICE_UNAVAILABLE,
            String::from("contact notification is unavailable"),
        )
    })?;
    notifier
        .granted_update(&name, contact.updated_at, notification)
        .await
        .map_err(|error| (http::StatusCode::BAD_GATEWAY, error.to_string()))?;
    state
        .service
        .activate_contact(&name)
        .await
        .map_err(crate::api::database)?;
    Ok(http::StatusCode::NO_CONTENT)
}

pub(crate) async fn apply_granted_update(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    visitor: Option<axum::Extension<crate::Visitor>>,
    headers: http::HeaderMap,
    axum::Json(body): axum::Json<GrantedUpdateBody>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    let name = visitor
        .as_ref()
        .map(|identity| identity.name())
        .ok_or_else(|| crate::api::bad_request("verified visitor identity is required"))?;
    let modified_since = parse_modified_since(&headers)?;
    state
        .service
        .patch_contact(
            name,
            ContactPatch::GrantedUpdate {
                granted_access: validate_granted_access(body.granted_access)?,
                modified_since,
            },
        )
        .await
        .map_err(crate::api::database)?;
    Ok(http::StatusCode::NO_CONTENT)
}

pub(crate) async fn delete(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    state
        .service
        .delete_contacts(std::slice::from_ref(&name))
        .await
        .map_err(crate::api::database)?;
    Ok(http::StatusCode::NO_CONTENT)
}

pub(crate) async fn delete_many(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::Json(body): axum::Json<DeleteContactsBody>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    state
        .service
        .delete_contacts(&body.names)
        .await
        .map_err(crate::api::database)?;
    Ok(http::StatusCode::NO_CONTENT)
}

fn validate_requested_access(
    access: RequestedAccess,
) -> Result<RequestedAccess, crate::api::ApiError> {
    normalize_requested_access(&access).map_err(crate::api::database)
}

fn validate_granted_access(access: GrantedAccess) -> Result<GrantedAccess, crate::api::ApiError> {
    normalize_granted_access(&access).map_err(crate::api::database)
}

impl From<ContactRecord> for ContactBody {
    fn from(value: ContactRecord) -> Self {
        Self {
            name: value.name,
            subject_id: String::from_utf8_lossy(value.subject_id.as_bytes()).into_owned(),
            alias: value.alias,
            class: value.class,
            description: value.description,
            status: value.status,
            created_at: value.created_at,
            updated_at: value.updated_at,
            expired_after: value.expired_after,
            requested_access: value.requested_access,
            granted_access: value.granted_access,
            offers: value.offers,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use http_body_util::BodyExt;
    use radix_trie::TrieCommon;
    use sea_orm::{ConnectionTrait, Database, TryGetable};
    use tower::ServiceExt;

    use super::*;

    const APPLICATION_CREATED_AT: i64 = 1_893_455_900;
    const APPLICATION_UPDATED_AT: i64 = 1_893_456_000;
    const APPLICATION_EXPIRED_AFTER: i64 = 1_893_715_200;
    const APPLICATION_UPDATED_HTTP_DATE: &str = "Tue, 01 Jan 2030 00:00:00 GMT";

    async fn service() -> AccessService {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(include_str!("../migrations/0.sql"))
            .await
            .unwrap();
        AccessService::new(db, "owner.example")
    }

    struct RecordingNotifier {
        service: Arc<AccessService>,
        fail: bool,
        notifications: Mutex<Vec<(String, i32, i64, GrantedUpdateBody)>>,
    }

    impl crate::api::ContactNotifier for RecordingNotifier {
        fn granted_update<'a>(
            &'a self,
            contact: &'a str,
            modified_since: i64,
            body: Vec<u8>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), crate::api::NotifyError>> + Send + 'a>,
        > {
            Box::pin(async move {
                let status = self.service.find_contact_by_name(contact).await?.status;
                let body = serde_json::from_slice(&body)?;
                self.notifications.lock().unwrap().push((
                    contact.to_owned(),
                    status,
                    modified_since,
                    body,
                ));
                if self.fail {
                    Err(Box::new(std::io::Error::other("peer rejected update"))
                        as crate::api::NotifyError)
                } else {
                    Ok(())
                }
            })
        }
    }

    fn request(
        method: http::Method,
        uri: &str,
        body: &'static str,
    ) -> http::Request<axum::body::Body> {
        http::Request::builder()
            .method(method)
            .uri(uri)
            .header(http::header::CONTENT_TYPE, "application/json")
            .header(
                http::header::IF_MODIFIED_SINCE,
                APPLICATION_UPDATED_HTTP_DATE,
            )
            .body(axum::body::Body::from(body))
            .unwrap()
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

    #[tokio::test]
    async fn create_stores_pending_contact_with_callback_rule() {
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
                "SELECT COUNT(*) count FROM access_rules",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(i64::try_get(&count, "", "count").unwrap(), 1);
    }

    #[tokio::test]
    async fn callback_rule_survives_application_expiry() {
        let service = service().await;
        service.create_contact(contact()).await.unwrap();

        assert_eq!(
            service
                .policies
                .read()
                .await
                .evaluate(
                    &http::Method::PATCH,
                    "/contact",
                    &[Grantee::One("alice.example".into())]
                )
                .0,
            Effect::Allow
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
                    "/contact",
                    &[Grantee::One("alice.example".into())]
                )
                .0,
            Effect::Allow
        );
    }

    #[tokio::test]
    async fn frozen_contacts_reject_repeated_applications() {
        for status in [0, 1, 4, 5] {
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
        assert_eq!(service.contacts.read().await.len(), 1);
    }

    #[tokio::test]
    async fn application_expiry_comes_from_the_sender_without_a_three_day_recalculation() {
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
                        status: Some(ContactStatus::Syncing),
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
    async fn expired_application_rejects_local_approval_but_accepts_timely_peer_approval() {
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
                "/contact/alice.example",
                r#"{"status":"syncing"}"#,
            ),
            "owner.example",
        );
        assert_eq!(
            app.clone().oneshot(local).await.unwrap().status(),
            http::StatusCode::CONFLICT
        );

        let mut peer = as_visitor(
            request(http::Method::PATCH, "/contact", r#"{"granted_access":{}}"#),
            "alice.example",
        );
        peer.headers_mut().insert(
            http::header::IF_MODIFIED_SINCE,
            http::HeaderValue::from_static("Thu, 01 Jan 1970 00:00:02 GMT"),
        );
        assert_eq!(
            app.oneshot(peer).await.unwrap().status(),
            http::StatusCode::NO_CONTENT
        );
        let stored = service.find_contact_by_name("alice.example").await.unwrap();
        assert_eq!(stored.status, 2);
        assert_eq!(stored.updated_at, 2);
    }

    #[tokio::test]
    async fn peer_approval_at_or_after_expiry_does_not_compensate() {
        let service = service().await;
        service.create_contact(contact()).await.unwrap();
        service
            .db
            .execute_unprepared(
                "UPDATE contacts SET created_at = 1, updated_at = 2, expired_after = 3 WHERE name = 'alice.example'",
            )
            .await
            .unwrap();
        let patch = ContactPatch::GrantedUpdate {
            granted_access: GrantedAccess::new(),
            modified_since: 3,
        };

        assert!(service.patch_contact("alice.example", patch).await.is_err());
        let stored = service.find_contact_by_name("alice.example").await.unwrap();
        assert_eq!(stored.status, 4);
        assert_eq!(stored.updated_at, 2);
    }

    #[tokio::test]
    async fn syncing_and_blocked_contacts_reject_peer_grant_updates() {
        for status in [1, 5] {
            let service = service().await;
            service.create_contact(contact()).await.unwrap();
            service
                .db
                .execute_unprepared(&format!(
                    "UPDATE contacts SET status = {status} WHERE name = 'alice.example'"
                ))
                .await
                .unwrap();
            let patch = ContactPatch::GrantedUpdate {
                granted_access: granted("/remote", Effect::Allow),
                modified_since: APPLICATION_UPDATED_AT,
            };

            assert!(service.patch_contact("alice.example", patch).await.is_err());
            let stored = service.find_contact_by_name("alice.example").await.unwrap();
            assert_eq!(stored.status, status);
            assert!(stored.granted_access.is_empty());
            assert_eq!(stored.offers, granted("/granted", Effect::Allow));
            assert_eq!(stored.updated_at, APPLICATION_UPDATED_AT);
        }
    }

    #[tokio::test]
    async fn peer_patch_requires_if_modified_since() {
        let service = Arc::new(service().await);
        service.create_contact(contact()).await.unwrap();
        let app = crate::api::router(service);
        let mut request = as_visitor(
            request(http::Method::PATCH, "/contact", r#"{"granted_access":{}}"#),
            "alice.example",
        );
        request
            .headers_mut()
            .remove(http::header::IF_MODIFIED_SINCE);

        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            http::StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn local_approval_marks_contact_syncing_without_changing_rules() {
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
                    status: Some(ContactStatus::Syncing),
                    alias: None,
                },
            )
            .await
            .unwrap();

        let stored = service.find_contact_by_name("alice.example").await.unwrap();
        assert_eq!(stored.status, 1);
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
        assert_eq!(rows.len(), 2);
        assert_eq!(String::try_get(&rows[0], "", "api").unwrap(), "/contact");
        assert_eq!(String::try_get(&rows[0], "", "method").unwrap(), "PATCH");
        assert_eq!(String::try_get(&rows[0], "", "effect").unwrap(), "allow");
        assert_eq!(String::try_get(&rows[1], "", "api").unwrap(), "/local");
        assert_eq!(String::try_get(&rows[1], "", "effect").unwrap(), "review");
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
    async fn granted_update_applies_stored_offers_and_is_idempotent() {
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
        let patch = ContactPatch::GrantedUpdate {
            granted_access: granted("/remote", Effect::Review),
            modified_since: APPLICATION_UPDATED_AT,
        };
        service
            .patch_contact("alice.example", patch.clone())
            .await
            .unwrap();
        service.patch_contact("alice.example", patch).await.unwrap();
        assert_eq!(
            service
                .find_contact_by_name("alice.example")
                .await
                .unwrap()
                .granted_access,
            granted("/remote", Effect::Review)
        );
        let rows = service
            .db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT api FROM access_rules WHERE grantee = 'alice.example' ORDER BY api",
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(String::try_get(&rows[0], "", "api").unwrap(), "/contact");
        assert_eq!(String::try_get(&rows[1], "", "api").unwrap(), "/granted");
        assert_eq!(String::try_get(&rows[2], "", "api").unwrap(), "/local");
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
                    status: Some(ContactStatus::Syncing),
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
    async fn http_contact_endpoints_cover_create_list_get_granted_update_and_batch_delete() {
        let service = Arc::new(service().await);
        let app = crate::api::router(service.clone());
        let owner = as_visitor(
            request(
                http::Method::POST,
                "/contact",
                r#"{"name":"owner.example","subject_id":"verified-subject","description":"Owner","created_at":1893455900,"updated_at":1893456000,"expired_after":1893715200}"#,
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
                "/contact",
                r#"{"name":"alice.example","subject_id":"verified-subject","class":"agent","description":"Alice","requested_access":{},"offers":{},"created_at":1893455900,"updated_at":1893456000,"expired_after":1893715200}"#,
            ),
            "alice.example",
        );
        assert_eq!(
            app.clone().oneshot(create).await.unwrap().status(),
            http::StatusCode::CREATED
        );
        let duplicate = as_visitor(
            request(
                http::Method::POST,
                "/contact",
                r#"{"name":"alice.example","subject_id":"verified-subject","class":"service","description":"Updated Alice","requested_access":{},"offers":{},"created_at":1893455900,"updated_at":1893456010,"expired_after":1893715200}"#,
            ),
            "alice.example",
        );
        assert_eq!(
            app.clone().oneshot(duplicate).await.unwrap().status(),
            http::StatusCode::CONFLICT
        );

        let get = request(http::Method::GET, "/contact/alice.example", "");
        let response = app.clone().oneshot(get).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["subject_id"], "verified-subject");
        assert_eq!(body["class"], "agent");
        assert_eq!(body["description"], "Alice");
        assert_eq!(body["status"], 0);
        assert_eq!(body["created_at"], APPLICATION_CREATED_AT);
        assert_eq!(body["updated_at"], APPLICATION_UPDATED_AT);
        assert_eq!(body["expired_after"], APPLICATION_EXPIRED_AFTER);

        let list = request(http::Method::GET, "/contacts", "");
        assert_eq!(
            app.clone().oneshot(list).await.unwrap().status(),
            http::StatusCode::OK
        );

        let anonymous = request(http::Method::PATCH, "/contact", r#"{"granted_access":{}}"#);
        assert_eq!(
            app.clone().oneshot(anonymous).await.unwrap().status(),
            http::StatusCode::BAD_REQUEST
        );
        let unknown = as_visitor(
            request(http::Method::PATCH, "/contact", r#"{"granted_access":{}}"#),
            "mallory.example",
        );
        assert_eq!(
            app.clone().oneshot(unknown).await.unwrap().status(),
            http::StatusCode::NOT_FOUND
        );
        let legacy = as_visitor(
            request(
                http::Method::PATCH,
                "/contact",
                r#"{"kind":"granted_update","granted_access":{}}"#,
            ),
            "alice.example",
        );
        assert_eq!(
            app.clone().oneshot(legacy).await.unwrap().status(),
            http::StatusCode::UNPROCESSABLE_ENTITY
        );

        let update = request(
            http::Method::PATCH,
            "/contact",
            r#"{"granted_access":{"/remote":{"review":["GET"]}}}"#,
        );
        assert_eq!(
            app.clone()
                .oneshot(as_visitor(update, "alice.example"))
                .await
                .unwrap()
                .status(),
            http::StatusCode::NO_CONTENT
        );
        assert_eq!(
            service
                .find_contact_by_name("alice.example")
                .await
                .unwrap()
                .granted_access,
            granted("/remote", Effect::Review)
        );

        let delete = request(
            http::Method::DELETE,
            "/contacts",
            r#"{"names":["alice.example"]}"#,
        );
        assert_eq!(
            app.clone().oneshot(delete).await.unwrap().status(),
            http::StatusCode::NO_CONTENT
        );
        assert!(service.find_contact_by_name("alice.example").await.is_err());
        let missing = request(http::Method::GET, "/contact/alice.example", "");
        assert_eq!(
            app.oneshot(missing).await.unwrap().status(),
            http::StatusCode::NOT_FOUND
        );
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
                    &format!("/contacts?page=1&page_size=1&sort={sort}&order=asc"),
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
                "/contacts?page=2&page_size=1&sort=name&order=asc",
                "",
            ))
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&second_page.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["items"][0]["name"], "bob.example");

        for (uri, expected) in [
            ("/contacts?page_size=1", "charlie.example"),
            (
                "/contacts?page_size=1&sort=name&order=desc",
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
            "/contacts?page=0",
            "/contacts?page_size=101",
            "/contacts?sort=unknown",
            "/contacts?order=sideways",
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
    async fn local_approval_marks_notifying_then_activates_after_peer_accepts() {
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
            .set_policy(
                Method::Specified(http::Method::POST),
                "/local",
                Effect::Review,
                Grantee::One("alice.example".into()),
            )
            .await
            .unwrap();
        service
            .set_policy(
                Method::Specified(http::Method::DELETE),
                "/local",
                Effect::Deny,
                Grantee::One("alice.example".into()),
            )
            .await
            .unwrap();
        let notifier = Arc::new(RecordingNotifier {
            service: service.clone(),
            fail: false,
            notifications: Mutex::new(Vec::new()),
        });
        let app = crate::api::router_with_notifier(service.clone(), Some(notifier.clone()));
        let approval = request(
            http::Method::PATCH,
            "/contact/alice.example",
            r#"{"status":"syncing"}"#,
        );
        assert_eq!(
            app.oneshot(as_visitor(approval, "admin.example"))
                .await
                .unwrap()
                .status(),
            http::StatusCode::NO_CONTENT
        );

        let notifications = notifier.notifications.lock().unwrap();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].0, "alice.example");
        assert_eq!(
            notifications[0].1, 1,
            "contact must remain retryable until notification succeeds"
        );
        assert_eq!(notifications[0].2, APPLICATION_UPDATED_AT);
        let granted_access = &notifications[0].3.granted_access;
        assert_eq!(granted_access.len(), 2);
        assert_eq!(
            granted_access["/contact"].allow,
            [Method::Specified(http::Method::PATCH)]
        );
        assert_eq!(
            granted_access["/local"].allow,
            [Method::Specified(http::Method::GET)]
        );
        assert_eq!(
            granted_access["/local"].review,
            [Method::Specified(http::Method::POST)]
        );
        assert_eq!(
            granted_access["/local"].deny,
            [Method::Specified(http::Method::DELETE)]
        );
        drop(notifications);

        let stored = service.find_contact_by_name("alice.example").await.unwrap();
        assert_eq!(stored.status, 2);
        assert_eq!(stored.requested_access, requested("/requested"));
        assert_eq!(stored.granted_access, granted("/granted", Effect::Allow));
    }

    #[tokio::test]
    async fn local_patch_requires_a_field_and_a_valid_transition() {
        let service = Arc::new(service().await);
        service.create_contact(contact()).await.unwrap();
        let app = crate::api::router(service);

        let anonymous = request(
            http::Method::PATCH,
            "/contact/alice.example",
            r#"{"status":"syncing"}"#,
        );
        assert_eq!(
            app.clone().oneshot(anonymous).await.unwrap().status(),
            http::StatusCode::BAD_REQUEST
        );

        for (body, expected) in [
            (r#"{}"#, http::StatusCode::BAD_REQUEST),
            (r#"{"status":"active"}"#, http::StatusCode::CONFLICT),
        ] {
            let approval = request(http::Method::PATCH, "/contact/alice.example", body);
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
            "/contact/alice.example",
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
            "/contact/alice.example",
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
            "/contact/alice.example",
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
            "/contact/alice.example",
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
                "/acl/review",
                Effect::Allow,
                Grantee::One("alice.example".into()),
            )
            .await
            .unwrap();
        service
            .set_policy(
                method.clone(),
                "/acl/review",
                Effect::Deny,
                Grantee::One("owner.example".into()),
            )
            .await
            .unwrap();
        let app = crate::api::router(service.clone());
        let block = request(
            http::Method::PATCH,
            "/contact/alice.example",
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
                    "/acl/review",
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
        let notifier = Arc::new(RecordingNotifier {
            service: service.clone(),
            fail: false,
            notifications: Mutex::new(Vec::new()),
        });
        let app = crate::api::router_with_notifier(service.clone(), Some(notifier.clone()));
        let approval = as_visitor(
            request(
                http::Method::PATCH,
                "/contact/alice.example",
                r#"{"status":"syncing"}"#,
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
        assert_eq!(notifier.notifications.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn failed_peer_notification_leaves_contact_syncing_and_retryable() {
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
        let notifier = Arc::new(RecordingNotifier {
            service: service.clone(),
            fail: true,
            notifications: Mutex::new(Vec::new()),
        });
        let app = crate::api::router_with_notifier(service.clone(), Some(notifier.clone()));
        let approval = request(
            http::Method::PATCH,
            "/contact/alice.example",
            r#"{"status":"syncing"}"#,
        );
        assert_eq!(
            app.clone()
                .oneshot(as_visitor(approval, "owner.example"))
                .await
                .unwrap()
                .status(),
            http::StatusCode::BAD_GATEWAY
        );

        let stored = service.find_contact_by_name("alice.example").await.unwrap();
        assert_eq!(stored.status, 1);
        assert_eq!(stored.requested_access, requested("/requested"));
        let rows = service
            .db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT api FROM access_rules WHERE grantee = 'alice.example' ORDER BY api",
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(String::try_get(&rows[0], "", "api").unwrap(), "/contact");
        assert_eq!(String::try_get(&rows[1], "", "api").unwrap(), "/local");

        let missing = request(
            http::Method::PATCH,
            "/contact/missing.example",
            r#"{"status":"syncing"}"#,
        );
        assert_eq!(
            app.oneshot(as_visitor(missing, "owner.example"))
                .await
                .unwrap()
                .status(),
            http::StatusCode::NOT_FOUND
        );
        assert_eq!(notifier.notifications.lock().unwrap().len(), 1);

        let retry_notifier = Arc::new(RecordingNotifier {
            service: service.clone(),
            fail: false,
            notifications: Mutex::new(Vec::new()),
        });
        let retry = crate::api::router_with_notifier(service.clone(), Some(retry_notifier.clone()));
        let approval = request(
            http::Method::PATCH,
            "/contact/alice.example",
            r#"{"status":"syncing"}"#,
        );
        assert_eq!(
            retry
                .oneshot(as_visitor(approval, "owner.example"))
                .await
                .unwrap()
                .status(),
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
        assert_eq!(retry_notifier.notifications.lock().unwrap().len(), 1);
    }
}
