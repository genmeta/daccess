use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use sea_orm::{
    ConnectionTrait, DatabaseBackend, DbErr, Order, Statement, TransactionTrait, TryGetable,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AccessService, ContactStatus, Effect, Grantee, Method, SubjectId, Visitor,
    pagination::{Page, PageQuery, order_sql},
    policy::database_api,
};

const MAX_DESCRIPTION_CHARS: usize = 80;
const APPLICATION_LIFETIME_SECONDS: i64 = 7 * 86_400;

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

impl GrantedMethods {
    fn contains(&self, method: &Method) -> bool {
        self.allow.contains(method) || self.review.contains(method) || self.deny.contains(method)
    }

    fn push(&mut self, effect: Effect, method: Method) {
        match effect {
            Effect::Allow => self.allow.push(method),
            Effect::Review => self.review.push(method),
            Effect::Deny => self.deny.push(method),
        }
    }

    fn effect_methods(&self) -> [(Effect, &[Method]); 3] {
        [
            (Effect::Allow, &self.allow),
            (Effect::Review, &self.review),
            (Effect::Deny, &self.deny),
        ]
    }
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewContactBody {
    #[serde(rename = "from")]
    from_name: String,
    to: String,
    application_id: String,
    #[serde(default)]
    class: String,
    description: String,
    #[serde(default)]
    requested_access: RequestedAccess,
    #[serde(default)]
    offers: GrantedAccess,
}

#[derive(Serialize)]
pub(crate) struct ApplicationStatusBody {
    application_id: String,
    name: String,
    subject_id: String,
    status: String,
    received_at: i64,
    #[serde(rename = "valid_before")]
    expired_after: i64,
    granted_access: GrantedAccess,
}

struct ApplicationRecord {
    application_id: String,
    applicant_name: String,
    applicant_sid: Vec<u8>,
    payload_hash: String,
    status: String,
    received_at: i64,
    expired_after: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalContactPatchBody {
    status: Option<ContactStatus>,
    alias: Option<String>,
    expires_after: Option<i64>,
    valid_before: Option<i64>,
}

#[derive(Serialize)]
pub(crate) struct ContactBody {
    id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    incoming: Option<bool>,
    name: String,
    subject_id: String,
    alias: Option<String>,
    class: String,
    description: String,
    status: ContactStatus,
    created_at: i64,
    updated_at: i64,
    #[serde(rename = "valid_before")]
    expired_after: i64,
    requested_access: RequestedAccess,
    granted_access: GrantedAccess,
    offers: GrantedAccess,
}

#[derive(Serialize)]
pub(crate) struct SelfContactStatusBody {
    valid_before: i64,
    id: i64,
    name: String,
    subject_id: String,
    status: ContactStatus,
    granted_access: GrantedAccess,
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
        transaction.commit().await?;
        self.contacts
            .write()
            .await
            .insert(contact.name, contact.subject_id);
        Ok(())
    }

    async fn create_application(
        &self,
        contact: NewContact,
        application_id: &str,
        payload_hash: &str,
    ) -> Result<(ApplicationRecord, bool), DbErr> {
        validate_description_length(&contact.description)?;
        validate_application_times(
            contact.created_at,
            contact.updated_at,
            contact.expired_after,
        )?;
        let requests = encode_requested_access(&contact.requested_access)?;
        let offers = encode_granted_access(&contact.offers)?;
        let initial_status = ContactStatus::Pending as i32;
        let transaction = self.db.begin().await?;
        expire_pending_contacts(&transaction, Some(&contact.name)).await?;
        if let Some(row) = transaction.query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT application_id, applicant_name, applicant_sid, payload_hash, status, received_at, expired_after \
             FROM contact_applications WHERE application_id = ?",
            [application_id.into()],
        )).await? {
            let existing = decode_application(row)?;
            if existing.applicant_name != contact.name
                || existing.applicant_sid.as_slice() != contact.subject_id.as_bytes()
                || existing.payload_hash != payload_hash {
                return Err(DbErr::RecordNotUpdated);
            }
            transaction.commit().await?;
            return Ok((existing, false));
        }
        let previous = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT status, subject_id FROM contacts WHERE name = ?",
                [contact.name.as_str().into()],
            ))
            .await?;
        let previous_status = previous
            .as_ref()
            .map(|row| i32::try_get(row, "", "status"))
            .transpose()?;
        let previous_subject = previous
            .as_ref()
            .map(|row| Vec::<u8>::try_get(row, "", "subject_id"))
            .transpose()?;
        if previous_subject
            .as_deref()
            .is_some_and(|sid| sid != contact.subject_id.as_bytes())
        {
            return Err(DbErr::RecordNotUpdated);
        }
        if matches!(previous_status, Some(5)) {
            return Err(DbErr::RecordNotUpdated);
        }
        let result = transaction.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO contacts \
             (name, subject_id, class, offers, requests, description, status, expired_after, updated_at, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(name) DO UPDATE SET \
               subject_id = excluded.subject_id, class = excluded.class, offers = excluded.offers, \
               requests = excluded.requests, description = excluded.description, \
               status = CASE WHEN contacts.status IN (0, 4) THEN excluded.status ELSE contacts.status END, \
               expired_after = excluded.expired_after, updated_at = excluded.updated_at, \
               created_at = excluded.created_at \
             WHERE contacts.status IN (0, 2, 3, 4)",
            [
                contact.name.as_str().into(),
                contact.subject_id.as_bytes().to_vec().into(),
                contact.class.as_str().into(),
                offers.into(), requests.into(), contact.description.as_str().into(), initial_status.into(),
                contact.expired_after.into(), contact.updated_at.into(), contact.created_at.into(),
            ],
        )).await?;
        require_contact_update(&transaction, result.rows_affected(), &contact.name).await?;
        // A fresh application supersedes pending receipts, while retries of an
        // existing application_id return above without replacing the contact.
        transaction
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE contact_applications SET status = 'revoked' \
             WHERE applicant_name = ? AND status = 'pending'",
                [contact.name.as_str().into()],
            ))
            .await?;
        let status = if matches!(previous_status, Some(2 | 3))
            || initial_status == ContactStatus::Active as i32
        {
            "active"
        } else {
            "pending"
        };
        transaction.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO contact_applications \
             (application_id, applicant_name, applicant_sid, payload_hash, status, received_at, expired_after) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                application_id.into(), contact.name.as_str().into(),
                contact.subject_id.as_bytes().to_vec().into(), payload_hash.into(),
                status.into(), contact.created_at.into(), contact.expired_after.into(),
            ],
        )).await?;
        transaction.commit().await?;
        self.contacts
            .write()
            .await
            .insert(contact.name.clone(), contact.subject_id.clone());
        Ok((
            ApplicationRecord {
                application_id: application_id.to_owned(),
                applicant_name: contact.name,
                applicant_sid: contact.subject_id.as_bytes().to_vec(),
                payload_hash: payload_hash.to_owned(),
                status: status.to_owned(),
                received_at: contact.created_at,
                expired_after: contact.expired_after,
            },
            true,
        ))
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
        modified_since: Option<i64>,
        search: &str,
    ) -> Result<(u64, Vec<ContactBody>), DbErr> {
        expire_pending_contacts(&self.db, None).await?;
        let total = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                format!(
                    "SELECT COUNT(*) AS total FROM contacts WHERE {}",
                    CONTACT_FILTER
                ),
                [
                    modified_since.unwrap_or(0).into(),
                    search.into(),
                    search.into(),
                    search.into(),
                ],
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
            "SELECT id, name, subject_id, alias, class, description, status, expired_after, updated_at, created_at, requests, grants, offers, EXISTS(SELECT 1 FROM contact_applications a WHERE a.applicant_name = contacts.name AND a.applicant_sid = contacts.subject_id) AS incoming FROM contacts WHERE {CONTACT_FILTER} \
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
                [
                    modified_since.unwrap_or(0).into(),
                    search.into(),
                    search.into(),
                    search.into(),
                    limit.into(),
                    offset.into(),
                ],
            ))
            .await?
            .into_iter()
            .map(|row| {
                let id = row.try_get("", "id")?;
                let incoming = row.try_get::<i64>("", "incoming")? != 0;
                Ok::<_, DbErr>(contact_body(decode_contact(row)?, id, Some(incoming)))
            })
            .collect::<Result<_, _>>()?;
        Ok((total, contacts))
    }

    pub async fn patch_contact(&self, name: &str, patch: ContactPatch) -> Result<(), DbErr> {
        self.patch_contact_with_expiry(name, patch, None).await
    }

    async fn patch_contact_with_expiry(
        &self,
        name: &str,
        patch: ContactPatch,
        valid_before: Option<i64>,
    ) -> Result<(), DbErr> {
        let changes_policies = matches!(
            &patch,
            ContactPatch::LocalUpdate {
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
                        ContactStatus::Pending | ContactStatus::Transfered,
                        Some(ContactStatus::Active),
                    ) => {
                        let result = transaction
                            .execute_raw(Statement::from_sql_and_values(
                                DatabaseBackend::Sqlite,
                                "UPDATE contacts SET status = 2 WHERE name = ?",
                                [name.into()],
                            ))
                            .await?;
                        require_contact_update(&transaction, result.rows_affected(), name).await?;
                        transaction.execute_raw(Statement::from_sql_and_values(
                            DatabaseBackend::Sqlite,
                            "UPDATE contact_applications SET status = 'active' WHERE applicant_name = ? AND status = 'pending'",
                            [name.into()],
                        )).await?;
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
                        for method in [http::Method::POST] {
                            let method = Method::Specified(method);
                            upsert_exact_rule(
                                &transaction,
                                name,
                                &method,
                                "/std/contact",
                                Effect::Deny,
                            )
                            .await?;
                            added_rules.push((method, String::from("/std/contact"), Effect::Deny));
                        }
                        transaction
                            .execute_raw(Statement::from_sql_and_values(
                                DatabaseBackend::Sqlite,
                                "UPDATE contacts SET offers = ?, status = 5 WHERE name = ?",
                                [encode_granted_access(&snapshot)?.into(), name.into()],
                            ))
                            .await?;
                        transaction.execute_raw(Statement::from_sql_and_values(
                            DatabaseBackend::Sqlite,
                            "UPDATE contact_applications SET status = 'revoked' WHERE applicant_name = ? AND status = 'active'",
                            [name.into()],
                        )).await?;
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
                            "contact status must be active or blocked",
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
        if let Some(expires) = valid_before {
            let result = transaction
                .execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE contacts SET expired_after = ? WHERE name = ?",
                    [expires.into(), name.into()],
                ))
                .await?;
            require_contact(result.rows_affected(), name)?;
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

    pub async fn delete_contacts(&self, names: &[String]) -> Result<(), DbErr> {
        let mut policies = self.policies.write().await;
        let transaction = self.db.begin().await?;
        let mut removed_rules = Vec::new();
        for name in names {
            removed_rules.push((name.clone(), query_exact_rules(&transaction, name).await?));
            transaction.execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE contact_applications SET status = CASE WHEN status = 'pending' THEN 'denied' ELSE 'revoked' END WHERE applicant_name = ? AND status IN ('pending', 'active')",
                [name.as_str().into()],
            )).await?;
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
        for (effect, methods) in methods.effect_methods() {
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

pub(crate) async fn upsert_exact_rule(
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
    let application_statement = match name {
        Some(name) => Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            format!(
                "UPDATE contact_applications SET status = 'expired' WHERE applicant_name = ? AND status = 'pending' AND expired_after <= {now}"
            ),
            [name.into()],
        ),
        None => Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "UPDATE contact_applications SET status = 'expired' WHERE status = 'pending' AND expired_after <= {now}"
            ),
        ),
    };
    db.execute_raw(application_statement).await?;
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
        methods.push(effect, method);
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
        for (effect, source) in source.effect_methods() {
            for method in source {
                if methods.contains(method) {
                    return Err(DbErr::Type(format!(
                        "duplicate granted access {} {api:?}",
                        method.to_string()
                    )));
                }
                methods.push(effect, method.clone());
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

fn decode_application(row: sea_orm::QueryResult) -> Result<ApplicationRecord, DbErr> {
    Ok(ApplicationRecord {
        application_id: String::try_get(&row, "", "application_id")?,
        applicant_name: String::try_get(&row, "", "applicant_name")?,
        applicant_sid: Vec::<u8>::try_get(&row, "", "applicant_sid")?,
        payload_hash: String::try_get(&row, "", "payload_hash")?,
        status: String::try_get(&row, "", "status")?,
        received_at: i64::try_get(&row, "", "received_at")?,
        expired_after: i64::try_get(&row, "", "expired_after")?,
    })
}

fn validate_application_id(id: &str) -> Result<(), crate::api::ApiError> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(crate::api::bad_request("invalid application_id"));
    }
    Ok(())
}

fn application_time() -> Result<i64, crate::api::ApiError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| crate::api::internal("invalid system clock"))?;
    i64::try_from(duration.as_secs()).map_err(|_| crate::api::internal("invalid system clock"))
}

async fn application_response(
    service: &AccessService,
    record: ApplicationRecord,
) -> Result<ApplicationStatusBody, crate::api::ApiError> {
    let subject_id = service
        .contacts
        .read()
        .await
        .get(service.owner_name.as_str())
        .map(|sid| String::from_utf8_lossy(sid.as_bytes()).into_owned())
        .ok_or_else(|| crate::api::internal("receiver identity unavailable"))?;
    let granted_access = if record.status == "active" {
        collect_granted_access(&service.db, &record.applicant_name)
            .await
            .map_err(crate::api::database)?
    } else {
        GrantedAccess::new()
    };
    Ok(ApplicationStatusBody {
        application_id: record.application_id,
        name: service.owner_name.clone(),
        subject_id,
        status: record.status,
        received_at: record.received_at,
        expired_after: record.expired_after,
        granted_access,
    })
}

pub(crate) async fn create(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    visitor: Option<axum::Extension<crate::Visitor>>,
    axum::Json(body): axum::Json<NewContactBody>,
) -> Result<(http::StatusCode, axum::Json<ApplicationStatusBody>), crate::api::ApiError> {
    let visitor = visitor
        .as_ref()
        .ok_or_else(|| crate::api::bad_request("verified visitor identity is required"))?;
    if normalized_name(&body.from_name)? != visitor.name() {
        return Err((
            http::StatusCode::FORBIDDEN,
            "from does not match the verified caller".into(),
        ));
    }
    if normalized_name(&body.to)? != state.service.owner_name {
        return Err(crate::api::bad_request("to does not match this identity"));
    }
    validate_application_id(&body.application_id)?;
    if visitor.name() == state.service.owner_name.as_str() {
        return Err(crate::api::bad_request(
            "profile owner cannot be created as a contact",
        ));
    }
    validate_description_length(&body.description).map_err(crate::api::database)?;
    let payload_hash = Sha256::digest(
        serde_json::to_vec(&body)
            .map_err(|_| crate::api::internal("failed to encode application"))?,
    )
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect::<String>();
    let received_at = application_time()?;
    let contact = NewContact {
        name: visitor.name().to_owned(),
        subject_id: visitor.subject_id().clone(),
        class: body.class,
        description: body.description,
        requested_access: validate_requested_access(body.requested_access)?,
        offers: validate_granted_access(body.offers)?,
        created_at: received_at,
        updated_at: received_at,
        expired_after: received_at + APPLICATION_LIFETIME_SECONDS,
    };
    let (record, inserted) = state
        .service
        .create_application(contact, &body.application_id, &payload_hash)
        .await
        .map_err(crate::api::database)?;
    let response = application_response(&state.service, record).await?;
    Ok((
        if inserted {
            http::StatusCode::CREATED
        } else {
            http::StatusCode::OK
        },
        axum::Json(response),
    ))
}

const CONTACT_FILTER: &str = "updated_at >= ? AND (? = '' OR instr(lower(name), lower(?)) > 0 OR instr(lower(coalesce(alias, '')), lower(?)) > 0)";

#[derive(Deserialize)]
pub(crate) struct ContactListQuery {
    #[serde(flatten)]
    page: PageQuery<Sort>,
    modified_since: Option<i64>,
    #[serde(default)]
    search: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContactQuery {
    name: Option<String>,
}

fn normalized_name(raw: &str) -> Result<String, crate::api::ApiError> {
    let raw = raw.trim().to_ascii_lowercase();
    let name = raw
        .strip_suffix('~')
        .map_or_else(|| raw.clone(), |short| format!("{short}.dhttp.net"));
    if name.is_empty()
        || name.len() > 253
        || !name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err(crate::api::bad_request("invalid contact name"));
    }
    Ok(name)
}

impl ContactQuery {
    fn required_name(&self) -> Result<String, crate::api::ApiError> {
        normalized_name(
            self.name
                .as_deref()
                .ok_or_else(|| crate::api::bad_request("name is required"))?,
        )
    }
}

pub(crate) async fn list(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Query(query): axum::extract::Query<ContactListQuery>,
) -> Result<axum::Json<serde_json::Value>, crate::api::ApiError> {
    if query.modified_since.is_some_and(|value| value < 0) {
        return Err(crate::api::bad_request("invalid modified_since"));
    }
    let pagination = query.page.pagination();
    let (offset, limit) = pagination.offset_limit()?;
    let (total, contacts) = state
        .service
        .list_contacts(
            offset,
            limit,
            query.page.sort,
            query.page.order,
            query.modified_since,
            &query.search,
        )
        .await
        .map_err(crate::api::database)?;
    let mut result = serde_json::to_value(Page::new(contacts, total, pagination))
        .map_err(crate::api::internal)?;
    let deleted = if let Some(since) = query.modified_since {
        state.service.db.query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT name, updated_at FROM contact_deletions WHERE updated_at >= ? ORDER BY updated_at, name",
            [since.into()],
        )).await.map_err(crate::api::database)?
    } else {
        Vec::new()
    };
    result["deleted"] = serde_json::Value::Array(deleted.into_iter().map(|row| {
        Ok(serde_json::json!({"name": String::try_get(&row, "", "name")?, "updated_at": i64::try_get(&row, "", "updated_at")?}))
    }).collect::<Result<Vec<_>, DbErr>>().map_err(crate::api::database)?);
    Ok(axum::Json(result))
}

pub(crate) async fn get(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    visitor: Option<axum::Extension<Visitor>>,
    axum::extract::Query(query): axum::extract::Query<ContactQuery>,
) -> Result<axum::Json<serde_json::Value>, crate::api::ApiError> {
    let name = query.required_name()?;
    let visitor = visitor.ok_or((
        http::StatusCode::FORBIDDEN,
        "verified visitor identity is required".into(),
    ))?;
    let manager = matches!(
        state
            .service
            .auth(
                crate::Headers {
                    method: http::Method::GET,
                    path: "/std/contact/list".into(),
                    fields: http::HeaderMap::new(),
                },
                Some(visitor.name()),
                Some(visitor.subject_id())
            )
            .await
            .map_err(crate::api::database)?,
        crate::AuthResult::Allowed
    );
    if !manager && name != visitor.name() {
        return Err((
            http::StatusCode::FORBIDDEN,
            "only your own contact state may be read".into(),
        ));
    }
    let contact = state
        .service
        .find_contact_by_name(&name)
        .await
        .map_err(crate::api::database)?;
    let id = contact_id(&state.service, &name, &contact.subject_id)
        .await
        .map_err(crate::api::database)?;
    if manager {
        return Ok(axum::Json(
            serde_json::to_value(contact_body(contact, id, None)).map_err(crate::api::internal)?,
        ));
    }
    if &contact.subject_id != visitor.subject_id() {
        return Err((
            http::StatusCode::FORBIDDEN,
            "contact subject no longer matches verified caller".into(),
        ));
    }
    let status = ContactStatus::try_from(contact.status)
        .map_err(|_| crate::api::internal("invalid contact status"))?;
    let granted_access = if status == ContactStatus::Active {
        collect_granted_access(&state.service.db, &name)
            .await
            .map_err(crate::api::database)?
    } else {
        GrantedAccess::new()
    };
    Ok(axum::Json(
        serde_json::to_value(SelfContactStatusBody {
            id,
            name,
            subject_id: String::from_utf8_lossy(visitor.subject_id().as_bytes()).into_owned(),
            status,
            valid_before: contact.expired_after,
            granted_access,
        })
        .map_err(crate::api::internal)?,
    ))
}

struct Expiry {
    expires_after: Option<i64>,
    valid_before: Option<i64>,
}

impl Expiry {
    fn resolve(&self, now: i64, fallback: i64) -> Result<i64, crate::api::ApiError> {
        let result = match (self.expires_after, self.valid_before) {
            (Some(_), Some(_)) => {
                return Err(crate::api::bad_request("use expires_after or valid_before"));
            }
            (Some(seconds), None) if seconds > 0 => now
                .checked_add(seconds)
                .ok_or_else(|| crate::api::bad_request("expiry overflow"))?,
            (Some(_), None) => {
                return Err(crate::api::bad_request("expires_after must be positive"));
            }
            (None, Some(time)) => time,
            (None, None) => return Ok(fallback),
        };
        if result <= now {
            return Err(crate::api::bad_request(
                "valid_before must be in the future",
            ));
        }
        Ok(result)
    }
}

impl AccessService {
    /// Record a peer authenticated by the host's outbound contact workflow.
    /// This creates only a pending identity binding; it never grants access or
    /// changes an existing relationship, including its expiry and permissions.
    pub async fn record_outbound_contact(&self, contact: NewContact) -> Result<(), DbErr> {
        let name = normalized_name(&contact.name).map_err(|(_, message)| DbErr::Type(message))?;
        if name != contact.name || name == self.owner_name {
            return Err(DbErr::Type("invalid outbound contact name".into()));
        }
        validate_description_length(&contact.description)?;
        validate_application_times(
            contact.created_at,
            contact.updated_at,
            contact.expired_after,
        )?;
        let requests = encode_requested_access(&contact.requested_access)?;
        let offers = encode_granted_access(&contact.offers)?;
        let tx = self.db.begin().await?;
        // A delayed worker must not recreate an identity removed since submission.
        if tx
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT name FROM contact_deletions WHERE name=? AND updated_at>=?",
                [name.as_str().into(), contact.created_at.into()],
            ))
            .await?
            .is_some()
        {
            return Err(DbErr::RecordNotUpdated);
        }

        tx.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO contacts(name,subject_id,class,description,status,requests,offers,created_at,updated_at,expired_after) \
             VALUES(?,?,?,?,0,?,?,?,?,?) ON CONFLICT(name) DO NOTHING",
            [name.as_str().into(), contact.subject_id.as_bytes().to_vec().into(), contact.class.into(), contact.description.into(),
             requests.into(), offers.into(), contact.created_at.into(), contact.updated_at.into(), contact.expired_after.into()],
        )).await?;
        let row = tx
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT subject_id,status,expired_after FROM contacts WHERE name=?",
                [name.as_str().into()],
            ))
            .await?
            .ok_or(DbErr::RecordNotUpdated)?;
        let status = row.try_get::<i32>("", "status")?;
        if row.try_get::<Vec<u8>>("", "subject_id")? != contact.subject_id.as_bytes()
            || !matches!(
                ContactStatus::try_from(status),
                Ok(ContactStatus::Pending | ContactStatus::Active)
            )
            || (status == ContactStatus::Pending as i32
                && row.try_get::<i64>("", "expired_after")? <= contact.updated_at)
        {
            return Err(DbErr::RecordNotUpdated);
        }
        tx.commit().await?;
        self.contacts.write().await.insert(name, contact.subject_id);
        Ok(())
    }
}

fn validate_alias(alias: &str) -> Result<(), crate::api::ApiError> {
    if alias.chars().count() > 80 || alias.chars().any(char::is_control) {
        return Err(crate::api::bad_request("invalid alias"));
    }
    Ok(())
}

async fn contact_id(
    service: &AccessService,
    name: &str,
    subject: &SubjectId,
) -> Result<i64, DbErr> {
    let row = service
        .database()
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT id FROM contacts WHERE name = ? AND subject_id = ?",
            [name.into(), subject.as_bytes().to_vec().into()],
        ))
        .await?
        .ok_or_else(|| DbErr::RecordNotFound(name.into()))?;
    row.try_get("", "id")
}

pub(crate) async fn patch(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Query(query): axum::extract::Query<ContactQuery>,
    axum::Json(body): axum::Json<LocalContactPatchBody>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    let name = query.required_name()?;
    if body.status.is_none()
        && body.alias.is_none()
        && body.expires_after.is_none()
        && body.valid_before.is_none()
    {
        return Err(crate::api::bad_request(
            "contact patch requires status, alias or expiry",
        ));
    }
    if let Some(alias) = &body.alias {
        validate_alias(alias)?;
    }
    let valid_before = if body.expires_after.is_some() || body.valid_before.is_some() {
        Some(
            Expiry {
                expires_after: body.expires_after,
                valid_before: body.valid_before,
            }
            .resolve(application_time()?, 0)?,
        )
    } else {
        None
    };
    state
        .service
        .patch_contact_with_expiry(
            &name,
            ContactPatch::LocalUpdate {
                status: body.status,
                alias: body.alias,
            },
            valid_before,
        )
        .await
        .map_err(crate::api::database)?;
    Ok(http::StatusCode::NO_CONTENT)
}

pub(crate) async fn delete(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Query(query): axum::extract::Query<ContactQuery>,
    body: Option<axum::Json<DeleteContactsBody>>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    let names = match (query.name, body) {
        (Some(name), None) => vec![normalized_name(&name)?],
        (None, Some(axum::Json(body))) if !body.names.is_empty() => body
            .names
            .iter()
            .map(|name| normalized_name(name))
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(crate::api::bad_request(
                "provide name or a nonempty names array",
            ));
        }
    };
    state
        .service
        .delete_contacts(&names)
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

fn contact_subject_id_text(subject_id: &SubjectId) -> String {
    match std::str::from_utf8(subject_id.as_bytes()) {
        Ok(text) if !text.chars().any(char::is_control) => text.to_owned(),
        _ => {
            let hex = subject_id
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("hex:{hex}")
        }
    }
}

fn contact_body(value: ContactRecord, id: i64, incoming: Option<bool>) -> ContactBody {
    ContactBody {
        id,
        incoming,
        name: value.name,
        subject_id: contact_subject_id_text(&value.subject_id),
        alias: value.alias,
        class: value.class,
        description: value.description,
        status: ContactStatus::try_from(value.status)
            .expect("contact status is constrained by the database schema"),
        created_at: value.created_at,
        updated_at: value.updated_at,
        expired_after: value.expired_after,
        requested_access: value.requested_access,
        granted_access: value.granted_access,
        offers: value.offers,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/api/contact.rs"]
mod tests;
