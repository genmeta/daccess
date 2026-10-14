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
    AccessService, ContactStatus, Effect, Grantee, Method, SubjectId,
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
    application_id: String,
    #[serde(default)]
    class: String,
    description: String,
    #[serde(default)]
    requested_access: RequestedAccess,
    #[serde(default)]
    offers: GrantedAccess,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplicationQuery {
    application_id: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct ApplicationStatusBody {
    application_id: String,
    name: String,
    subject_id: String,
    status: String,
    received_at: i64,
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
    expired_after: i64,
    requested_access: RequestedAccess,
    granted_access: GrantedAccess,
    offers: GrantedAccess,
}

#[derive(Serialize)]
pub(crate) struct SelfContactStatusBody {
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
        let initial_status = if contact
            .requested_access
            .values()
            .any(|methods| !methods.is_empty())
        {
            ContactStatus::Pending as i32
        } else {
            ContactStatus::Active as i32
        };
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
        if previous_status == Some(ContactStatus::Active as i32)
            && previous_subject
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

    async fn find_application(&self, application_id: &str) -> Result<ApplicationRecord, DbErr> {
        expire_pending_contacts(&self.db, None).await?;
        let row = self.db.query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT application_id, applicant_name, applicant_sid, payload_hash, status, received_at, expired_after \
             FROM contact_applications WHERE application_id = ?",
            [application_id.into()],
        )).await?.ok_or_else(|| DbErr::RecordNotFound(format!("application {application_id:?}")))?;
        decode_application(row)
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
    ) -> Result<(u64, Vec<ContactBody>), DbErr> {
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
            "SELECT id, name, subject_id, alias, class, description, status, expired_after, updated_at, created_at, requests, grants, offers, EXISTS(SELECT 1 FROM contact_applications a WHERE a.applicant_name = contacts.name AND a.applicant_sid = contacts.subject_id) AS incoming FROM contacts \
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
            .map(|row| {
                let id = row.try_get("", "id")?;
                let incoming = row.try_get::<i64>("", "incoming")? != 0;
                Ok::<_, DbErr>(contact_body(decode_contact(row)?, id, Some(incoming)))
            })
            .collect::<Result<_, _>>()?;
        Ok((total, contacts))
    }

    pub async fn patch_contact(&self, name: &str, patch: ContactPatch) -> Result<(), DbErr> {
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
    Ok(axum::Json(Page::new(contacts, total, pagination)))
}

pub(crate) async fn get(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<axum::Json<ContactBody>, crate::api::ApiError> {
    let contact = state
        .service
        .find_contact_by_name(&name)
        .await
        .map_err(crate::api::database)?;
    let id = contact_id(&state.service, &name, &contact.subject_id)
        .await
        .map_err(crate::api::database)?;
    Ok(axum::Json(contact_body(contact, id, None)))
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

pub(crate) async fn self_status(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    visitor: Option<axum::Extension<crate::Visitor>>,
    axum::extract::Query(query): axum::extract::Query<ApplicationQuery>,
) -> Result<axum::Json<serde_json::Value>, crate::api::ApiError> {
    let visitor = visitor
        .as_ref()
        .ok_or_else(|| crate::api::bad_request("verified visitor identity is required"))?;
    if let Some(application_id) = query.application_id {
        validate_application_id(&application_id)?;
        let record = state
            .service
            .find_application(&application_id)
            .await
            .map_err(crate::api::database)?;
        if record.applicant_name != visitor.name()
            || record.applicant_sid.as_slice() != visitor.subject_id().as_bytes()
        {
            return Err((
                http::StatusCode::FORBIDDEN,
                String::from("application does not belong to the verified visitor"),
            ));
        }
        let response = application_response(&state.service, record).await?;
        return Ok(axum::Json(serde_json::to_value(response).map_err(
            |_| crate::api::internal("failed to encode application"),
        )?));
    }
    let contact = state
        .service
        .find_contact_by_name(visitor.name())
        .await
        .map_err(crate::api::database)?;
    if &contact.subject_id != visitor.subject_id() {
        return Err((
            http::StatusCode::FORBIDDEN,
            String::from("contact subject_id no longer matches the verified visitor"),
        ));
    }
    let status = ContactStatus::try_from(contact.status)
        .map_err(|_| crate::api::internal("contact has an invalid status"))?;
    let granted_access = if status == ContactStatus::Active {
        collect_granted_access(&state.service.db, visitor.name())
            .await
            .map_err(crate::api::database)?
    } else {
        GrantedAccess::new()
    };
    Ok(axum::Json(
        serde_json::to_value(SelfContactStatusBody {
            id: contact_id(&state.service, visitor.name(), visitor.subject_id())
                .await
                .map_err(crate::api::database)?,
            name: visitor.name().to_owned(),
            subject_id: String::from_utf8_lossy(visitor.subject_id().as_bytes()).into_owned(),
            status,
            granted_access,
        })
        .map_err(|_| crate::api::internal("failed to encode contact status"))?,
    ))
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
    state
        .service
        .patch_contact(
            &name,
            ContactPatch::LocalUpdate {
                status: body.status,
                alias: body.alias,
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
mod tests {
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
        db.execute_unprepared(include_str!("../migrations/0.sql"))
            .await
            .unwrap();
        db.execute_unprepared(include_str!("../migrations/1.sql"))
            .await
            .unwrap();
        let service = AccessService::new(db, "owner.example");
        service.contacts.write().await.insert(
            String::from("owner.example"),
            SubjectId::new(b"owner-subject".to_vec()).unwrap(),
        );
        service
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

        for path in ["/std/contact/alice.example", "/std/contacts"] {
            let response = app
                .clone()
                .oneshot(request(http::Method::GET, path, ""))
                .await
                .unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let item = if path == "/std/contacts" {
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
                "SELECT COUNT(*) count FROM access_rules",
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
                "/std/contact/alice.example",
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
        assert_eq!(stored.updated_at, 2);
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

        let anonymous = request(http::Method::GET, "/std/contact/self", "");
        assert_eq!(
            app.clone().oneshot(anonymous).await.unwrap().status(),
            http::StatusCode::BAD_REQUEST
        );

        let mut self_request = request(http::Method::GET, "/std/contact/self", "");
        self_request.extensions_mut().insert(crate::Visitor::new(
            "alice.example",
            SubjectId::new(vec![1]).unwrap(),
        ));
        let response = app.clone().oneshot(self_request).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["status"], "active");
        assert_eq!(
            body["granted_access"]["/local"]["allow"],
            serde_json::json!(["GET"])
        );

        let mismatch = as_visitor(
            request(http::Method::GET, "/std/contact/self", ""),
            "alice.example",
        );
        assert_eq!(
            app.clone().oneshot(mismatch).await.unwrap().status(),
            http::StatusCode::FORBIDDEN
        );

        let missing = as_visitor(
            request(http::Method::GET, "/std/contact/self", ""),
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
            let mut request = request(http::Method::GET, "/std/contact/self", "");
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
        let mut request = request(http::Method::GET, "/std/contact/self", "");
        request.extensions_mut().insert(crate::Visitor::new(
            "alice.example",
            SubjectId::new(vec![1]).unwrap(),
        ));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
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
                r#"{"application_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","description":"Owner"}"#,
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
                r#"{"application_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","class":"agent","description":"Alice","requested_access":{"/api/messages":["POST"]},"offers":{}}"#,
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
                r#"{"application_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","class":"agent","description":"Alice","requested_access":{"/api/messages":["POST"]},"offers":{}}"#,
            ),
            "alice.example",
        );
        assert_eq!(
            app.clone().oneshot(retry).await.unwrap().status(),
            http::StatusCode::OK
        );
        let status = as_visitor(
            request(
                http::Method::GET,
                "/std/contact/self?application_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "",
            ),
            "alice.example",
        );
        let status = app.clone().oneshot(status).await.unwrap();
        assert_eq!(status.status(), http::StatusCode::OK);
        let status: serde_json::Value =
            serde_json::from_slice(&status.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(status["name"], "owner.example");
        assert_eq!(status["status"], "pending");
        let duplicate = as_visitor(
            request(
                http::Method::POST,
                "/std/contact",
                r#"{"application_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","class":"service","description":"Updated Alice","requested_access":{"/api/messages":["POST"]},"offers":{}}"#,
            ),
            "alice.example",
        );
        assert_eq!(
            app.clone().oneshot(duplicate).await.unwrap().status(),
            http::StatusCode::CREATED
        );

        let get = request(http::Method::GET, "/std/contact/alice.example", "");
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
            body["expired_after"].as_i64().unwrap() - body["created_at"].as_i64().unwrap(),
            7 * 86_400
        );

        let list = request(http::Method::GET, "/std/contacts", "");
        assert_eq!(
            app.clone().oneshot(list).await.unwrap().status(),
            http::StatusCode::OK
        );

        let delete = request(
            http::Method::DELETE,
            "/std/contacts",
            r#"{"names":["alice.example"]}"#,
        );
        assert_eq!(
            app.clone().oneshot(delete).await.unwrap().status(),
            http::StatusCode::NO_CONTENT
        );
        assert!(service.find_contact_by_name("alice.example").await.is_err());
        let missing = request(http::Method::GET, "/std/contact/alice.example", "");
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
            assert_eq!(
                receipt.status,
                if without_permissions {
                    "active"
                } else {
                    "pending"
                }
            );
            let latest = service.find_contact_by_name("alice.example").await.unwrap();
            assert_eq!(latest.description, replacement.description);
            assert_eq!(latest.requested_access, replacement.requested_access);
            assert_eq!(latest.offers, replacement.offers);
            assert_eq!(latest.created_at, replacement.created_at);
            assert_eq!(latest.expired_after, replacement.expired_after);
            assert_eq!(latest.status, if without_permissions { 2 } else { 0 });
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
            if !without_permissions {
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
            }
            assert_eq!(
                service.find_application(&first_id).await.unwrap().status,
                "revoked"
            );
            assert_eq!(
                service.find_application(&next_id).await.unwrap().status,
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
            assert!(service.find_application(&next_id).await.is_err());
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
                    &format!("/std/contacts?page=1&page_size=1&sort={sort}&order=asc"),
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
                "/std/contacts?page=2&page_size=1&sort=name&order=asc",
                "",
            ))
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&second_page.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["items"][0]["name"], "bob.example");

        for (uri, expected) in [
            ("/std/contacts?page_size=1", "charlie.example"),
            (
                "/std/contacts?page_size=1&sort=name&order=desc",
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
            "/std/contacts?page=0",
            "/std/contacts?page_size=101",
            "/std/contacts?sort=unknown",
            "/std/contacts?order=sideways",
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
            "/std/contact/alice.example",
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

        let anonymous = request(
            http::Method::PATCH,
            "/std/contact/alice.example",
            r#"{"status":"active"}"#,
        );
        assert_eq!(
            app.clone().oneshot(anonymous).await.unwrap().status(),
            http::StatusCode::BAD_REQUEST
        );

        for (body, expected) in [
            (r#"{}"#, http::StatusCode::BAD_REQUEST),
            (r#"{"status":"active"}"#, http::StatusCode::NO_CONTENT),
        ] {
            let approval = request(http::Method::PATCH, "/std/contact/alice.example", body);
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
            "/std/contact/alice.example",
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
            "/std/contact/alice.example",
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
            "/std/contact/alice.example",
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
            "/std/contact/alice.example",
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
            "/std/contact/alice.example",
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
                "/std/contact/alice.example",
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
}
