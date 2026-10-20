use chrono::{DateTime, Utc};
use sea_orm::{ConnectionTrait, DatabaseBackend, DbErr, Statement, TransactionTrait, TryGetable};
use serde::{Deserialize, Serialize};

use crate::{
    AccessService, Action, ContactStatus, Effect, ReviewStatus, SubjectId, Visitor,
    pagination::{Page, Pagination},
    review::ReviewTarget,
};

#[derive(Clone, Debug)]
pub enum ReviewRecord {
    Persistent {
        id: i64,
        visitor: String,
        method: String,
        api: String,
        reason: String,
        expired_after: DateTime<Utc>,
    },
}

#[derive(Serialize)]
pub(crate) struct ReviewBody {
    kind: &'static str,
    id: i64,
    requested_at: i64,
    visitor: String,
    method: String,
    api: String,
    reason: String,
    expired_after: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub(crate) struct ReviewStatusBody {
    status: &'static str,
}

#[derive(Deserialize)]
pub(crate) struct ReviewDecisionBody {
    #[serde(default = "persistent_kind")]
    kind: String,
    id: i64,
    action: String,
}

fn persistent_kind() -> String {
    "persistent".into()
}

impl AccessService {
    pub async fn pending_persistent_reviews(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<(u64, Vec<ReviewRecord>), DbErr> {
        let total = self
            .db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                String::from(
                    "SELECT COUNT(*) AS total FROM access_reviews \
                     WHERE stage = 0 AND expired_after > CAST(strftime('%s', 'now') AS INTEGER)",
                ),
            ))
            .await?
            .expect("aggregate query always returns one row");
        let total = i64::try_get(&total, "", "total")? as u64;
        let reviews = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT id, visitor, method, api, reason, expired_after \
                 FROM access_reviews \
                 WHERE stage = 0 AND expired_after > CAST(strftime('%s', 'now') AS INTEGER) \
                 ORDER BY id LIMIT ? OFFSET ?",
                [limit.into(), offset.into()],
            ))
            .await?
            .into_iter()
            .map(|row| {
                Ok(ReviewRecord::Persistent {
                    id: i64::try_get(&row, "", "id")?,
                    visitor: String::try_get(&row, "", "visitor")?,
                    method: String::try_get(&row, "", "method")?,
                    api: String::try_get(&row, "", "api")?,
                    reason: String::try_get(&row, "", "reason")?,
                    expired_after: decode_timestamp(i64::try_get(&row, "", "expired_after")?)?,
                })
            })
            .collect::<Result<Vec<_>, DbErr>>()?;
        Ok((total, reviews))
    }

    pub async fn decide_review(&self, id: i64, action: Action) -> Result<(), DbErr> {
        self.decide_request(ReviewSource::Persistent(id), action)
            .await
    }

    pub async fn decide_live_review(&self, id: u64, action: Action) -> Result<(), DbErr> {
        self.decide_request(ReviewSource::Live(id), action).await
    }

    async fn decide_request(&self, source: ReviewSource, action: Action) -> Result<(), DbErr> {
        let mut policies = self.policies.write().await;
        let transaction = self.db.begin().await?;
        let target = match source {
            ReviewSource::Live(id) => self
                .reviews
                .target(id)
                .ok_or_else(|| DbErr::RecordNotFound(format!("live review {id}")))?,
            ReviewSource::Persistent(id) => {
                let row = transaction.query_one_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "SELECT visitor,visitor_sid,method,api FROM access_reviews WHERE id=? AND stage=0 AND expired_after>CAST(strftime('%s','now') AS INTEGER)",
                    [id.into()],
                )).await?.ok_or_else(|| DbErr::RecordNotFound(format!("pending review {id}")))?;
                ReviewTarget {
                    visitor: row.try_get("", "visitor")?,
                    subject_id: SubjectId::new(row.try_get::<Vec<u8>>("", "visitor_sid")?)
                        .map_err(|_| DbErr::Type("invalid review subject".into()))?,
                    method: row.try_get("", "method")?,
                    api: row.try_get("", "api")?,
                }
            }
        };
        let contact = transaction
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT subject_id,status FROM contacts WHERE name=?",
                [target.visitor.as_str().into()],
            ))
            .await?;
        if let Some(contact) = contact {
            if contact.try_get::<Vec<u8>>("", "subject_id")? != target.subject_id.as_bytes()
                || (action == Action::Allow
                    && contact.try_get::<i32>("", "status")? == ContactStatus::Blocked as i32)
            {
                // Never transfer existing permissions to a changed identity or undo a block.
                return Err(DbErr::RecordNotUpdated);
            }
        } else if target.visitor != self.owner_name {
            // Exact ACL grants need a durable identity binding. This does not accept a friend request.
            transaction.execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO contacts(name,subject_id,status,expired_after,updated_at,created_at) VALUES(?,?,?,CAST(strftime('%s','now','+7 days') AS INTEGER),CAST(strftime('%s','now') AS INTEGER),CAST(strftime('%s','now') AS INTEGER))",
                [target.visitor.as_str().into(), target.subject_id.as_bytes().to_vec().into(), (ContactStatus::Pending as i32).into()],
            )).await?;
        }
        let effect = match action {
            Action::Allow => Effect::Allow,
            Action::Deny => Effect::Deny,
        };
        super::contact::upsert_exact_rule(
            &transaction,
            &target.visitor,
            &target.method.parse()?,
            &target.api,
            effect,
        )
        .await?;
        Self::validate_management_administrators(&transaction, &self.owner_name).await?;
        transaction.execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "UPDATE access_reviews SET stage=?,updated_at=CAST(strftime('%s','now') AS INTEGER) WHERE visitor=? AND visitor_sid=? AND method=? AND api=? AND stage=0",
            [if action == Action::Allow { 1i32 } else { 2i32 }.into(), target.visitor.as_str().into(), target.subject_id.as_bytes().to_vec().into(), target.method.as_str().into(), target.api.as_str().into()],
        )).await?;
        let next_policies = Self::policies_from_db(&transaction, &self.owner_name).await?;
        transaction.commit().await?;
        if target.visitor != self.owner_name {
            self.contacts
                .write()
                .await
                .insert(target.visitor.clone(), target.subject_id.clone());
        }
        *policies = next_policies;
        self.reviews.resolve(&target, action);
        Ok(())
    }
}

enum ReviewSource {
    Live(u64),
    Persistent(i64),
}

fn decode_timestamp(value: i64) -> Result<DateTime<Utc>, DbErr> {
    DateTime::from_timestamp(value, 0)
        .ok_or_else(|| DbErr::Type(format!("invalid UTC timestamp {value}")))
}

fn status_name(status: ReviewStatus) -> &'static str {
    match status {
        ReviewStatus::Pending => "pending",
        ReviewStatus::Allowed => "allowed",
        ReviewStatus::Denied => "denied",
        ReviewStatus::Expired => "expired",
    }
}

pub(crate) async fn list_persistent(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Query(pagination): axum::extract::Query<Pagination>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<axum::Json<Page<Vec<ReviewBody>>>, crate::api::ApiError> {
    let comparison = match query.get("status").map(String::as_str).unwrap_or("pending") {
        "pending" => ">",
        "expired" => "<=",
        _ => return Err(crate::api::bad_request("status must be pending or expired")),
    };
    let kind = query.get("kind").map(String::as_str).unwrap_or("all");
    if !matches!(kind, "all" | "live" | "persistent") {
        return Err(crate::api::bad_request(
            "kind must be all, live or persistent",
        ));
    }
    let (offset, limit) = pagination.offset_limit()?;
    let mut items = Vec::new();
    if comparison == ">" && kind != "persistent" {
        items.extend(
            state
                .service
                .reviews
                .pending()
                .into_iter()
                .map(|review| ReviewBody {
                    kind: "live",
                    id: review.id as i64,
                    visitor: review.target.visitor,
                    requested_at: review.requested_at,
                    method: review.target.method,
                    api: review.target.api,
                    reason: review.reason,
                    expired_after: None,
                }),
        );
    }
    let mut total = items.len() as u64;
    if kind != "live" {
        let condition =
            format!("stage=0 AND expired_after {comparison} CAST(strftime('%s','now') AS INTEGER)");
        let db = state.service.database();
        let row = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                format!("SELECT count(*) AS total FROM access_reviews WHERE {condition}"),
            ))
            .await
            .map_err(crate::api::database)?
            .ok_or_else(|| crate::api::internal("review count missing"))?;
        total += row
            .try_get::<i64>("", "total")
            .map_err(|e| crate::api::database(e.into()))? as u64;
        let rows = db.query_all_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            format!("SELECT id,visitor,method,api,reason,created_at,expired_after FROM access_reviews WHERE {condition} ORDER BY created_at DESC,id DESC LIMIT ?"),
            [offset.saturating_add(limit).into()])).await.map_err(crate::api::database)?;
        for row in rows {
            let review = (|| -> Result<ReviewBody, DbErr> {
                Ok(ReviewBody {
                    kind: "persistent",
                    id: row.try_get("", "id")?,
                    visitor: row.try_get("", "visitor")?,
                    requested_at: row.try_get("", "created_at")?,
                    method: row.try_get("", "method")?,
                    api: row.try_get("", "api")?,
                    reason: row.try_get("", "reason")?,
                    expired_after: Some(decode_timestamp(row.try_get("", "expired_after")?)?),
                })
            })()
            .map_err(crate::api::database)?;
            items.push(review);
        }
    }
    items.sort_by(|a, b| {
        b.requested_at
            .cmp(&a.requested_at)
            .then_with(|| b.id.cmp(&a.id))
            .then_with(|| a.kind.cmp(b.kind))
    });
    let items = items
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();
    Ok(axum::Json(Page::new(items, total, pagination)))
}

pub(crate) async fn status(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    visitor: Option<axum::Extension<Visitor>>,
) -> Result<axum::Json<ReviewStatusBody>, crate::api::ApiError> {
    let visitor = visitor.ok_or((
        http::StatusCode::FORBIDDEN,
        String::from("review status requires an authenticated visitor"),
    ))?;
    let status = state
        .service
        .review_status(id, visitor.name(), visitor.subject_id())
        .await
        .map_err(crate::api::database)?;
    Ok(axum::Json(ReviewStatusBody {
        status: status_name(status),
    }))
}

pub(crate) async fn decide(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::Json(body): axum::Json<ReviewDecisionBody>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    let action = match body.action.as_str() {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        _ => {
            return Err((
                http::StatusCode::BAD_REQUEST,
                String::from("invalid review action"),
            ));
        }
    };
    if body.kind == "live" {
        let id = u64::try_from(body.id).map_err(crate::api::bad_request)?;
        state
            .service
            .decide_live_review(id, action)
            .await
            .map_err(crate::api::database)?;
        return Ok(http::StatusCode::NO_CONTENT);
    }
    if body.kind != "persistent" {
        return Err(crate::api::bad_request("kind must be live or persistent"));
    }
    state
        .service
        .decide_review(body.id, action)
        .await
        .map_err(crate::api::database)?;
    Ok(http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sea_orm::{ConnectionTrait, Database};
    use tower::ServiceExt;

    use super::*;
    use crate::SubjectId;

    async fn service() -> AccessService {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(include_str!("../migrations/0.sql"))
            .await
            .unwrap();
        AccessService::new(db, "owner.example")
    }

    #[tokio::test]
    async fn lists_and_decides_a_persistent_review() {
        let service = service().await;
        service.db.execute_unprepared("INSERT INTO access_reviews (request_id, visitor, visitor_sid, method, api, stage, reason, expired_after, updated_at, created_at) VALUES ('r1', 'alice.example', X'01', 'GET', '/api', 0, 'review', 4070995200, 4070908800, 4070908800)").await.unwrap();
        let (total, reviews) = service.pending_persistent_reviews(0, 20).await.unwrap();
        assert_eq!(total, 1);
        let id = match &reviews[0] {
            ReviewRecord::Persistent { id, .. } => *id,
        };
        service.decide_review(id, Action::Allow).await.unwrap();
        assert_eq!(
            service.pending_persistent_reviews(0, 20).await.unwrap().0,
            0
        );
    }

    #[tokio::test]
    async fn status_is_scoped_to_the_original_visitor_identity() {
        let service = Arc::new(service().await);
        service.db.execute_unprepared("INSERT INTO access_reviews (request_id, visitor, visitor_sid, method, api, stage, reason, expired_after, updated_at, created_at) VALUES ('r1', 'alice.example', X'01', 'GET', '/api', 1, 'review', 4070995200, 4070908800, 4070908800)").await.unwrap();
        let app = crate::api::router(service.clone());
        let request = http::Request::builder()
            .uri("/std/acl/status/1")
            .body(axum::body::Body::empty())
            .unwrap();
        let denied = app.clone().oneshot(request).await.unwrap();
        assert_eq!(denied.status(), http::StatusCode::FORBIDDEN);

        let mut request = http::Request::builder()
            .uri("/std/acl/status/1")
            .body(axum::body::Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(Visitor::new("alice.example", SubjectId::new([1]).unwrap()));
        let allowed = app.oneshot(request).await.unwrap();
        assert_eq!(allowed.status(), http::StatusCode::OK);
    }
}

#[cfg(test)]
mod expiry_tests {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    #[tokio::test]
    async fn expired_reviews_are_queryable_and_only_expired_pending_records_can_be_deleted() {
        let service = std::sync::Arc::new(
            AccessService::load_from_db(
                "sqlite::memory:",
                "owner.example",
                &crate::SubjectId::new(b"owner".to_vec()).unwrap(),
            )
            .await
            .unwrap(),
        );
        let time = Utc::now().timestamp();
        service.database().execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            "INSERT INTO access_reviews(id,request_id,visitor,visitor_sid,method,api,stage,reason,expired_after,created_at,updated_at) VALUES(1,'expired','alice',?,'GET','/private',0,'expired',?,?,?),(2,'pending','alice',?,'GET','/private',0,'pending',?,?,?),(3,'decided','alice',?,'GET','/private',1,'decided',?,?,?)",
            vec![b"alice".to_vec().into(),(time-1).into(),(time-30).into(),(time-30).into(),b"alice".to_vec().into(),(time+30).into(),time.into(),time.into(),b"alice".to_vec().into(),(time-1).into(),(time-30).into(),(time-30).into()])).await.unwrap();
        let app = crate::api::router(service);
        let response = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri("/std/acl/reviews?status=expired")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let value: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(value["total"], 1);
        assert_eq!(value["items"][0]["id"], 1);
        assert_eq!(value["items"][0]["requested_at"], time - 30);
        for (id, status) in [(2, 404), (3, 404), (1, 204), (1, 404)] {
            assert_eq!(
                app.clone()
                    .oneshot(
                        http::Request::builder()
                            .method("DELETE")
                            .uri(format!("/std/acl/review/{id}"))
                            .body(Body::empty())
                            .unwrap()
                    )
                    .await
                    .unwrap()
                    .status(),
                status
            );
        }
        assert_eq!(
            app.oneshot(
                http::Request::builder()
                    .uri("/std/acl/reviews?status=other")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
            400
        );
    }
}
