use chrono::{DateTime, Utc};
use sea_orm::{ConnectionTrait, DatabaseBackend, DbErr, Statement, TryGetable};
use serde::{Deserialize, Serialize};

use crate::{
    AccessService, Action, ReviewStatus, Visitor,
    pagination::{Page, Pagination},
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
    id: i64,
    visitor: String,
    method: String,
    api: String,
    reason: String,
    expired_after: DateTime<Utc>,
}

#[derive(Serialize)]
pub(crate) struct ReviewStatusBody {
    status: &'static str,
}

#[derive(Deserialize)]
pub(crate) struct ReviewDecisionBody {
    id: i64,
    action: String,
    expired_after: Option<DateTime<Utc>>,
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

    pub async fn decide_review(
        &self,
        id: i64,
        action: Action,
        expired_after: DateTime<Utc>,
    ) -> Result<(), DbErr> {
        let stage = match action {
            Action::Allow => 1,
            Action::Deny => 2,
        };
        let result = self
            .db
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE access_reviews SET stage = ?, expired_after = ?, \
                 updated_at = CAST(strftime('%s', 'now') AS INTEGER) \
                 WHERE id = ? AND stage = 0 AND expired_after > CAST(strftime('%s', 'now') AS INTEGER)",
                [stage.into(), expired_after.timestamp().into(), id.into()],
            ))
            .await?;
        if result.rows_affected() == 0 {
            Err(DbErr::RecordNotFound(format!("pending review {id}")))
        } else {
            Ok(())
        }
    }
}

fn decode_timestamp(value: i64) -> Result<DateTime<Utc>, DbErr> {
    DateTime::from_timestamp(value, 0)
        .ok_or_else(|| DbErr::Type(format!("invalid UTC timestamp {value}")))
}

impl From<ReviewRecord> for ReviewBody {
    fn from(review: ReviewRecord) -> Self {
        match review {
            ReviewRecord::Persistent {
                id,
                visitor,
                method,
                api,
                reason,
                expired_after,
            } => Self {
                id,
                visitor,
                method,
                api,
                reason,
                expired_after,
            },
        }
    }
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
) -> Result<axum::Json<Page<Vec<ReviewBody>>>, crate::api::ApiError> {
    let (offset, limit) = pagination.offset_limit()?;
    let (total, reviews) = state
        .service
        .pending_persistent_reviews(offset, limit)
        .await
        .map_err(crate::api::database)?;
    Ok(axum::Json(Page::new(
        reviews.into_iter().map(ReviewBody::from).collect(),
        total,
        pagination,
    )))
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
    let expired_after = body.expired_after.ok_or((
        http::StatusCode::BAD_REQUEST,
        String::from("review decision expiry is required"),
    ))?;
    if expired_after <= Utc::now() {
        return Err((
            http::StatusCode::BAD_REQUEST,
            String::from("review decision expiry must be in the future"),
        ));
    }
    state
        .service
        .decide_review(body.id, action, expired_after)
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
        service
            .decide_review(id, Action::Allow, "2099-02-01T00:00:00Z".parse().unwrap())
            .await
            .unwrap();
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
            .uri("/std/acl/review/1/status")
            .body(axum::body::Body::empty())
            .unwrap();
        let denied = app.clone().oneshot(request).await.unwrap();
        assert_eq!(denied.status(), http::StatusCode::FORBIDDEN);

        let mut request = http::Request::builder()
            .uri("/std/acl/review/1/status")
            .body(axum::body::Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(Visitor::new("alice.example", SubjectId::new([1]).unwrap()));
        let allowed = app.oneshot(request).await.unwrap();
        assert_eq!(allowed.status(), http::StatusCode::OK);
    }
}
