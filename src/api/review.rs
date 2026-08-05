use chrono::{DateTime, Utc};
use sea_orm::{ConnectionTrait, DatabaseBackend, DbErr, Statement, TryGetable, Value};
use serde::{Deserialize, Serialize};

use crate::{
    AccessService, Action, RequestId, ReviewingRequest,
    pagination::{Page, Pagination},
};

#[derive(Clone, Debug)]
pub enum ReviewRecord {
    Live {
        id: u64,
        request: ReviewingRequest,
    },
    Persistent {
        id: i64,
        request_id: RequestId,
        visitor: String,
        method: String,
        api: String,
        reason: String,
        expired_after: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewTarget {
    Live(u64),
    Persistent(i64),
}

#[derive(Serialize)]
pub(crate) struct ReviewBody {
    kind: &'static str,
    id: u64,
    request_id: Option<String>,
    visitor: Option<String>,
    method: String,
    api: String,
    reason: String,
    expired_after: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
pub(crate) struct ReviewDecisionBody {
    kind: String,
    id: u64,
    action: String,
    expired_after: Option<DateTime<Utc>>,
}

impl AccessService {
    pub fn pending_live_reviews(&self, offset: i64, limit: i64) -> (u64, Vec<ReviewRecord>) {
        let mut reviews = self.reviews.pending();
        reviews.sort_by_key(|(id, _)| *id);
        let total = reviews.len() as u64;
        let reviews = reviews
            .into_iter()
            .skip(usize::try_from(offset).unwrap_or(usize::MAX))
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .map(|(id, request)| ReviewRecord::Live { id, request })
            .collect();
        (total, reviews)
    }

    pub async fn pending_persistent_reviews(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<(u64, Vec<ReviewRecord>), DbErr> {
        let mut live_request_ids = self
            .reviews
            .pending()
            .into_iter()
            .filter_map(|(_, request)| {
                Some((
                    request.name()?.to_owned(),
                    request.headers().request_id.as_ref()?.as_str().to_owned(),
                ))
            })
            .collect::<Vec<_>>();
        live_request_ids.sort();
        live_request_ids.dedup();
        let exclusion = if live_request_ids.is_empty() {
            String::new()
        } else {
            format!(
                " AND NOT ({})",
                std::iter::repeat("(visitor = ? AND request_id = ?)")
                    .take(live_request_ids.len())
                    .collect::<Vec<_>>()
                    .join(" OR ")
            )
        };
        let values = live_request_ids
            .into_iter()
            .flat_map(|(visitor, request_id)| [Value::from(visitor), Value::from(request_id)])
            .collect::<Vec<_>>();
        let total = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                format!("SELECT COUNT(*) AS total FROM access_reviews WHERE stage = 0{exclusion}"),
                values.clone(),
            ))
            .await?
            .expect("aggregate query always returns one row");
        let total = i64::try_get(&total, "", "total")? as u64;
        let mut page_values = values;
        page_values.extend([limit.into(), offset.into()]);
        let reviews = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                format!(
                    "SELECT id, request_id, visitor, method, api, reason, expired_after \
                     FROM access_reviews WHERE stage = 0{exclusion} \
                     ORDER BY id LIMIT ? OFFSET ?"
                ),
                page_values,
            ))
            .await?
            .into_iter()
            .map(|row| {
                Ok(ReviewRecord::Persistent {
                    id: i64::try_get(&row, "", "id")?,
                    request_id: RequestId::new(String::try_get(&row, "", "request_id")?),
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
        target: ReviewTarget,
        action: Action,
        expired_after: Option<DateTime<Utc>>,
    ) -> Result<(), DbErr> {
        match target {
            ReviewTarget::Live(id) => {
                let request = self
                    .reviews
                    .pending()
                    .into_iter()
                    .find_map(|(pending_id, request)| (pending_id == id).then_some(request))
                    .ok_or_else(|| DbErr::RecordNotFound(format!("live review {id}")))?;
                if let Some((visitor, request_id)) =
                    request.name().zip(request.headers().request_id.as_ref())
                {
                    self.db
                        .execute_raw(Statement::from_sql_and_values(
                            DatabaseBackend::Sqlite,
                            "DELETE FROM access_reviews \
                             WHERE visitor = ? AND request_id = ? AND stage = 0",
                            [visitor.into(), request_id.as_str().into()],
                        ))
                        .await?;
                }
                let found = match action {
                    Action::Allow => self.reviews.approve(id),
                    Action::Deny => self.reviews.reject(id),
                };
                if found {
                    Ok(())
                } else {
                    Err(DbErr::RecordNotFound(format!("live review {id}")))
                }
            }
            ReviewTarget::Persistent(id) => {
                let stage = match action {
                    Action::Allow => 1,
                    Action::Deny => 2,
                };
                let expired_after_timestamp = expired_after
                    .ok_or_else(|| {
                        DbErr::Type(String::from("persistent review expiry is required"))
                    })?
                    .timestamp();
                let result = self.db.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
                    "UPDATE access_reviews SET stage = ?, expired_after = ?, updated_at = CAST(strftime('%s', 'now') AS INTEGER) WHERE id = ? AND stage = 0",
                    [stage.into(), expired_after_timestamp.into(), id.into()])).await?;
                if result.rows_affected() == 0 {
                    Err(DbErr::RecordNotFound(format!("persistent review {id}")))
                } else {
                    Ok(())
                }
            }
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
            ReviewRecord::Live { id, request } => Self {
                kind: "live",
                id,
                request_id: request
                    .headers()
                    .request_id
                    .as_ref()
                    .map(|request_id| request_id.as_str().to_owned()),
                visitor: request.name().map(str::to_owned),
                method: request.headers().method.to_string(),
                api: request.headers().path.clone(),
                reason: request.reason().into(),
                expired_after: None,
            },
            ReviewRecord::Persistent {
                id,
                request_id,
                visitor,
                method,
                api,
                reason,
                expired_after,
            } => Self {
                kind: "persistent",
                id: id as u64,
                request_id: Some(request_id.as_str().to_owned()),
                visitor: Some(visitor),
                method,
                api,
                reason,
                expired_after: Some(expired_after),
            },
        }
    }
}

pub(crate) async fn list_live(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Query(pagination): axum::extract::Query<Pagination>,
) -> Result<axum::Json<Page<Vec<ReviewBody>>>, crate::api::ApiError> {
    let (offset, limit) = pagination.offset_limit()?;
    let (total, reviews) = state.service.pending_live_reviews(offset, limit);
    Ok(axum::Json(Page::new(
        reviews.into_iter().map(ReviewBody::from).collect(),
        total,
        pagination,
    )))
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

pub(crate) async fn decide(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::Json(body): axum::Json<ReviewDecisionBody>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    let target = match body.kind.as_str() {
        "live" => ReviewTarget::Live(body.id),
        "persistent" => ReviewTarget::Persistent(body.id as i64),
        _ => {
            return Err((
                http::StatusCode::BAD_REQUEST,
                String::from("invalid review kind"),
            ));
        }
    };
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
    state
        .service
        .decide_review(target, action, body.expired_after)
        .await
        .map_err(crate::api::database)?;
    Ok(http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    use sea_orm::{ConnectionTrait, Database};

    use super::*;
    use crate::{Headers, ReviewingRequest, SubjectId};

    async fn service() -> AccessService {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(include_str!("../migrations/0.sql"))
            .await
            .unwrap();
        AccessService::new(db, "owner.example")
    }

    #[tokio::test]
    async fn lists_and_decides_live_review() {
        let service = service().await;
        let request = ReviewingRequest::new(
            Headers {
                method: http::Method::GET,
                path: "/api".into(),
                fields: http::HeaderMap::new(),
                request_id: None,
            },
            Some("alice.example".into()),
            Some(SubjectId::new([1]).unwrap()),
            "review".into(),
        );
        let (id, mut state) = service.reviews.add(request);
        let (total, reviews) = service.pending_live_reviews(0, 20);
        assert_eq!(total, 1);
        assert_eq!(reviews.len(), 1);
        service
            .decide_review(ReviewTarget::Live(id), Action::Allow, None)
            .await
            .unwrap();
        assert!(matches!(
            Pin::new(&mut state).poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(Action::Allow))
        ));
        assert!(
            service
                .decide_review(ReviewTarget::Live(id + 1), Action::Deny, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn persistent_decision_does_not_complete_a_live_review() {
        let service = service().await;
        service.db.execute_unprepared("INSERT INTO access_reviews (request_id, visitor, visitor_sid, method, api, stage, reason, expired_after, updated_at, created_at) VALUES ('r1', 'alice.example', X'01', 'GET', '/api', 0, 'review', 4070995200, 4070908800, 4070908800)").await.unwrap();
        let (total, reviews) = service.pending_persistent_reviews(0, 20).await.unwrap();
        assert_eq!(total, 1);
        let id = match &reviews[0] {
            ReviewRecord::Persistent {
                id, expired_after, ..
            } => {
                assert_eq!(expired_after.timestamp(), 4070995200);
                *id
            }
            _ => panic!("expected persistent review"),
        };
        let (_, mut state) = service.reviews.add(ReviewingRequest::new(
            Headers {
                method: http::Method::GET,
                path: "/api".into(),
                fields: http::HeaderMap::new(),
                request_id: Some(crate::RequestId::new("r1")),
            },
            Some("alice.example".into()),
            Some(SubjectId::new([1]).unwrap()),
            "review".into(),
        ));
        service
            .decide_review(
                ReviewTarget::Persistent(id),
                Action::Deny,
                Some("2099-02-01T00:00:00Z".parse().unwrap()),
            )
            .await
            .unwrap();
        assert!(
            Pin::new(&mut state)
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let (total, reviews) = service.pending_persistent_reviews(0, 20).await.unwrap();
        assert_eq!(total, 0);
        assert!(reviews.is_empty());
        assert!(
            service
                .decide_review(
                    ReviewTarget::Persistent(id),
                    Action::Allow,
                    Some("2099-03-01T00:00:00Z".parse().unwrap())
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn deciding_live_review_removes_overlapping_persistent_review() {
        let service = service().await;
        service.db.execute_unprepared("INSERT INTO access_reviews (request_id, visitor, visitor_sid, method, api, stage, reason, expired_after, updated_at, created_at) VALUES ('r1', 'alice.example', X'01', 'GET', '/api', 0, 'review', 4070995200, 4070908800, 4070908800)").await.unwrap();
        let (id, mut state) = service.reviews.add(ReviewingRequest::new(
            Headers {
                method: http::Method::GET,
                path: "/api".into(),
                fields: http::HeaderMap::new(),
                request_id: Some(RequestId::new("r1")),
            },
            Some("alice.example".into()),
            Some(SubjectId::new([1]).unwrap()),
            "review".into(),
        ));

        service
            .decide_review(ReviewTarget::Live(id), Action::Allow, None)
            .await
            .unwrap();
        assert!(matches!(
            Pin::new(&mut state).poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(Action::Allow))
        ));
        let row = service
            .db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT id FROM access_reviews WHERE request_id = 'r1'",
            ))
            .await
            .unwrap();
        assert!(row.is_none());
    }

    #[tokio::test]
    async fn http_decides_one_review_at_the_singular_endpoint() {
        use std::sync::Arc;

        use tower::ServiceExt;

        let service = Arc::new(service().await);
        let request = ReviewingRequest::new(
            Headers {
                method: http::Method::GET,
                path: "/api".into(),
                fields: http::HeaderMap::new(),
                request_id: None,
            },
            Some("alice.example".into()),
            Some(SubjectId::new([1]).unwrap()),
            "review".into(),
        );
        let (id, mut state) = service.reviews.add(request);
        let response = crate::api::router(service)
            .oneshot(
                http::Request::builder()
                    .method(http::Method::PATCH)
                    .uri("/acl/review")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(format!(
                        r#"{{"kind":"live","id":{id},"action":"allow"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
        assert!(matches!(
            Pin::new(&mut state).poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(Action::Allow))
        ));
    }

    #[tokio::test]
    async fn persistent_page_hides_request_ids_already_shown_live() {
        use std::sync::Arc;

        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let service = Arc::new(service().await);
        service.db.execute_unprepared("INSERT INTO access_reviews (request_id, visitor, visitor_sid, method, api, stage, reason, expired_after, updated_at, created_at) VALUES ('r1', 'alice.example', X'01', 'GET', '/persistent', 0, 'review', 4070995200, 4070908800, 4070908800), ('r3', 'bob.example', X'02', 'POST', '/persistent', 0, 'review', 4070995200, 4070908800, 4070908800)").await.unwrap();
        for (request_id, path) in [("r1", "/live/one"), ("r2", "/live/two")] {
            service.reviews.add(ReviewingRequest::new(
                Headers {
                    method: http::Method::GET,
                    path: path.into(),
                    fields: http::HeaderMap::new(),
                    request_id: Some(RequestId::new(request_id)),
                },
                Some("alice.example".into()),
                Some(SubjectId::new([1]).unwrap()),
                "review".into(),
            ));
        }

        let app = crate::api::router(service);

        let live = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri("/acl/reviews/live?page=1&page_size=1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(live.status(), http::StatusCode::OK);
        let live: serde_json::Value =
            serde_json::from_slice(&live.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(live["total"], 2);
        assert_eq!(live["page"], 1);
        assert_eq!(live["page_size"], 1);
        assert_eq!(live["items"][0]["kind"], "live");
        assert_eq!(live["items"][0]["request_id"], "r1");

        let persistent = app
            .oneshot(
                http::Request::builder()
                    .uri("/acl/reviews/persistent?page=1&page_size=1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(persistent.status(), http::StatusCode::OK);
        let persistent: serde_json::Value =
            serde_json::from_slice(&persistent.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(persistent["total"], 1);
        assert_eq!(persistent["items"][0]["kind"], "persistent");
        assert_eq!(persistent["items"][0]["request_id"], "r3");
    }
}
