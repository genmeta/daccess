use std::fmt::Write as _;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::SubjectId;

/// A server-internal, deterministic identifier for a reviewed request.
///
/// It is never accepted from an HTTP caller. The request ID only deduplicates a
/// pending review and binds a later business-request retry to the same verified
/// identity and request metadata.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RequestId(String);

impl RequestId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn for_request(headers: &Headers, visitor: &str, subject_id: &SubjectId) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"dhttp/request-id/1\0");
        let path = crate::policy::database_api(headers.path.split('?').next().unwrap_or("/"));
        for value in [
            headers.method.as_str().as_bytes(),
            path.as_bytes(),
            visitor.as_bytes(),
            subject_id.as_bytes(),
        ] {
            update_digest(&mut digest, value);
        }

        let mut request_id = String::with_capacity(64);
        for byte in digest.finalize() {
            write!(request_id, "{byte:02x}").expect("writing to String cannot fail");
        }
        Self(request_id)
    }
}

fn update_digest(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

#[derive(Clone, Debug)]
pub struct Headers {
    pub method: http::Method,
    pub path: String,
    pub fields: http::HeaderMap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Allow,
    Deny,
}

/// A pending review returned synchronously to an adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingReview {
    id: i64,
}

impl PendingReview {
    pub(crate) fn new(id: i64) -> Self {
        Self { id }
    }

    pub fn id(self) -> i64 {
        self.id
    }
}

/// The response body returned by an adapter for an asynchronous review.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PendingReviewResponse {
    status: &'static str,
    review_id: i64,
    status_url: String,
}

impl From<PendingReview> for PendingReviewResponse {
    fn from(review: PendingReview) -> Self {
        let review_id = review.id();
        Self {
            status: "pending_review",
            review_id,
            status_url: format!("/std/acl/status?id={review_id}"),
        }
    }
}

/// The state exposed by the visitor's read-only status endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewStatus {
    Pending,
    Allowed,
    Denied,
    Expired,
    Consumed,
}

/// How a request handles an ACL review. Omitted headers default to asynchronous review.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewMode {
    Waiting,
    Break,
}

impl ReviewMode {
    pub fn from_headers(fields: &http::HeaderMap) -> Result<Self, sea_orm::DbErr> {
        let mut values = fields.get_all("if-reviewed").iter();
        let mode = match values.next().map(http::HeaderValue::as_bytes) {
            None | Some(b"break") => Self::Break,
            Some(b"waiting") => Self::Waiting,
            _ => {
                return Err(sea_orm::DbErr::Type(
                    "If-Reviewed must be waiting or break".into(),
                ));
            }
        };
        if values.next().is_some() {
            return Err(sea_orm::DbErr::Type("duplicate If-Reviewed header".into()));
        }
        Ok(mode)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReviewTarget {
    pub visitor: String,
    pub subject_id: SubjectId,
    pub method: String,
    pub api: String,
}

#[derive(Clone, Debug)]
pub(crate) struct LiveRequest {
    pub id: u64,
    pub target: ReviewTarget,
    pub reason: String,
    pub requested_at: i64,
}

#[derive(Debug, Default)]
struct Registry {
    requests: std::collections::BTreeMap<u64, (LiveRequest, tokio::sync::oneshot::Sender<Action>)>,
}

fn next_live_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    // Stay within JSON's exact integer range and avoid reusing small IDs after a restart.
    let time = chrono::Utc::now().timestamp_micros() as u64;
    let mut previous = NEXT_ID.load(Ordering::Relaxed);
    loop {
        let next = (previous + 1).max(time);
        match NEXT_ID.compare_exchange_weak(previous, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(current) => previous = current,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct LiveReviews(std::sync::Arc<std::sync::Mutex<Registry>>);

impl LiveReviews {
    fn lock(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn add(
        &self,
        visitor: &str,
        subject_id: &SubjectId,
        headers: &Headers,
        reason: String,
    ) -> LiveReview {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let mut registry = self.lock();
        let id = next_live_id();
        registry.requests.insert(
            id,
            (
                LiveRequest {
                    id,
                    target: ReviewTarget {
                        visitor: visitor.to_owned(),
                        subject_id: subject_id.clone(),
                        method: headers.method.to_string(),
                        api: crate::policy::database_api(
                            headers.path.split('?').next().unwrap_or("/"),
                        ),
                    },
                    reason,
                    requested_at: chrono::Utc::now().timestamp(),
                },
                sender,
            ),
        );
        LiveReview {
            id,
            receiver,
            registry: self.clone(),
        }
    }

    pub fn pending(&self) -> Vec<LiveRequest> {
        self.lock()
            .requests
            .values()
            .map(|(request, _)| request.clone())
            .collect()
    }

    pub fn target(&self, id: u64) -> Option<ReviewTarget> {
        self.lock()
            .requests
            .get(&id)
            .map(|(request, _)| request.target.clone())
    }

    pub fn resolve_one(&self, id: u64, action: Action) -> Result<(), sea_orm::DbErr> {
        let (_, sender) = self
            .lock()
            .requests
            .remove(&id)
            .ok_or_else(|| sea_orm::DbErr::RecordNotFound(format!("live review {id}")))?;
        sender
            .send(action)
            .map_err(|_| sea_orm::DbErr::RecordNotUpdated)
    }

    pub fn resolve(&self, target: &ReviewTarget, action: Action) {
        let mut registry = self.lock();
        let ids: Vec<_> = registry
            .requests
            .iter()
            .filter(|(_, (request, _))| request.target == *target)
            .map(|(id, _)| *id)
            .collect();
        let senders: Vec<_> = ids
            .into_iter()
            .filter_map(|id| registry.requests.remove(&id).map(|(_, sender)| sender))
            .collect();
        drop(registry);
        for sender in senders {
            let _ = sender.send(action);
        }
    }
}

/// Owns exactly one waiting request. Dropping it unregisters the review, including on cancellation.
#[derive(Debug)]
pub struct LiveReview {
    id: u64,
    receiver: tokio::sync::oneshot::Receiver<Action>,
    registry: LiveReviews,
}

impl std::future::Future for LiveReview {
    type Output = Result<Action, tokio::sync::oneshot::error::RecvError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.receiver).poll(cx)
    }
}

impl Drop for LiveReview {
    fn drop(&mut self) {
        self.registry.lock().requests.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_is_stable_across_header_order_and_binds_the_request_identity() {
        let mut first_fields = http::HeaderMap::new();
        first_fields.insert("x-second", "2".parse().unwrap());
        first_fields.insert("x-first", "1".parse().unwrap());
        let first = Headers {
            method: http::Method::POST,
            path: "/api?view=full".into(),
            fields: first_fields,
        };
        let mut second_fields = http::HeaderMap::new();
        second_fields.insert("x-first", "1".parse().unwrap());
        second_fields.insert("x-second", "2".parse().unwrap());
        let second = Headers {
            method: http::Method::POST,
            path: "/api?view=full".into(),
            fields: second_fields,
        };
        let subject_id = SubjectId::new(b"owner-hash".to_vec()).unwrap();

        let expected = RequestId::for_request(&first, "alice.example", &subject_id);
        assert_eq!(
            expected,
            RequestId::for_request(&second, "alice.example", &subject_id)
        );
        assert_ne!(
            expected,
            RequestId::for_request(&second, "bob.example", &subject_id)
        );
    }

    #[test]
    fn review_mode_defaults_to_break_and_rejects_duplicate_headers() {
        let mut fields = http::HeaderMap::new();
        assert_eq!(
            ReviewMode::from_headers(&fields).unwrap(),
            ReviewMode::Break
        );
        fields.append("if-reviewed", "waiting".parse().unwrap());
        fields.append("if-reviewed", "break".parse().unwrap());
        assert!(ReviewMode::from_headers(&fields).is_err());
    }

    #[test]
    fn pending_response_points_to_the_acl_managed_status_resource() {
        let response = PendingReviewResponse::from(PendingReview::new(12));
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({
                "status": "pending_review", "review_id": 12, "status_url": "/std/acl/status?id=12",
            })
        );
    }
}

#[cfg(test)]
mod protocol_tests {
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
    use tower::ServiceExt;

    use super::*;
    use crate::{AccessService, AuthResult, Effect, Grantee, Method};

    async fn service() -> AccessService {
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
        service
    }

    fn headers(mode: &str) -> Headers {
        let mut fields = http::HeaderMap::new();
        fields.insert("if-reviewed", mode.parse().unwrap());
        Headers {
            method: http::Method::POST,
            path: "/deploy?version=1".into(),
            fields,
        }
    }

    #[tokio::test]
    async fn waiting_is_memory_only_until_approval_saves_acl_and_releases_matching_requests() {
        let service = std::sync::Arc::new(service().await);
        let subject = SubjectId::new(b"alice").unwrap();
        let AuthResult::Waiting(first) = service
            .auth(headers("waiting"), Some("alice.example"), Some(&subject))
            .await
            .unwrap()
        else {
            panic!("expected live review")
        };
        let AuthResult::Waiting(second) = service
            .auth(headers("waiting"), Some("alice.example"), Some(&subject))
            .await
            .unwrap()
        else {
            panic!("expected live review")
        };
        assert_eq!(
            service.pending_persistent_reviews(0, 10).await.unwrap().0,
            0
        );
        let live = service.reviews.pending();
        assert_eq!(live.len(), 2);
        let app = crate::management_router(service.clone());
        let decide = |id| {
            http::Request::builder()
                .method("PATCH")
                .uri("/std/acl/review")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({"kind":"live","id":id,"action":"allow","remember":true})
                        .to_string(),
                ))
                .unwrap()
        };
        assert_eq!(
            app.clone()
                .oneshot(decide(live[0].id))
                .await
                .unwrap()
                .status(),
            204
        );
        assert_eq!(first.await.unwrap(), Action::Allow);
        assert_eq!(second.await.unwrap(), Action::Allow);
        assert!(matches!(
            service
                .auth(headers("waiting"), Some("alice.example"), Some(&subject))
                .await
                .unwrap(),
            AuthResult::Allowed
        ));
        assert_eq!(app.oneshot(decide(live[0].id)).await.unwrap().status(), 404);
        let AuthResult::Waiting(cancelled) = service
            .auth(
                headers("waiting"),
                Some("bob.example"),
                Some(&SubjectId::new(b"bob").unwrap()),
            )
            .await
            .unwrap()
        else {
            panic!("expected live review")
        };
        drop(cancelled);
        assert!(service.reviews.pending().is_empty());
        let count = service
            .database()
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT count(*) AS n FROM access_reviews",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(count.try_get::<i64>("", "n").unwrap(), 0);
    }

    #[tokio::test]
    async fn break_deduplicates_metadata_changes_and_approval_writes_durable_acl() {
        let service = service().await;
        let subject = SubjectId::new(b"alice").unwrap();
        let AuthResult::Reviewing(review) = service
            .auth(headers("break"), Some("alice.example"), Some(&subject))
            .await
            .unwrap()
        else {
            panic!("expected persistent review")
        };
        let mut retry = headers("break");
        retry.fields.insert("x-trace", "different".parse().unwrap());
        retry.path = "/deploy?version=2".into();
        assert!(
            matches!(service.auth(retry.clone(), Some("alice.example"), Some(&subject)).await.unwrap(), AuthResult::Reviewing(other) if review.id() == other.id())
        );
        service
            .decide_review(review.id(), Action::Allow, true)
            .await
            .unwrap();
        assert!(matches!(
            service
                .auth(retry.clone(), Some("alice.example"), Some(&subject))
                .await
                .unwrap(),
            AuthResult::Allowed
        ));
        assert!(matches!(
            service
                .auth(retry, Some("alice.example"), Some(&subject))
                .await
                .unwrap(),
            AuthResult::Allowed
        ));
        assert!(service.reviews.pending().is_empty());
    }

    #[tokio::test]
    async fn invalid_mode_and_anonymous_reviews_never_create_requests() {
        let service = service().await;
        assert!(
            service
                .auth(
                    headers("other"),
                    Some("alice.example"),
                    Some(&SubjectId::new(b"alice").unwrap())
                )
                .await
                .is_err()
        );
        for mode in ["waiting", "break"] {
            assert!(matches!(
                service.auth(headers(mode), None, None).await.unwrap(),
                AuthResult::Denied
            ));
        }
        assert!(service.reviews.pending().is_empty());
        assert_eq!(
            service.pending_persistent_reviews(0, 10).await.unwrap().0,
            0
        );
    }
}
