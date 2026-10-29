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
#[path = "../tests/unit/review.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/unit/review_protocol.rs"]
mod protocol_tests;
