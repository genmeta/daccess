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
        let mut fields = vec![(
            b":method".to_vec(),
            headers.method.as_str().as_bytes().to_vec(),
        )];
        fields.push((b":path".to_vec(), headers.path.as_bytes().to_vec()));
        fields.extend(
            headers.fields.iter().map(|(name, value)| {
                (name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec())
            }),
        );
        fields.sort();

        let mut digest = Sha256::new();
        for (name, value) in fields {
            update_digest(&mut digest, &name);
            update_digest(&mut digest, &value);
        }
        update_digest(&mut digest, visitor.as_bytes());
        update_digest(&mut digest, subject_id.as_bytes());

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
    review_id: i64,
    status_url: String,
}

impl From<PendingReview> for PendingReviewResponse {
    fn from(review: PendingReview) -> Self {
        let review_id = review.id();
        Self {
            review_id,
            status_url: format!("/acl/review/{review_id}/status"),
        }
    }
}

/// Identifies the one management route that must not be re-authorized as a
/// business request. The handler still scopes the record to the verified
/// visitor before returning a status.
pub fn is_review_status_path(method: &http::Method, path: &str) -> bool {
    method == http::Method::GET
        && path
            .strip_prefix("/acl/review/")
            .and_then(|path| path.strip_suffix("/status"))
            .is_some_and(|id| id.parse::<i64>().is_ok())
}

/// The state exposed by the visitor's read-only status endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewStatus {
    Pending,
    Allowed,
    Denied,
    Expired,
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
    fn pending_response_and_status_route_are_canonical() {
        let response = PendingReviewResponse::from(PendingReview::new(12));
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({
                "review_id": 12,
                "status_url": "/acl/review/12/status",
            })
        );
        assert!(is_review_status_path(
            &http::Method::GET,
            "/acl/review/12/status"
        ));
        assert!(!is_review_status_path(
            &http::Method::GET,
            "/acl/review/abc/status"
        ));
        assert!(!is_review_status_path(
            &http::Method::POST,
            "/acl/review/12/status"
        ));
    }
}
