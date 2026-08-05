use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};

use sha2::{Digest, Sha256};

use crate::SubjectId;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RequestId(pub String);

impl RequestId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

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
    pub request_id: Option<RequestId>,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(display("Request reset"))]
pub struct RequestResetError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Default)]
pub enum ReviewState {
    #[default]
    Inited,
    Pending(Waker),
    Reviewed(Action),
    Cancelled,
}

#[derive(Clone, Debug, Default)]
pub struct ArcReviewState(Arc<Mutex<ReviewState>>);

impl ArcReviewState {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_guard(&self) -> std::sync::MutexGuard<'_, ReviewState> {
        self.0.lock().expect("review state poisoned")
    }

    pub fn approve(&self) {
        self.review(Action::Allow);
    }

    pub fn reject(&self) {
        self.review(Action::Deny);
    }

    pub fn cancel(&self) {
        let waker = {
            let mut state = self.lock_guard();
            let waker = match &*state {
                ReviewState::Inited => None,
                ReviewState::Pending(waker) => Some(waker.clone()),
                ReviewState::Reviewed(_) | ReviewState::Cancelled => return,
            };
            *state = ReviewState::Cancelled;
            waker
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn review(&self, action: Action) {
        let waker = {
            let mut state = self.lock_guard();
            let waker = match &*state {
                ReviewState::Inited => None,
                ReviewState::Pending(waker) => Some(waker.clone()),
                ReviewState::Reviewed(_) | ReviewState::Cancelled => return,
            };
            *state = ReviewState::Reviewed(action);
            waker
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Future for ArcReviewState {
    type Output = Result<Action, RequestResetError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.lock_guard();
        match &mut *state {
            ReviewState::Inited => {
                *state = ReviewState::Pending(cx.waker().clone());
                Poll::Pending
            }
            ReviewState::Pending(waker) => {
                if !waker.will_wake(cx.waker()) {
                    *waker = cx.waker().clone();
                }
                Poll::Pending
            }
            ReviewState::Reviewed(action) => Poll::Ready(Ok(*action)),
            ReviewState::Cancelled => Poll::Ready(Err(RequestResetError)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReviewingRequest {
    headers: Headers,
    name: Option<String>,
    subject_id: Option<SubjectId>,
    reason: String,
}

impl ReviewingRequest {
    pub fn new(
        headers: Headers,
        name: Option<String>,
        subject_id: Option<SubjectId>,
        reason: String,
    ) -> Self {
        Self {
            headers,
            name,
            subject_id,
            reason,
        }
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn subject_id(&self) -> Option<&SubjectId> {
        self.subject_id.as_ref()
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Debug)]
pub struct ReviewRegistry {
    idx_generator: AtomicU64,
    requests: HashMap<u64, ReviewingRequest>,
    states: HashMap<u64, ArcReviewState>,
    request_ids: HashSet<RequestId>,
}

impl Default for ReviewRegistry {
    fn default() -> Self {
        Self {
            idx_generator: AtomicU64::new(0),
            requests: HashMap::new(),
            states: HashMap::new(),
            request_ids: HashSet::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ArcReviewRegistry(Arc<Mutex<ReviewRegistry>>);

impl ArcReviewRegistry {
    pub fn add(&self, request: ReviewingRequest) -> (u64, ArcReviewState) {
        let mut registry = self.0.lock().expect("review registry poisoned");
        let id = registry.idx_generator.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(request_id) = &request.headers.request_id {
            registry.request_ids.insert(request_id.clone());
        }
        registry.requests.insert(id, request);
        let state = ArcReviewState::new();
        registry.states.insert(id, state.clone());
        (id, state)
    }

    pub fn del(&self, id: u64) -> bool {
        let mut registry = self.0.lock().expect("review registry poisoned");
        let existed = registry.requests.remove(&id).is_some();
        registry.states.remove(&id);
        existed
    }

    pub fn approve(&self, id: u64) -> bool {
        self.review(id, Action::Allow)
    }

    pub fn reject(&self, id: u64) -> bool {
        self.review(id, Action::Deny)
    }

    pub fn contains_request_id(&self, request_id: &RequestId) -> bool {
        self.0
            .lock()
            .expect("review registry poisoned")
            .request_ids
            .contains(request_id)
    }

    pub(crate) fn pending(&self) -> Vec<(u64, ReviewingRequest)> {
        let registry = self.0.lock().expect("review registry poisoned");
        registry
            .requests
            .iter()
            .filter_map(|(id, request)| {
                let state = registry.states.get(id)?.lock_guard();
                matches!(*state, ReviewState::Inited | ReviewState::Pending(_))
                    .then(|| (*id, request.clone()))
            })
            .collect()
    }

    fn review(&self, id: u64, action: Action) -> bool {
        let states = {
            let mut registry = self.0.lock().expect("review registry poisoned");
            let Some(request) = registry.requests.get(&id) else {
                return false;
            };
            let request_id = request.headers.request_id.clone();
            let ids = match &request_id {
                Some(request_id) => registry
                    .requests
                    .iter()
                    .filter_map(|(id, request)| {
                        (request.headers.request_id.as_ref() == Some(request_id)).then_some(*id)
                    })
                    .collect::<Vec<_>>(),
                None => vec![id],
            };
            if let Some(request_id) = request_id {
                registry.request_ids.remove(&request_id);
            }
            ids.into_iter()
                .filter_map(|id| registry.states.get(&id).cloned())
                .collect::<Vec<_>>()
        };

        for state in states {
            match action {
                Action::Allow => state.approve(),
                Action::Deny => state.reject(),
            }
        }
        true
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
            request_id: None,
        };
        let mut second_fields = http::HeaderMap::new();
        second_fields.insert("x-first", "1".parse().unwrap());
        second_fields.insert("x-second", "2".parse().unwrap());
        let second = Headers {
            method: http::Method::POST,
            path: "/api?view=full".into(),
            fields: second_fields,
            request_id: None,
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
        assert_ne!(
            expected,
            RequestId::for_request(
                &second,
                "alice.example",
                &SubjectId::new(b"changed-owner-hash".to_vec()).unwrap(),
            )
        );
    }

    fn request(request_id: Option<&str>, path: &str) -> ReviewingRequest {
        ReviewingRequest::new(
            Headers {
                method: http::Method::GET,
                path: path.into(),
                fields: http::HeaderMap::new(),
                request_id: request_id.map(RequestId::new),
            },
            Some(String::from("alice.example")),
            None,
            String::from("test review"),
        )
    }

    fn context() -> Context<'static> {
        Context::from_waker(Waker::noop())
    }

    #[test]
    fn one_approval_completes_all_live_requests_with_same_request_id() {
        let reviews = ArcReviewRegistry::default();
        let (first, mut first_state) = reviews.add(request(Some("same"), "/one"));
        let (_, mut second_state) = reviews.add(request(Some("same"), "/two"));
        let mut cx = context();

        assert!(Pin::new(&mut first_state).poll(&mut cx).is_pending());
        assert!(Pin::new(&mut second_state).poll(&mut cx).is_pending());
        assert!(reviews.approve(first));
        assert!(matches!(
            Pin::new(&mut first_state).poll(&mut cx),
            Poll::Ready(Ok(Action::Allow))
        ));
        assert!(matches!(
            Pin::new(&mut second_state).poll(&mut cx),
            Poll::Ready(Ok(Action::Allow))
        ));
        assert!(!reviews.contains_request_id(&RequestId::new("same")));
    }

    #[test]
    fn approval_without_request_id_only_completes_selected_request() {
        let reviews = ArcReviewRegistry::default();
        let (first, mut first_state) = reviews.add(request(None, "/one"));
        let (_, mut second_state) = reviews.add(request(None, "/two"));
        let mut cx = context();

        assert!(Pin::new(&mut first_state).poll(&mut cx).is_pending());
        assert!(Pin::new(&mut second_state).poll(&mut cx).is_pending());
        assert!(reviews.reject(first));
        assert!(matches!(
            Pin::new(&mut first_state).poll(&mut cx),
            Poll::Ready(Ok(Action::Deny))
        ));
        assert!(Pin::new(&mut second_state).poll(&mut cx).is_pending());
    }

    #[test]
    fn cancelled_state_survives_registry_deletion() {
        let reviews = ArcReviewRegistry::default();
        let (id, mut state) = reviews.add(request(None, "/one"));
        let mut cx = context();

        assert!(Pin::new(&mut state).poll(&mut cx).is_pending());
        state.cancel();
        assert!(reviews.del(id));
        assert!(matches!(
            Pin::new(&mut state).poll(&mut cx),
            Poll::Ready(Err(RequestResetError))
        ));
    }
}
