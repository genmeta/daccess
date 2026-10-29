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
