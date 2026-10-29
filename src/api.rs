pub mod access;
pub mod contact;
pub mod review;

use std::sync::Arc;

use axum::{Router, routing::get};
pub use contact::{
    ContactPatch, ContactRecord, GrantedAccess, GrantedMethods, NewContact, RequestedAccess,
};
pub use review::ReviewRecord;

use crate::AccessService;

#[derive(Clone)]
pub(crate) struct ApiState {
    pub(crate) service: Arc<AccessService>,
}

pub fn router(service: Arc<AccessService>) -> Router {
    Router::new()
        .route("/std/contact/list", get(contact::list))
        .route(
            "/std/contact",
            get(contact::get)
                .post(contact::create)
                .patch(contact::patch)
                .delete(contact::delete),
        )
        .route(
            "/std/acl/access",
            get(access::list_rules_by_api).post(access::set_by_api),
        )
        .route("/std/acl/apis", get(access::list_apis))
        .route(
            "/std/acl/allow",
            get(access::list_rules_by_name)
                .patch(access::set_by_name)
                .delete(access::delete_by_name),
        )
        .route(
            "/std/acl/review",
            axum::routing::patch(review::decide).delete(review::delete),
        )
        .route("/std/acl/review/list", get(review::list_persistent))
        .route("/std/acl/status", get(review::status))
        .with_state(ApiState { service })
}

pub(crate) type ApiError = (http::StatusCode, String);

pub(crate) fn internal(error: impl std::fmt::Display) -> ApiError {
    (http::StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

pub(crate) fn bad_request(error: impl std::fmt::Display) -> ApiError {
    (http::StatusCode::BAD_REQUEST, error.to_string())
}

pub(crate) fn database(error: sea_orm::DbErr) -> ApiError {
    let status = if matches!(
        error.sql_err(),
        Some(sea_orm::SqlErr::UniqueConstraintViolation(_))
    ) {
        http::StatusCode::CONFLICT
    } else {
        match error {
            sea_orm::DbErr::RecordNotFound(_) => http::StatusCode::NOT_FOUND,
            sea_orm::DbErr::RecordNotUpdated => http::StatusCode::CONFLICT,
            sea_orm::DbErr::Type(_) => http::StatusCode::BAD_REQUEST,
            _ => http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    };
    (status, error.to_string())
}

#[cfg(test)]
#[path = "../tests/unit/api.rs"]
mod tests;
