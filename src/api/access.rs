use std::collections::BTreeMap;

use sea_orm::{
    ConnectionTrait, DatabaseBackend, DbErr, Order, Statement, TransactionTrait, TryGetable,
};
use serde::{Deserialize, Serialize};

use crate::{
    AccessService, Effect, Grantee, Method,
    pagination::{Page, PageQuery, order_sql},
    policy::database_api,
};

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Sort {
    Api,
    #[default]
    UpdatedAt,
}

impl Sort {
    fn column(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::UpdatedAt => "updated_at",
        }
    }
}

#[derive(Serialize)]
pub(crate) struct AccessApiResponse {
    api: String,
    updated_at: i64,
}

#[derive(Deserialize)]
pub(crate) struct AccessRuleBody {
    method: String,
    effect: String,
    grantee: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessRuleByNameBody {
    method: String,
    api: String,
    effect: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteRuleByNameBody {
    method: String,
    api: String,
}

#[derive(Default, Serialize)]
pub(crate) struct EffectItems {
    allow: Vec<String>,
    review: Vec<String>,
    deny: Vec<String>,
}

impl EffectItems {
    fn push(&mut self, effect: Effect, value: String) {
        match effect {
            Effect::Allow => self.allow.push(value),
            Effect::Review => self.review.push(value),
            Effect::Deny => self.deny.push(value),
        }
    }
}

pub(crate) type RulesByApiTree = BTreeMap<String, BTreeMap<String, EffectItems>>;
pub(crate) type RulesByNameTree = BTreeMap<String, BTreeMap<String, EffectItems>>;
pub(crate) type RulesByMethod = BTreeMap<String, EffectItems>;

impl AccessService {
    pub(crate) async fn validate_management_administrators(
        db: &impl ConnectionTrait,
        owner_name: &str,
    ) -> Result<(), DbErr> {
        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT method, api, effect, grantee_type, grantee FROM access_rules \
                 WHERE api = '/std/acl' OR api LIKE '/std/acl/%'",
            ))
            .await?;
        let mut scopes = BTreeMap::<(String, String), (Option<Effect>, bool)>::new();
        for row in rows {
            let method = String::try_get(&row, "", "method")?;
            let api = String::try_get(&row, "", "api")?;
            let effect = String::try_get(&row, "", "effect")?.parse::<Effect>()?;
            let grantee_type = i32::try_get(&row, "", "grantee_type")?;
            let grantee = String::try_get(&row, "", "grantee")?;
            let scope = scopes.entry((method, api)).or_default();
            if grantee_type == 0 && grantee == owner_name {
                scope.0 = Some(effect);
            } else if effect == Effect::Allow && matches!(grantee_type, 0 | 1) {
                scope.1 = true;
            }
        }
        if let Some(((method, api), _)) =
            scopes
                .into_iter()
                .find(|(_, (owner_effect, has_other_administrator))| {
                    matches!(owner_effect, Some(Effect::Review | Effect::Deny))
                        && !has_other_administrator
                })
        {
            return Err(DbErr::Type(format!(
                "management API {method} {api:?} must keep at least one named or group administrator with allow access"
            )));
        }
        Ok(())
    }

    async fn list_all_rules_by_api(&self) -> Result<RulesByApiTree, DbErr> {
        let rows = self
            .db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT api, method, effect, grantee FROM access_rules \
                 ORDER BY api, method, effect, grantee",
            ))
            .await?;
        let mut tree = RulesByApiTree::new();
        for row in rows {
            let api = String::try_get(&row, "", "api")?;
            let method = String::try_get(&row, "", "method")?;
            let effect = String::try_get(&row, "", "effect")?.parse()?;
            let grantee = String::try_get(&row, "", "grantee")?;
            let rules = tree.entry(api).or_default().entry(method).or_default();
            rules.push(effect, grantee);
        }
        Ok(tree)
    }

    async fn list_all_rules_by_name(&self) -> Result<RulesByNameTree, DbErr> {
        let rows = self
            .db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT grantee, api, effect, method FROM access_rules \
                 ORDER BY grantee, api, effect, method",
            ))
            .await?;
        let mut tree = RulesByNameTree::new();
        for row in rows {
            let grantee = String::try_get(&row, "", "grantee")?;
            let api = String::try_get(&row, "", "api")?;
            let effect = String::try_get(&row, "", "effect")?.parse()?;
            let method = String::try_get(&row, "", "method")?;
            let rules = tree.entry(grantee).or_default().entry(api).or_default();
            rules.push(effect, method);
        }
        Ok(tree)
    }

    async fn list_apis(
        &self,
        offset: i64,
        limit: i64,
        sort: Sort,
        order: Order,
    ) -> Result<(u64, Vec<AccessApiResponse>), DbErr> {
        let total = self
            .db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(DISTINCT api) AS total FROM access_rules",
            ))
            .await?
            .expect("aggregate query always returns one row");
        let total = i64::try_get(&total, "", "total")? as u64;
        let sql = format!(
            "SELECT api, MAX(updated_at) AS updated_at FROM access_rules \
             GROUP BY api ORDER BY {} {}, api ASC LIMIT ? OFFSET ?",
            sort.column(),
            order_sql(&order)
        );
        let items = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                sql,
                [limit.into(), offset.into()],
            ))
            .await?
            .into_iter()
            .map(|row| {
                Ok(AccessApiResponse {
                    api: String::try_get(&row, "", "api")?,
                    updated_at: i64::try_get(&row, "", "updated_at")?,
                })
            })
            .collect::<Result<_, DbErr>>()?;
        Ok((total, items))
    }

    async fn list_rules_by_name(
        &self,
        name: &str,
        offset: i64,
        limit: i64,
        sort: Sort,
        order: Order,
    ) -> Result<(u64, RulesByApiTree), DbErr> {
        if name.is_empty() {
            return Err(DbErr::Type(String::from("contact name cannot be empty")));
        }
        let total = self
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(DISTINCT api) AS total FROM access_rules WHERE grantee = ?",
                [name.into()],
            ))
            .await?
            .expect("aggregate query always returns one row");
        let total = i64::try_get(&total, "", "total")? as u64;
        let sort = sort.column();
        let order = order_sql(&order);
        let sql = format!(
            "WITH apis AS (\
                 SELECT api, MAX(updated_at) AS updated_at FROM access_rules \
                 WHERE grantee = ? GROUP BY api \
                 ORDER BY {sort} {order}, api ASC LIMIT ? OFFSET ?\
             ) \
             SELECT access_rules.api, access_rules.method, access_rules.effect, \
                    access_rules.grantee \
             FROM apis JOIN access_rules \
               ON access_rules.api = apis.api AND access_rules.grantee = ? \
             ORDER BY apis.{sort} {order}, apis.api ASC, \
                      access_rules.method ASC, access_rules.effect ASC"
        );
        let rows = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                sql,
                [name.into(), limit.into(), offset.into(), name.into()],
            ))
            .await?;
        let mut tree = RulesByApiTree::new();
        for row in rows {
            let api = String::try_get(&row, "", "api")?;
            let method = String::try_get(&row, "", "method")?;
            let effect = String::try_get(&row, "", "effect")?.parse()?;
            let grantee = String::try_get(&row, "", "grantee")?;
            let rules = tree.entry(api).or_default().entry(method).or_default();
            rules.push(effect, grantee);
        }
        Ok((total, tree))
    }

    async fn list_rules_by_api(&self, api: &str) -> Result<RulesByMethod, DbErr> {
        if !api.starts_with('/') {
            return Err(DbErr::Type(format!("invalid access API {api:?}")));
        }
        let api = database_api(api);
        let rows = self
            .db
            .query_all_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT method, effect, grantee FROM access_rules \
                 WHERE api = ? ORDER BY method, effect, grantee",
                [api.into()],
            ))
            .await?;
        let mut rules = RulesByMethod::new();
        for row in rows {
            let method = String::try_get(&row, "", "method")?;
            let effect = String::try_get(&row, "", "effect")?.parse()?;
            let grantee = String::try_get(&row, "", "grantee")?;
            let rules = rules.entry(method).or_default();
            rules.push(effect, grantee);
        }
        Ok(rules)
    }

    pub async fn set_policy(
        &self,
        method: Method,
        api: &str,
        effect: Effect,
        grantee: Grantee,
    ) -> Result<(), DbErr> {
        if !api.starts_with('/') {
            return Err(DbErr::Type(format!("invalid access API {api:?}")));
        }
        let mut policies = self.policies.write().await;
        let transaction = self.db.begin().await?;
        if let Grantee::One(name) = &grantee
            && name != &self.owner_name
            && transaction
                .query_one_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "SELECT 1 FROM contacts WHERE name = ?",
                    [name.as_str().into()],
                ))
                .await?
                .is_none()
        {
            return Err(DbErr::Type(format!("contact {name:?} does not exist")));
        }
        let method_value = method.to_string();
        let api_value = database_api(api);
        for conflict in grantee.conflicts() {
            transaction
                .execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "DELETE FROM access_rules WHERE method = ? AND api = ? AND grantee = ?",
                    [
                        method_value.clone().into(),
                        api_value.clone().into(),
                        conflict.to_string().into(),
                    ],
                ))
                .await?;
        }
        transaction.execute_raw(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
            r#"INSERT INTO access_rules (method, api, effect, grantee_type, grantee, updated_at, created_at)
               VALUES (?, ?, ?, ?, ?, CAST(strftime('%s', 'now') AS INTEGER), CAST(strftime('%s', 'now') AS INTEGER))
               ON CONFLICT(grantee, method, api) DO UPDATE SET effect = excluded.effect, grantee_type = excluded.grantee_type, updated_at = excluded.updated_at"#,
            [method_value.into(), api_value.into(), effect.as_str().into(), grantee.key().into(), grantee.to_string().into()])).await?;
        Self::validate_management_administrators(&transaction, &self.owner_name).await?;
        let next_policies = Self::policies_from_db(&transaction, &self.owner_name).await?;
        transaction.commit().await?;
        *policies = next_policies;
        Ok(())
    }

    pub async fn remove_policy(
        &self,
        method: Method,
        api: &str,
        grantee: Grantee,
    ) -> Result<(), DbErr> {
        if !api.starts_with('/') {
            return Err(DbErr::Type(format!("invalid access API {api:?}")));
        }
        let mut policies = self.policies.write().await;
        let transaction = self.db.begin().await?;
        transaction
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "DELETE FROM access_rules WHERE method = ? AND api = ? AND grantee = ?",
                [
                    method.to_string().into(),
                    database_api(api).into(),
                    grantee.to_string().into(),
                ],
            ))
            .await?;
        Self::validate_management_administrators(&transaction, &self.owner_name).await?;
        let next_policies = Self::policies_from_db(&transaction, &self.owner_name).await?;
        transaction.commit().await?;
        *policies = next_policies;
        Ok(())
    }
}

pub(crate) async fn list_apis(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Query(query): axum::extract::Query<PageQuery<Sort>>,
) -> Result<axum::Json<Page<Vec<AccessApiResponse>>>, crate::api::ApiError> {
    let pagination = query.pagination();
    let (offset, limit) = pagination.offset_limit()?;
    let (total, items) = state
        .service
        .list_apis(offset, limit, query.sort, query.order)
        .await
        .map_err(crate::api::database)?;
    Ok(axum::Json(Page::new(items, total, pagination)))
}

pub(crate) async fn list_all_rules_by_api(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
) -> Result<axum::Json<RulesByApiTree>, crate::api::ApiError> {
    Ok(axum::Json(
        state
            .service
            .list_all_rules_by_api()
            .await
            .map_err(crate::api::database)?,
    ))
}

pub(crate) async fn list_all_rules_by_name(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
) -> Result<axum::Json<RulesByNameTree>, crate::api::ApiError> {
    Ok(axum::Json(
        state
            .service
            .list_all_rules_by_name()
            .await
            .map_err(crate::api::database)?,
    ))
}

pub(crate) async fn list_rules_by_name(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<PageQuery<Sort>>,
) -> Result<axum::Json<Page<RulesByApiTree>>, crate::api::ApiError> {
    let pagination = query.pagination();
    let (offset, limit) = pagination.offset_limit()?;
    let (total, items) = state
        .service
        .list_rules_by_name(&name, offset, limit, query.sort, query.order)
        .await
        .map_err(crate::api::database)?;
    Ok(axum::Json(Page::new(items, total, pagination)))
}

pub(crate) async fn list_rules_by_api(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Path(api): axum::extract::Path<String>,
) -> Result<axum::Json<RulesByMethod>, crate::api::ApiError> {
    let api = api_from_path(api);
    Ok(axum::Json(
        state
            .service
            .list_rules_by_api(&api)
            .await
            .map_err(crate::api::database)?,
    ))
}

pub(crate) async fn set_by_api(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Path(api): axum::extract::Path<String>,
    axum::Json(body): axum::Json<AccessRuleBody>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    set_rule(
        &state,
        &api_from_path(api),
        body.method,
        body.effect,
        body.grantee,
    )
    .await
}

pub(crate) async fn set_by_name(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::Json(body): axum::Json<AccessRuleByNameBody>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    set_rule(&state, &body.api, body.method, body.effect, name).await
}

async fn set_rule(
    state: &crate::api::ApiState,
    api: &str,
    method: String,
    effect: String,
    grantee: String,
) -> Result<http::StatusCode, crate::api::ApiError> {
    let method = method.parse().map_err(crate::api::bad_request)?;
    let effect = effect.parse().map_err(crate::api::bad_request)?;
    let grantee = grantee.parse().map_err(crate::api::bad_request)?;
    state
        .service
        .set_policy(method, api, effect, grantee)
        .await
        .map_err(crate::api::database)?;
    Ok(http::StatusCode::NO_CONTENT)
}

pub(crate) async fn delete_by_name(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::Json(body): axum::Json<DeleteRuleByNameBody>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    delete_rule(&state, &body.api, body.method, name).await
}

async fn delete_rule(
    state: &crate::api::ApiState,
    api: &str,
    method: String,
    grantee: String,
) -> Result<http::StatusCode, crate::api::ApiError> {
    let method = method.parse().map_err(crate::api::bad_request)?;
    let grantee = grantee.parse().map_err(crate::api::bad_request)?;
    state
        .service
        .remove_policy(method, api, grantee)
        .await
        .map_err(crate::api::database)?;
    Ok(http::StatusCode::NO_CONTENT)
}

fn api_from_path(api: String) -> String {
    format!("/{}", api.trim_start_matches('/'))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http_body_util::BodyExt;
    use sea_orm::{ConnectionTrait, Database};
    use tower::ServiceExt;

    use super::*;

    async fn service() -> AccessService {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(include_str!("../migrations/0.sql"))
            .await
            .unwrap();
        AccessService::new(db, "owner.example")
    }

    #[tokio::test]
    async fn set_list_update_and_delete_rule_stay_in_sync() {
        let service = service().await;
        let grantee = Grantee::Named;
        service
            .set_policy(
                Method::Specified(http::Method::GET),
                "/api/",
                Effect::Allow,
                grantee.clone(),
            )
            .await
            .unwrap();
        let rules = service.list_rules_by_api("/api").await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules["GET"].allow, ["**"]);
        assert!(rules["GET"].review.is_empty());
        assert!(rules["GET"].deny.is_empty());
        assert_eq!(
            service
                .policies
                .read()
                .await
                .evaluate(&http::Method::GET, "/api/item", &[grantee.clone()])
                .0,
            Effect::Allow
        );
        service
            .set_policy(
                Method::Specified(http::Method::GET),
                "/api",
                Effect::Review,
                grantee.clone(),
            )
            .await
            .unwrap();
        let rules = service.list_rules_by_api("/api").await.unwrap();
        assert_eq!(rules["GET"].review, ["**"]);
        service
            .remove_policy(
                Method::Specified(http::Method::GET),
                "/api",
                grantee.clone(),
            )
            .await
            .unwrap();
        assert!(service.list_rules_by_api("/api").await.unwrap().is_empty());
        assert_eq!(
            service
                .policies
                .read()
                .await
                .evaluate(&http::Method::GET, "/api", &[grantee])
                .0,
            Effect::Deny
        );
    }

    #[tokio::test]
    async fn invalid_api_does_not_touch_database_or_memory() {
        let service = service().await;
        assert!(
            service
                .set_policy(Method::Unspecified, "relative", Effect::Allow, Grantee::All)
                .await
                .is_err()
        );
        let (total, apis) = service
            .list_apis(0, 20, Sort::UpdatedAt, Order::Desc)
            .await
            .unwrap();
        assert_eq!(total, 0);
        assert!(apis.is_empty());
        assert_eq!(
            service
                .policies
                .read()
                .await
                .evaluate(&http::Method::GET, "/", &[Grantee::All])
                .0,
            Effect::Deny
        );
    }

    #[tokio::test]
    async fn anyone_and_named_rules_remain_mutually_exclusive() {
        let service = service().await;
        service
            .set_policy(Method::Unspecified, "/", Effect::Allow, Grantee::All)
            .await
            .unwrap();
        service
            .set_policy(Method::Unspecified, "/", Effect::Review, Grantee::Named)
            .await
            .unwrap();
        let rules = service.list_rules_by_api("/").await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules["*"].review, ["**"]);
        assert!(rules["*"].allow.is_empty());
        assert!(rules["*"].deny.is_empty());
    }

    #[tokio::test]
    async fn http_lists_apis_by_page_and_one_api_complete_rules() {
        let service = Arc::new(service().await);
        for (api, method) in [
            ("/older", http::Method::GET),
            ("/newer", http::Method::GET),
            ("/newer", http::Method::POST),
        ] {
            service
                .set_policy(
                    Method::Specified(method),
                    api,
                    Effect::Allow,
                    Grantee::Named,
                )
                .await
                .unwrap();
        }
        service
            .set_policy(
                Method::Specified(http::Method::GET),
                "/newer",
                Effect::Review,
                Grantee::Group {
                    title: String::from("admin"),
                    issuer: String::from("example"),
                },
            )
            .await
            .unwrap();
        service
            .set_policy(
                Method::Specified(http::Method::GET),
                "/newer",
                Effect::Deny,
                Grantee::Anony,
            )
            .await
            .unwrap();
        service
            .db
            .execute_unprepared(
                "UPDATE access_rules SET updated_at = CASE api WHEN '/older' THEN 1 ELSE 2 END",
            )
            .await
            .unwrap();

        let app = crate::api::router(service);
        let response = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri("/std/acl/apis?page=1&page_size=1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["page"], 1);
        assert_eq!(body["page_size"], 1);
        assert_eq!(body["total"], 2);
        assert_eq!(body["items"][0]["api"], "/newer");

        let response = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri("/std/acl/apis?page=2&page_size=1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["items"][0]["api"], "/older");

        let response = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri("/std/acl/apis?page_size=1&sort=api&order=desc")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["items"][0]["api"], "/older");

        let response = app
            .oneshot(
                http::Request::builder()
                    .uri("/std/acl/access/newer")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "GET": {
                    "allow": ["**"],
                    "review": ["admin@example"],
                    "deny": ["?"]
                },
                "POST": {
                    "allow": ["**"],
                    "review": [],
                    "deny": []
                }
            })
        );
    }

    #[tokio::test]
    async fn http_lists_all_rules_as_api_method_effect_tree() {
        let service = Arc::new(service().await);
        for (method, effect, grantee) in [
            (
                Method::Specified(http::Method::GET),
                Effect::Allow,
                Grantee::Named,
            ),
            (
                Method::Specified(http::Method::GET),
                Effect::Review,
                Grantee::Group {
                    title: String::from("admin"),
                    issuer: String::from("example"),
                },
            ),
            (
                Method::Specified(http::Method::GET),
                Effect::Deny,
                Grantee::Anony,
            ),
            (
                Method::Specified(http::Method::POST),
                Effect::Allow,
                Grantee::All,
            ),
        ] {
            service
                .set_policy(method, "/api/2", effect, grantee)
                .await
                .unwrap();
        }

        let app = crate::api::router(service);
        let response = app
            .clone()
            .oneshot(
                http::Request::builder()
                    .uri("/std/acl/access")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "/api/2": {
                    "GET": {
                        "allow": ["**"],
                        "review": ["admin@example"],
                        "deny": ["?"]
                    },
                    "POST": {
                        "allow": ["*?"],
                        "review": [],
                        "deny": []
                    }
                }
            })
        );

        let response = app
            .oneshot(
                http::Request::builder()
                    .uri("/std/acl/access/api/2")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["GET"]["allow"], serde_json::json!(["**"]));
        assert_eq!(body["POST"]["allow"], serde_json::json!(["*?"]));
    }

    #[tokio::test]
    async fn http_lists_all_allow_rules_by_grantee_and_api() {
        let service = Arc::new(service().await);
        service
            .db
            .execute_unprepared(
                "INSERT INTO contacts \
                 (name, subject_id, status, expired_after, updated_at, created_at) \
                 VALUES ('alice.smith~', X'01', 2, 100, 1, 1)",
            )
            .await
            .unwrap();
        for (method, effect) in [
            (http::Method::GET, Effect::Allow),
            (http::Method::POST, Effect::Allow),
            (http::Method::PATCH, Effect::Review),
            (http::Method::DELETE, Effect::Deny),
        ] {
            service
                .set_policy(
                    Method::Specified(method),
                    "/api/v2",
                    effect,
                    Grantee::One(String::from("alice.smith~")),
                )
                .await
                .unwrap();
        }

        let response = crate::api::router(service)
            .oneshot(
                http::Request::builder()
                    .uri("/std/acl/allow")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "alice.smith~": {
                    "/api/v2": {
                        "allow": ["GET", "POST"],
                        "review": ["PATCH"],
                        "deny": ["DELETE"]
                    }
                }
            })
        );
    }

    #[tokio::test]
    async fn http_lists_one_contacts_rules_by_api_page() {
        let service = Arc::new(service().await);
        service
            .db
            .execute_unprepared(
                "INSERT INTO contacts \
                 (name, subject_id, status, expired_after, updated_at, created_at) \
                 VALUES ('alice.smith~', X'01', 2, 100, 1, 1)",
            )
            .await
            .unwrap();
        for (api, method, effect) in [
            ("/api/1", http::Method::GET, Effect::Deny),
            ("/api/2", http::Method::GET, Effect::Allow),
            ("/api/2", http::Method::PATCH, Effect::Review),
        ] {
            service
                .set_policy(
                    Method::Specified(method),
                    api,
                    effect,
                    Grantee::One(String::from("alice.smith~")),
                )
                .await
                .unwrap();
        }
        service
            .db
            .execute_unprepared(
                "UPDATE access_rules SET updated_at = CASE api WHEN '/api/1' THEN 1 ELSE 2 END",
            )
            .await
            .unwrap();

        let response = crate::api::router(service)
            .oneshot(
                http::Request::builder()
                    .uri("/std/acl/allow/alice.smith~?page=1&page_size=1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["total"], 2);
        assert_eq!(body["page"], 1);
        assert_eq!(body["page_size"], 1);
        assert_eq!(
            body["items"],
            serde_json::json!({
                "/api/2": {
                    "GET": {
                        "allow": ["alice.smith~"],
                        "review": [],
                        "deny": []
                    },
                    "PATCH": {
                        "allow": [],
                        "review": ["alice.smith~"],
                        "deny": []
                    }
                }
            })
        );
    }

    #[tokio::test]
    async fn management_apis_always_keep_one_named_or_group_administrator() {
        let service = Arc::new(service().await);
        service
            .db
            .execute_unprepared(
                r#"INSERT INTO contacts
                   (name, subject_id, status, expired_after, updated_at, created_at)
                   VALUES ('alice.example', X'01', 2, 100, 1, 1),
                          ('bob.example', X'02', 2, 100, 1, 1)"#,
            )
            .await
            .unwrap();
        let app = crate::api::router(service);
        let rule = |method: http::Method, api: &str, effect: &str, grantee: &str| {
            let (uri, body) = if method == http::Method::POST {
                (
                    format!("/std/acl/access/{}", api.trim_start_matches('/')),
                    format!(r#"{{"method":"GET","effect":"{effect}","grantee":"{grantee}"}}"#),
                )
            } else {
                (
                    format!("/std/acl/allow/{grantee}"),
                    format!(r#"{{"method":"GET","api":"{api}","effect":"{effect}"}}"#),
                )
            };
            http::Request::builder()
                .method(method)
                .uri(uri)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body))
                .unwrap()
        };

        assert_eq!(
            app.clone()
                .oneshot(rule(
                    http::Method::POST,
                    "/business",
                    "deny",
                    "owner.example",
                ))
                .await
                .unwrap()
                .status(),
            http::StatusCode::NO_CONTENT
        );
        assert_eq!(
            app.clone()
                .oneshot(rule(
                    http::Method::POST,
                    "/business",
                    "allow",
                    "bob.example",
                ))
                .await
                .unwrap()
                .status(),
            http::StatusCode::NO_CONTENT
        );
        let delete_business_administrator = http::Request::builder()
            .method(http::Method::DELETE)
            .uri("/std/contact/bob.example")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(delete_business_administrator)
                .await
                .unwrap()
                .status(),
            http::StatusCode::NO_CONTENT
        );
        assert_eq!(
            app.clone()
                .oneshot(rule(
                    http::Method::POST,
                    "/std/acl",
                    "deny",
                    "owner.example",
                ))
                .await
                .unwrap()
                .status(),
            http::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            app.clone()
                .oneshot(rule(
                    http::Method::POST,
                    "/std/acl",
                    "allow",
                    "alice.example",
                ))
                .await
                .unwrap()
                .status(),
            http::StatusCode::NO_CONTENT
        );
        assert_eq!(
            app.clone()
                .oneshot(rule(
                    http::Method::POST,
                    "/std/acl",
                    "deny",
                    "owner.example",
                ))
                .await
                .unwrap()
                .status(),
            http::StatusCode::NO_CONTENT
        );

        let delete = http::Request::builder()
            .method(http::Method::DELETE)
            .uri("/std/acl/allow/alice.example")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                r#"{"method":"GET","api":"/std/acl"}"#,
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(delete).await.unwrap().status(),
            http::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            app.clone()
                .oneshot(rule(
                    http::Method::PATCH,
                    "/std/acl",
                    "review",
                    "alice.example",
                ))
                .await
                .unwrap()
                .status(),
            http::StatusCode::BAD_REQUEST
        );
        let delete_contact = http::Request::builder()
            .method(http::Method::DELETE)
            .uri("/std/contact/alice.example")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(delete_contact).await.unwrap().status(),
            http::StatusCode::BAD_REQUEST
        );

        assert_eq!(
            app.clone()
                .oneshot(rule(
                    http::Method::POST,
                    "/std/acl",
                    "allow",
                    "admin@example",
                ))
                .await
                .unwrap()
                .status(),
            http::StatusCode::NO_CONTENT
        );
        assert_eq!(
            app.clone()
                .oneshot(rule(
                    http::Method::PATCH,
                    "/std/acl",
                    "review",
                    "alice.example",
                ))
                .await
                .unwrap()
                .status(),
            http::StatusCode::NO_CONTENT
        );

        let delete_group = http::Request::builder()
            .method(http::Method::DELETE)
            .uri("/std/acl/allow/admin@example")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                r#"{"method":"GET","api":"/std/acl"}"#,
            ))
            .unwrap();
        assert_eq!(
            app.oneshot(delete_group).await.unwrap().status(),
            http::StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn concurrent_changes_cannot_remove_every_management_api_administrator() {
        let service = service().await;
        let method = Method::Specified(http::Method::GET);
        service
            .db
            .execute_unprepared(
                r#"INSERT INTO contacts
                   (name, subject_id, status, expired_after, updated_at, created_at)
                   VALUES ('alice.example', X'01', 2, 100, 1, 1),
                          ('bob.example', X'02', 2, 100, 1, 1)"#,
            )
            .await
            .unwrap();
        for name in ["alice.example", "bob.example"] {
            service
                .set_policy(
                    method.clone(),
                    "/std/acl",
                    Effect::Allow,
                    Grantee::One(name.into()),
                )
                .await
                .unwrap();
        }
        service
            .set_policy(
                method.clone(),
                "/std/acl",
                Effect::Deny,
                Grantee::One("owner.example".into()),
            )
            .await
            .unwrap();

        let (alice, bob) = tokio::join!(
            service.remove_policy(
                method.clone(),
                "/std/acl",
                Grantee::One("alice.example".into()),
            ),
            service.remove_policy(method, "/std/acl", Grantee::One("bob.example".into()),),
        );

        assert_ne!(alice.is_ok(), bob.is_ok());
        let administrators = service
            .db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS count FROM access_rules WHERE method = 'GET' AND api = '/std/acl' AND effect = 'allow' AND grantee_type IN (0, 1)",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(i64::try_get(&administrators, "", "count").unwrap(), 1);
    }
}
