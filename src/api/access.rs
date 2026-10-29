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

#[derive(Deserialize)]
pub(crate) struct ApiQuery {
    api: Option<String>,
}

impl ApiQuery {
    fn validated(self) -> Result<Option<String>, crate::api::ApiError> {
        if self.api.as_ref().is_some_and(|api| !api.starts_with('/')) {
            return Err(crate::api::bad_request("api must start with /"));
        }
        Ok(self.api)
    }
    fn required(self) -> Result<String, crate::api::ApiError> {
        self.validated()?
            .ok_or_else(|| crate::api::bad_request("api is required"))
    }
}

#[derive(Deserialize)]
pub(crate) struct NameQuery {
    name: Option<String>,
}

impl NameQuery {
    fn validated(self) -> Result<Option<String>, crate::api::ApiError> {
        if let Some(name) = &self.name {
            name.parse::<Grantee>().map_err(crate::api::bad_request)?;
        }
        Ok(self.name)
    }
    fn required(self) -> Result<String, crate::api::ApiError> {
        self.validated()?
            .ok_or_else(|| crate::api::bad_request("name is required"))
    }
}

pub(crate) async fn list_rules_by_name(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Query(target): axum::extract::Query<NameQuery>,
    axum::extract::Query(query): axum::extract::Query<PageQuery<Sort>>,
) -> Result<axum::Json<serde_json::Value>, crate::api::ApiError> {
    let value = match target.validated()? {
        None => serde_json::to_value(
            state
                .service
                .list_all_rules_by_name()
                .await
                .map_err(crate::api::database)?,
        ),
        Some(name) => {
            let pagination = query.pagination();
            let (offset, limit) = pagination.offset_limit()?;
            let (total, items) = state
                .service
                .list_rules_by_name(&name, offset, limit, query.sort, query.order)
                .await
                .map_err(crate::api::database)?;
            serde_json::to_value(Page::new(items, total, pagination))
        }
    }
    .map_err(crate::api::internal)?;
    Ok(axum::Json(value))
}

pub(crate) async fn list_rules_by_api(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Query(target): axum::extract::Query<ApiQuery>,
) -> Result<axum::Json<serde_json::Value>, crate::api::ApiError> {
    let value = match target.validated()? {
        None => serde_json::to_value(
            state
                .service
                .list_all_rules_by_api()
                .await
                .map_err(crate::api::database)?,
        ),
        Some(api) => serde_json::to_value(
            state
                .service
                .list_rules_by_api(&api)
                .await
                .map_err(crate::api::database)?,
        ),
    }
    .map_err(crate::api::internal)?;
    Ok(axum::Json(value))
}

pub(crate) async fn set_by_api(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Query(target): axum::extract::Query<ApiQuery>,
    axum::Json(body): axum::Json<AccessRuleBody>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    set_rule(
        &state,
        &target.required()?,
        body.method,
        body.effect,
        body.grantee,
    )
    .await
}

pub(crate) async fn set_by_name(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Query(target): axum::extract::Query<NameQuery>,
    axum::Json(body): axum::Json<AccessRuleByNameBody>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    set_rule(
        &state,
        &body.api,
        body.method,
        body.effect,
        target.required()?,
    )
    .await
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
    axum::extract::Query(target): axum::extract::Query<NameQuery>,
    axum::Json(body): axum::Json<DeleteRuleByNameBody>,
) -> Result<http::StatusCode, crate::api::ApiError> {
    delete_rule(&state, &body.api, body.method, target.required()?).await
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

#[cfg(test)]
#[path = "../../tests/unit/api/access.rs"]
mod tests;
