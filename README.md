# access_control

`access_control` 是一个与具体传输协议解耦的名称访问控制模块。它根据经过 mTLS 认证的来访者名称、证书 SubjectId、HTTP method 和 API 路径作出 `allow`、`review` 或 `deny` 决策，并提供联系人、权限规则和审批管理 API。

每个 identity profile 必须拥有独立的 `AccessService` 和 SQLite 数据库：

```text
<profile>/db/access.db
```

模块启动时通过 `src/migrations/` 按版本升级数据库结构至 schema v2，并将联系人和规则加载到内存索引。迁移保留已有数据，不转换历史 ACL 路径、不插入默认授权，也不自动替换数据库。默认策略是 deny all、allow profile owner；数据库规则在此基础上覆盖具体 API 和 method。业务默认权限由承载应用首次初始化时设置。

## 主要能力

- 按 API 路径最长匹配规则，支持指定 method 或 `*`。
- 支持精确联系人、所有已命名来访者、匿名来访者和所有来访者等 grantee。
- 联系人申请、批准、权限同步、拉黑和恢复。
- 业务请求触发审核：`If-Reviewed: waiting` 在内存等待，`break` 持久化待办并返回 `400 need_review`；批准后写入普通 ACL，后续持续允许。
- SQLite 持久化与内存 Policies 一致性更新。
- 可直接挂载到 Axum Router 的管理 API。

完整的数据模型、状态机和 HTTP API 定义见 [SPEC.md](SPEC.md)。

`feat/contact-acl-v2` 分支包含尚未发布的统一联系人 API 与 schema v2；已发布 `0.1.1` 的历史协议保存在 [UPSTREAM_SPEC.md](UPSTREAM_SPEC.md)。Pishoo 固定使用本分支的具体 Git 提交；共享开发时可临时使用同级本地 path 依赖同步修改和验证。

## 接入步骤

将本库作为外部依赖加入 pishoo 或其他承载应用：

```toml
[dependencies]
access_control = { package = "daccess", version = "0.1.1", git = "https://github.com/genmeta/daccess.git", branch = "feat/contact-acl-v2" }
```

发布包名为 `daccess`，Rust 库名保留 `access_control`。首次发布和 CI 认证说明见
[RELEASING.md](RELEASING.md)。分支依赖的具体提交由承载应用的 `Cargo.lock` 固定。

### 1. 为 profile 创建 AccessService

调用方先创建数据库父目录，再使用 profile 名称和本地证书 Subject Key Identifier 中的 64 字符 owner hash 初始化服务：

```rust
use std::sync::Arc;

use access_control::{AccessService, SubjectId};

let owner_name = "alice.example";
let owner_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
let owner_subject_id = SubjectId::new(owner_hash.as_bytes())?;
let database_uri = "sqlite:///profiles/alice/db/access.db?mode=rwc";

let acl = Arc::new(
    AccessService::load_from_db(database_uri, owner_name, &owner_subject_id).await?,
);
```

一个进程可以承载多个 profile，但不得在 profile 之间共享 `AccessService`。项目内的实际初始化代码见 [`pishoo/src/service/source.rs`](../pishoo/src/service/source.rs)。

### 2. 从 mTLS 连接构造 Visitor

名称和 SubjectId 必须来自已经验证的对端证书，不得信任普通 HTTP header 中的同名字段：

```rust
use access_control::{SubjectId, Visitor};

let visitor = Visitor::new(
    verified_peer_name,
    SubjectId::new(verified_peer_owner_hash.as_bytes())?,
);
request.extensions_mut().insert(visitor.clone());
```

`SubjectId` 最长 64 字节。pishoo 使用证书 SKI 中的 owner hash；项目内的提取代码见 [`gateway/src/reverse/access_control.rs`](../gateway/src/reverse/access_control.rs)。

### 3. 在业务 Router 外执行权限检查

将当前请求转换为 `Headers`，再调用 `AccessService::auth`：

```rust
use access_control::{Action, AuthResult, Headers, PendingReviewResponse};
use axum::{Json, http::StatusCode};

let headers = Headers {
    method: request.method().clone(),
    path: request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), |value| value.as_str().to_owned()),
    fields: request.headers().clone(),
};

match acl
    .auth(headers, Some(visitor.name()), Some(visitor.subject_id()))
    .await?
{
    AuthResult::Allowed => next.run(request).await,
    AuthResult::Denied => forbidden_response(),
    AuthResult::Reviewing(review) => (
        StatusCode::BAD_REQUEST,
        Json(PendingReviewResponse::from(review)),
    ).into_response(),
    AuthResult::Waiting(review) => {
        match tokio::time::timeout(std::time::Duration::from_secs(300), review).await {
            Ok(Ok(Action::Allow)) => next.run(request).await,
            _ => forbidden_response(),
        }
    }
}
```

匿名请求必须同时传入 `None, None`；名称与 SubjectId 只能同时存在或同时缺失。匿名请求命中 `review` 时拒绝且不创建待办。`If-Reviewed` 缺省为 `break`，非法值或重复头返回 400。allow/deny 仍由同一套 ACL 决定。

`waiting` 返回 `AuthResult::Waiting`，适配器等待此 Future 后继续原业务请求。待办只存内存，取消、超时或进程退出时清理。Pishoo 将等待上限设为 300 秒。`break` 返回 `AuthResult::Reviewing`，适配器应返回 400 与 `PendingReviewResponse`，并设置 `Cache-Control: no-store`。

管理员批准时持久化该 visitor 对 method/path 的普通 ACL `allow`，再放行同一身份和接口的所有等待请求；后续请求持续允许，重启后仍生效，可通过普通 ACL 修改或撤销。拒绝同样写入 `deny`。审批不自动接受联系人关系，也不授权其他接口。

400 响应中的 `status_url` 仅允许原已验证身份查询，返回 `pending`、`allowed`、`denied` 或 `expired`；也可直接重试原业务请求，无须提前查询权限。状态端点经过统一 ACL 并校验记录归属。审批记录的到期时间只限制待审批时间，不限制已保存 ACL 的有效期。

服务端从 method、规范化 path、visitor 与 SubjectId 派生内部 request ID，仅用于异步待办去重；不含 query、普通 headers 或正文。调用方不能覆盖它。完整协议见 [SPEC.md](SPEC.md)。

### 4. 挂载管理 API

管理 Router 应和业务 Router 合并后，再整体套上访问控制中间件。这样 `/std/contact` 和 `/std/acl` 自身也会受到同一个 `AccessService` 的规则约束：

```rust
use access_control::management_router;

let application = management_router(acl.clone())
    .fallback_service(business_router);

let application = application.layer(your_access_control_middleware(acl.clone()));
```

主要端点包括：

- `/std/contact`、`/std/contact/list`：联系人管理，单条资源通过 `?name=...` 指定；
- `POST /std/contact`、`GET /std/contact?name=NAME`：远端本人提交申请和查询关系状态；
- `/std/acl/apis`、`/std/acl/access`、`/std/acl/allow`：权限规则管理；
- `/std/acl/review`、`/std/acl/review/list`：审批管理；`/std/acl/status?id={id}`：发起方状态查询。

具体 method、请求体和响应体见 [SPEC.md](SPEC.md)。管理请求由统一 ACL 授权，处理器不再额外要求所有者身份。

### 5. 联系人状态拉取

本地管理员批准联系人只写入本 profile 的状态并立即返回；daccess 本身不主动向对端
推送审批结果。发送方 pishoo 将申请保存到本地队列并重试投递；
接收方以实际收到时间设定 7 天有效期。申请方以后通过已认证的 DHTTP 请求调用
`GET /std/contact?name=NAME`，其中 NAME 是申请者自己的真实名称，拉取关系状态和当前精确授权。

承载应用先从 mTLS/DHTTP 连接构造 `Visitor`，再执行统一 ACL。没有联系人目录管理权限时，
handler 仅允许查询该 Visitor 自己的 name，并校验已保存的 SubjectId，
返回最小关系状态及当前授权，不暴露其他联系人或管理端详情。

## 直接管理规则

除 HTTP API 外，也可以通过 Rust API 修改规则：

```rust
use access_control::{Effect, Grantee, Method};

acl.set_policy(
    Method::Specified(http::Method::GET),
    "/api/profile",
    Effect::Allow,
    Grantee::One("bob.example".into()),
)
.await?;
```

`set_policy` 和 `remove_policy` 会在一个数据库事务中校验管理 API 至少仍有一位具备 allow 权限的具名或组管理员，并在提交后同步更新内存 Policies。

## 验证

```bash
cargo test
cargo check
```

## pishoo 集成

`daccess` 是独立的 Rust 库，以 `access_control` crate 提供 `AccessService` 和管理
Router。pishoo 作为集成方，显式锁定依赖版本或 Git revision。

pishoo 负责 profile 生命周期，为每个 profile 创建独立的 `AccessService` 和 SQLite
数据库，在 DHTTP/mTLS 验证完成后构造 `Visitor`，并在同一个 Axum 进程中组合管理
Router、业务 Router 和访问控制中间件。

独立的 [Workspace 仓库](https://github.com/genmeta/workspace) 提供审批、联系人和访问规则页面，
构建为由 pishoo 安装和托管的 App，通过同源 `/std/acl/*`、`/std/contact` 和
`/std/contact/list` 调用原生接口；昵称和头像由独立的 Profile Lib 提供。

Workspace 的前端开发、静态资源构建和浏览器 E2E 在其独立仓库进行；
daccess 负责 Rust 库、协议文档、测试和当前数据库结构。

管理对象使用 query：`/std/acl/access?api=/std/message`、`/std/acl/allow?name=NAME`、`DELETE /std/acl/review?id=ID`。联系人不再提供 HTTP PUT；本端 POST 编排由宿主验证真实所有者后调用内部落库方法。
