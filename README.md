# access_control

`access_control` 是一个与具体传输协议解耦的名称访问控制模块。它根据经过 mTLS 认证的来访者名称、证书 SubjectId、HTTP method 和 API 路径作出 `allow`、`review` 或 `deny` 决策，并提供联系人、权限规则和审批管理 API。

每个 identity profile 必须拥有独立的 `AccessService` 和 SQLite 数据库：

```text
<profile>/db/access.db
```

模块启动时自动执行 schema migration，并将联系人和规则加载到内存索引。默认策略是 deny all、allow profile owner；数据库规则在此基础上覆盖具体 API 和 method。

## 主要能力

- 按 API 路径最长匹配规则，支持指定 method 或 `*`。
- 支持精确联系人、所有已命名来访者、匿名来访者和所有来访者等 grantee。
- 联系人申请、批准、权限同步、拉黑和恢复。
- 实时审批，以及绑定 RequestId 的持久审批。
- SQLite 持久化与内存 Policies 一致性更新。
- 可直接挂载到 Axum Router 的管理 API。

完整的数据模型、状态机和 HTTP API 定义见 [SPEC.md](SPEC.md)。

## 接入步骤

将本库作为外部依赖加入 pishoo 或其他承载应用：

```toml
[dependencies]
access_control = "0.1"
```

在尚未发布到 registry 的联合开发阶段，承载应用应固定一个明确的 Git revision；
临时 `path` 依赖只用于本地联调，不代表本库属于承载应用的 Cargo workspace。

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
use access_control::{AuthResult, Headers};

let headers = Headers {
    method: request.method().clone(),
    path: request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), |value| value.as_str().to_owned()),
    fields: request.headers().clone(),
    request_id,
};

match acl
    .auth(headers, Some(visitor.name()), Some(visitor.subject_id()))
    .await?
{
    AuthResult::Allowed => next.run(request).await,
    AuthResult::Denied => forbidden_response(),
    AuthResult::Reviewing(id, state, reviews) => {
        let decision = state.await;
        reviews.del(id);
        match decision {
            Ok(access_control::Action::Allow) => next.run(request).await,
            Ok(access_control::Action::Deny) | Err(_) => forbidden_response(),
        }
    }
}
```

匿名请求必须同时传入 `None, None`；名称与 SubjectId 只能同时存在或同时缺失。若请求携带 RequestId，适配层应把它放入 `Headers::request_id`；服务会重新计算并验证，不能由服务器替请求自动生成。

当传输层能够感知 request reset 时，应同时等待审批和取消信号：

```rust
tokio::select! {
    decision = state.clone() => {
        reviews.del(id);
        // 根据 decision 继续或拒绝请求
    }
    _ = request_cancelled() => {
        state.cancel();
        reviews.del(id);
    }
}
```

删除 Registry 项不会使已经持有的 `ArcReviewState` 失效，因此取消时应先调用 `cancel()` 唤醒等待者，再删除 Registry 项。

### 4. 挂载管理 API

管理 Router 应和业务 Router 合并后，再整体套上访问控制中间件。这样 `/contact` 和 `/acl` 自身也会受到同一个 `AccessService` 的规则约束：

```rust
use access_control::management_router_with_notifier;

let application = management_router_with_notifier(acl.clone(), notifier)
    .fallback_service(business_router);

let application = application.layer(your_access_control_middleware(acl.clone()));
```

主要端点包括：

- `/contact`、`/contact/{name}`、`/contacts`：联系人申请和管理；
- `/acl/apis`、`/acl/access`、`/acl/allow`：权限规则管理；
- `/acl/review`、`/acl/reviews/live`、`/acl/reviews/persistent`：审批管理。

具体 method、请求体和响应体见 [SPEC.md 的 HTTP API 章节](SPEC.md#10-http-api)。

### 5. 实现联系人通知器

本地管理员批准联系人时，需要向对端发送 `PATCH https://{contact}/contact`。承载应用通过 `ContactNotifier` 提供传输实现：

```rust
use access_control::{ContactNotifier, NotifyError};
use std::{future::Future, pin::Pin};

impl ContactNotifier for MyNotifier {
    fn granted_update<'a>(
        &'a self,
        contact: &'a str,
        modified_since: i64,
        body: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<(), NotifyError>> + Send + 'a>> {
        Box::pin(async move {
            // 通过已认证的 DHTTP/mTLS 连接发送 PATCH /contact。
            // If-Modified-Since 使用 modified_since，JSON 请求体直接使用 body。
            send_granted_update(contact, modified_since, body).await
        })
    }
}
```

不需要联系人同步时可以使用 `management_router(acl)`；此时需要远端通知的批准操作会返回 503。pishoo 的 DHTTP 实现见 [`pishoo/src/service/snapshot.rs`](../pishoo/src/service/snapshot.rs)。

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
