# Access Control 数据模型与管理协议

## 实现规范，版本 1

### 文档状态

本文档描述 `access_control` crate 当前实现的数据模型、授权算法和 HTTP 管理接口。它采用 IETF RFC 常见的组织方式与规范性语言，但不是 IETF 提案或互联网标准。

本文档以数据库 schema version 1 及当前公开 API 为准。除非明确标记为“扩展点”或“安全考虑”，本文描述的是已经实现的行为，而不是未来规划。

## 摘要

`access_control` 为每个 identity profile 提供一套独立的、以 SQLite 持久化的访问控制能力。系统将访问控制拆分为三个相互关联但语义独立的部分：

1. 联系人用于绑定可读名称与经过认证的主体标识；
2. 访问规则用于决定某个主体能否调用特定 HTTP 方法和 API 路径；
3. 审批记录用于承载不能立即允许或拒绝的请求。

设计的核心约束是：名称由传输层 mTLS 认证，`SubjectId` 用于确认该名称背后的主体是否发生转让；规则是本地入站授权的唯一事实来源；联系人交换的权限声明只描述双方提出或公开的能力，不能替代本地规则；审批始终持久化，并且原业务请求绝不等待管理员决定。

## 系统路径更新（2026-10-09）

管理 HTTP 入口固定使用 `/std/contact`、`/std/contacts` 与 `/std/acl/*`，
不提供旧 `/contact`、`/contacts`、`/acl/*` 的兼容路由。
审批 `status_url`、状态路径识别、联系人拉黑规则及最后一位管理员保护使用相同命名空间。
授权核心仍接受任意业务路径；普通业务规则不自动添加 `/std`。
数据库 schema 和 Rust 接口签名不变，已有规则、联系人声明和审批记录不自动迁移。
承载应用须核对旧系统规则并明确设置新路径，不能批量重写上游业务路径。

## 1. 规范性语言

本文中的“必须（MUST）”、“不得（MUST NOT）”、“应当（SHOULD）”、“不应（SHOULD NOT）”和“可以（MAY）”按照 RFC 2119 与 RFC 8174 的通常含义解释，但仅在以大写英文关键词同时出现时具有规范性。

## 2. 术语

**Identity Profile**
: 一个独立的服务身份及其运行配置。每个 profile 拥有自己的 `db/access.db`，不同 profile 的联系人、规则和审批不得共享。

**Owner**
: 创建 `AccessService` 时由 profile 提供的本方名称和 `SubjectId`。Owner 不作为 `AccessService` 的持久字段，也不要求写入 `contacts` 表；它仅用于构建当前进程的联系人索引和启动时默认规则。

**Contact**
: 本地已知的对端身份记录，由名称、`SubjectId`、分类、状态以及双方权限声明组成。

**SubjectId**
: 从已认证身份材料提取的主体标识，长度为 1 至 64 字节。当前 DHTTP 集成使用 64 字符 owner hash。名称相同但 `SubjectId` 不同的请求被视为身份发生变化。

**Rule**
: 四元组 `(method, api, grantee, effect)`。同一 `(grantee, method, api)` 最多存在一条规则。

**Effect**
: 规则结果之一：`allow`、`review` 或 `deny`。

**Review**
: 存储在 SQLite 中、由服务端内部 request ID 去重的审批记录。它与发起审批的 HTTP/DHTTP 连接没有生命周期关系。

**Request ID**
: 服务端从 method、path、普通 header、已验证 visitor 名称和 `SubjectId` 派生的 SHA-256 值。它不属于 HTTP 协议字段，调用方不得提供或伪造它。

**Requested Access**
: 对方向本方提出的 API 权限请求。它尚未带有 `allow` 或 `review` 结论。

**Granted Access**
: 对方向本方开放的 API 权限。它是对端授权状态的本地副本，不是本方授予该联系人的权限。

## 3. 设计背景与决策

### 3.1 每个 profile 独立存储

一个进程可以承载多个 identity profile，而访问决策必须由接收请求的 profile 自己作出。因此，每个 profile MUST 构造独立的 `AccessService`，并打开该 profile 目录下的 `db/access.db`。

这种设计避免了以下问题：

- 一个身份的管理员修改规则后意外影响另一个身份；
- 联系人同名时无法区分其所属信任域；
- 审批记录跨身份复用；
- 数据库连接、内存策略树和审批记录的生命周期不一致。

### 3.2 名称与主体标识分离

规则以名称表达，便于审计和人工管理。该名称不是应用层任意填写的 HTTP header，而是传输层从 mTLS 对端证书认证得到的 DHTTP 名称。认证层同时从证书 SKI 中取得 `SubjectId`；SKI 是签发证书时依据该名称背后的主体信息形成的 hash。

名称本身很难被未授权方冒充；`SubjectId` 解决的是名称合法转让或主体信息变化后的连续性问题。授权入口要求经过认证的名称和 `SubjectId` 同时出现或同时缺失。名称与本地联系人记录匹配、但 `SubjectId` 不匹配时，即使规则结果为 `allow`，系统也必须将请求降级为 `review`，使名称转让能够被发现并经管理员确认。

### 3.3 规则与联系人权限声明分离

`access_rules` 是本 profile 对入站请求实施授权的唯一持久化事实来源。

联系人中的两个权限字段具有不同方向：

- `requests`：对方希望本方开放的权限；
- `grants`：保留的历史字段；当前拉取协议不写入它；
- `offers`：联系人申请方可展示的待授予声明，或拉黑时保存的本地规则快照。

本方管理员批准对方请求时，应先在 `access_rules` 中建立最终规则，再将联系人状态更新为 Active。申请方随后通过 `GET /std/contact/self` 拉取自身状态和当前精确授权。系统 MUST NOT 将管理员审批结果重复存入联系人 `grants` 字段，也不得依赖对端在线或建立出站连接。

这种分离消除了两个本地事实来源之间的同步竞争，并允许 `deny`、组规则、匿名规则等并不属于联系人声明的规则正常存在。

### 3.4 异步审批

命中 `review` 的请求不会持有 HTTP/DHTTP stream。服务端立即创建或复用一条 SQLite pending 记录，并由承载应用返回 `202 Accepted`、审批 id 和状态查询 URL。调用方随后使用原身份查询状态；状态为 `allowed` 时，重试原业务请求；状态为 `denied` 或 `expired` 时，不得执行该请求。

因此审批不依赖连接取消、Future/Waker、进程内注册表或单 stream reset 信号。pishoo 重启后 pending 和已决定记录仍可查询；只有原业务请求重试时才消费一次 allow/deny 决定。

## 4. 数据表示

### 4.1 时间

数据库中的 `created_at`、`updated_at` 和 `expired_after` 均为 SQLite `INTEGER`，值为 UTC Unix 时间戳，单位为秒。

使用整数的原因是避免文本时间的解析、排序和时区歧义，并使范围查询及索引比较保持数值语义。联系人时间由接收方生成并在响应中使用 Unix 秒；持久审批 API 的 `expired_after` 使用 RFC 3339 日期时间字符串。

### 4.2 HTTP 方法

具体方法以大写 HTTP method token 表示，例如 `GET`、`POST`。`*` 表示任意方法。

包含小写字母的方法 MUST 被拒绝。数据库使用 `method = upper(method)` 约束再次保证这一条件。

### 4.3 API 路径

API 必须是以 `/` 开头的绝对路径。除根路径 `/` 外，持久化路径不得以 `/` 结尾；输入中的尾部 `/` 会被规范化移除。

授权时不考虑查询字符串。例如 `/users/42?view=full` 按 `/users/42` 匹配。

路径匹配以段边界为准，并从最具体路径逐级回退。例如 `/api/users/42` 依次检查：

```text
/api/users/42
/api/users
/api
/
```

规则 `/api/a` 不匹配 `/api/abc`。

### 4.4 Effect

| 值       | 含义               |
| -------- | ------------------ |
| `allow`  | 立即允许请求       |
| `review` | 将请求送入审批流程 |
| `deny`   | 立即拒绝请求       |

`deny` 不是跨越路径、方法和主体优先级的全局覆盖项。系统首先选择最具体的匹配维度，再返回该规则的 effect。管理员若希望在子路径拒绝访问，必须在该子路径建立相应规则。

### 4.5 Grantee

| `grantee_type` | 表示形式       | 含义                         |
| -------------: | -------------- | ---------------------------- |
|              0 | 联系人名称     | 精确命名主体                 |
|              1 | `title@issuer` | 由 issuer 声明的组           |
|              2 | `**`           | 任意已命名主体               |
|              3 | `?`            | 匿名主体                     |
|              4 | `*?`           | 任意主体，包括命名和匿名主体 |

空 grantee 无效。组的 `title` 和 `issuer` 均不得为空。

在同一个 `(method, api)` 下，`*?` 与 `**`、`?` 互斥。写入其中一类时，服务会删除冲突规则；数据库触发器阻止绕过服务直接制造冲突。

当前 `auth` 入口会构造精确名称、`**`、`?` 和 `*?` 候选。策略索引以 grantee 的规范字符串为键，因此当 mTLS 验证名称本身为 `title@issuer` 时，它可以命中同名 Group 规则。当前认证入口尚未从其他证书声明展开“组成员列表”；这种声明式组成员解析属于后续扩展。

### 4.6 SubjectId 的 HTTP 表示

联系人 HTTP 请求中的 `subject_id` 是长度 1 至 64 字节的字符串；服务按该字符串的 UTF-8 字节存入 BLOB。当前接口不执行十六进制解码。DHTTP owner hash 应直接作为 64 字符字符串传递。

本地管理查询 `GET /std/contact/{name}` 与 `GET /std/contacts` 中的 `subject_id` 用于展示。
可读 UTF-8 文本按原文返回，包括 DHTTP 的 64 字符 owner hash；非 UTF-8 字节或包含控制字符的值，
返回 `hex:` 前缀加原始字节的小写十六进制，例如字节 `00 80 ff 41` 返回 `hex:0080ff41`。
管理查询不得使用有损 UTF-8 解码生成替换字符。该展示形式不用于身份认证、主体比较或联系人交换，
数据库和授权判断始终使用原始字节。

## 5. 数据库规范

### 5.1 模块版本表

`module` 表记录 schema 所属模块及版本。数据库 MUST 只包含一行模块记录。当前 schema 的固定值为：

```text
module_name = access
version     = 1
license     = Apache-2.0
```

服务启动时：

1. 若不存在 `module` 表，则在事务中执行 `src/migrations/0.sql`，初始化基线 schema version 0；
2. 若 `module.version` 为 0，则在新事务中执行 `src/migrations/1.sql`，创建 `contact_applications` 表并将版本更新为 1 后提交；
3. 若 `module.version` 为 1，则直接继续初始化，不重复执行 migration；
4. 任何其他版本必须拒绝启动。

### 5.2 `contacts`

| 列            | 类型    | 约束与语义                                                            |
| ------------- | ------- | --------------------------------------------------------------------- |
| `id`          | INTEGER | 自增主键                                                              |
| `name`        | TEXT    | 非空、非空字符串、唯一                                                |
| `subject_id`  | BLOB    | 1 至 64 字节                                                          |
| `alias`       | TEXT    | 可空、唯一；本地管理员可通过联系人 PATCH 修改，空字符串表示清除      |
| `class`       | TEXT    | 非空，默认空字符串；开放分类，如 `human`、`agent`、`service`、`admin` |
| `grants`      | TEXT    | 合法 JSON object；对方授予本方的权限                                  |
| `offers`      | TEXT    | 合法 JSON object；通常保存待兑现权限，Blocked 时保存拉黑前权限快照     |
| `requests`    | TEXT    | 合法 JSON object；对方向本方申请的权限                                |
| `description` | TEXT    | 非 NULL 简介，最多 80 个 Unicode 字符；允许空字符串                    |
| `status`      | INTEGER | `0`、`2..5`                                                           |
| `expired_after` | INTEGER | 接收方按收到时间计算的申请失效时间，Unix 秒时间戳                   |
| `updated_at`  | INTEGER | 接收方维护的更新时间，Unix 秒时间戳                                   |
| `created_at`  | INTEGER | 接收方记录的首次收到时间，Unix 秒时间戳                               |

联系人状态为：

|  值 | 名称                  | 含义                                         |
| --: | --------------------- | -------------------------------------------- |
|   0 | Pending | 等待建立或批准                         |
|   2 | Active  | 已激活；申请方可拉取本地当前授权       |
|   3 | Transfered | 名称所代表的主体已经发生转让         |
|   4 | Expired   | Pending 申请超过有效期且未获批准     |
|   5 | Blocked   | 已被本方拉黑，拒绝重新申请和权限更新 |

首次 HTTP 创建时，含权限请求的申请写入 Pending；没有请求任何权限的申请直接写入 Active，无须单独批准“联系人关系”。接收方以收到请求的时间写入 `created_at` 和 `updated_at`，并将 `expired_after` 设为收到时间后 7 天。相同 `application_id`、认证身份和载荷的重试返回原记录，不重置有效期；编号被其他身份或不同载荷复用时返回冲突。新的申请编号可在前一申请过期后重新申请；Blocked 身份不可申请。

`contact_applications` 按 `application_id` 保存认证申请人名称与 SubjectId、载荷摘要、收到时间、失效时间和 pending/active/expired/denied/revoked 状态。它与联系人写入在同一事务中完成，并在联系人删除后保留供幂等重试和状态查询。删除待处理联系人将对应申请标记 denied；删除已激活联系人标记 revoked。

实现可以在读取或修改联系人时惰性地把 `status = Pending AND expired_after <= now` 的记录更新为 Expired。过期转换只改变状态，不改变 `updated_at`。过期记录必须保留以供审计，不得由过期处理自动删除，也不得接受本地批准。

删除联系人后，数据库触发器必须删除所有以该联系人名称为精确 grantee 的规则。服务随后同步清理内存联系人索引和策略树。

### 5.3 `access_rules`

| 列             | 类型    | 约束与语义                                      |
| -------------- | ------- | ----------------------------------------------- |
| `id`           | INTEGER | 自增主键                                        |
| `method`       | TEXT    | 非空、大写或 `*`                                |
| `api`          | TEXT    | 规范化绝对路径                                  |
| `effect`       | TEXT    | `allow`、`review`、`deny`                       |
| `grantee_type` | INTEGER | `0..4`；服务加载时校验其与 grantee 文本类别一致 |
| `grantee`      | TEXT    | 非空主体选择器                                  |
| `updated_at`   | INTEGER | Unix 秒时间戳                                   |
| `created_at`   | INTEGER | Unix 秒时间戳                                   |

唯一键为 `(grantee, method, api)`。因此同一主体、方法和路径只能具有一个 effect；设置规则采用 upsert，更新 effect 和 `updated_at`，保留 `created_at`。

索引用途如下：

- `(api, method)`：按 API 查询和加载规则；
- `(grantee)`：按联系人展示权限以及删除联系人时收集规则。

管理 API 写入精确 grantee 时，该名称必须是 owner 或已存在的联系人。由于 owner 按设计不存入 `contacts`，这个约束依赖管理路由所持有的 profile owner 上下文，不能由 SQLite 静态触发器完整表达。特殊选择器和包含 `@` 的组 grantee 不需要联系人记录。

### 5.4 `access_reviews`

| 列              | 类型    | 约束与语义                       |
| --------------- | ------- | -------------------------------- |
| `id`            | INTEGER | 自增主键                         |
| `request_id`      | TEXT    | 服务端生成的内部请求标识，不对调用方暴露 |
| `visitor`       | TEXT    | 非空访问者名称                   |
| `visitor_sid`   | BLOB    | 1 至 64 字节                     |
| `method`        | TEXT    | 大写 HTTP 方法                   |
| `api`           | TEXT    | 绝对路径                         |
| `stage`         | INTEGER | `0` pending、`1` allow、`2` deny |
| `reason`        | TEXT    | 非空审批原因                     |
| `expired_after` | INTEGER | 决定或待审批记录的失效时间       |
| `updated_at`    | INTEGER | Unix 秒时间戳                    |
| `created_at`    | INTEGER | Unix 秒时间戳                    |

唯一键为 `(visitor, request_id)`。同一键还必须持续绑定同一 `method` 和 `api`；在记录未过期时也必须绑定同一 `visitor_sid`。调用方不能传入该值，因而不能让某个审批决定绑定到另一身份或请求。

`expired_after` 必须晚于 `created_at`。新建 pending 记录的默认有效期为创建后一天。索引 `(stage, expired_after)` 支持待审批和有效期查询。

## 6. 启动与内存状态

数据库是联系人和显式规则的持久化来源；运行时使用 radix trie 加速联系人查询与策略匹配。

加载顺序如下：

1. 连接 profile 的 SQLite 数据库并完成 migration；
2. 将调用方提供的 owner 名称和 `SubjectId` 放入联系人 trie；
3. 加载 `contacts` 表的名称和 `SubjectId`；
4. 在根路径加入默认 `deny *?`；
5. 在根路径加入默认 `allow owner`；
6. 加载每条显式规则；
7. 对每个出现在数据库中的 `(method, api)`，在内存中同时补入 `deny *?` 和 `allow owner` 默认项。

这些默认项只存在于内存，不写入 `access_rules`。它们提供“未匹配时拒绝、owner 基线允许”的初始策略；随后加载的同键显式规则可以覆盖对应默认项，因此管理员仍可为 owner 写入 `review` 或 `deny`。显式规则列表 API 不展示隐式项。

## 7. 授权算法

### 7.1 输入验证

授权调用接收请求头信息、可选名称和可选 `SubjectId`。

- 名称与 `SubjectId` MUST 同时存在或同时缺失；
- 路径 MUST 以 `/` 开头；
- 查询字符串在匹配前 MUST 被移除；
- 匿名请求命中 `review` 时 MUST 被拒绝，因为审批状态无法安全绑定和查询该 visitor。

### 7.2 候选 grantee

已命名请求按以下顺序构造候选：

```text
<exact-name>, **, *?
```

匿名请求按以下顺序构造候选：

```text
?, *?
```

### 7.3 匹配优先级

策略树严格按以下顺序查找，首次命中即返回：

1. API 路径：最具体路径优先，随后逐段回退至 `/`；
2. 方法：具体 HTTP 方法优先，`*` 次之；
3. grantee：按第 7.2 节候选顺序，精确名称优先于类别选择器。

如果全部未命中，结果为 `deny`。

例如，命名用户 `alice.example` 请求 `GET /files/private/report` 时，系统会先检查 `/files/private/report` 的 `GET` 精确主体，再检查该路径的 `GET **` 和 `GET *?`，随后检查同路径的 `*`，然后才回退到 `/files/private`。

### 7.4 SubjectId 复核

若命中 `allow`，系统必须查询联系人 trie：

- 已知名称且 `SubjectId` 不同：结果转为 review，原因为 `subject_id changed`；
- 已知名称且 `SubjectId` 相同：允许；
- 名称不在联系人 trie：保持规则结果。精确名称规则通常受数据库联系人约束保护，类别规则可匹配未建联系人记录的命名主体。

`deny` 直接拒绝，不进入 SubjectId 复核。`review` 使用命中规则生成可审计原因。

### 7.5 结果

授权结果只有三类：

- `Allowed`：调用方可以继续处理请求；
- `Denied`：调用方必须拒绝请求；
- `Reviewing(PendingReview)`：调用方必须立即返回 `202 Accepted`，不得等待管理员决定。

## 8. 审批协议

### 8.1 创建或复用 pending

只有具有经 mTLS 验证名称和 `SubjectId` 的请求才能进入审批。服务端从请求的 method、path、普通 header、visitor 名称和 `SubjectId` 派生内部 request ID；调用方不携带、选择或控制该值。

处理顺序如下：

1. 查询与 visitor、request ID、`SubjectId`、method 和 API 完全匹配且未过期的已决定记录；若存在，通过 `DELETE ... RETURNING` 原子消费，并立即返回 allow 或 deny；
2. 否则查询 `(visitor, request_id)`；有效记录绑定另一 `SubjectId` 时拒绝，method 或 API 不同也拒绝；
3. 有效 pending 存在时，返回同一个数据库 id；
4. 不存在记录时，创建有效期一天的 pending；
5. 已过期记录重置为 pending，并更新 `SubjectId`、原因和有效期。

承载应用在步骤 3 至 5 返回 `202 Accepted`：

```json
{
  "review_id": 12,
  "status_url": "/std/acl/review/12/status"
}
```

该 `202` 不代表原业务请求已执行。调用方以创建审批的同一 mTLS 身份请求 `status_url`，得到 `pending`、`allowed`、`denied` 或 `expired`。`allowed` 时必须使用相同的请求字段重试原业务请求；重试会原子消费该决定。已决定记录不是长期规则，长期授权必须写入 `access_rules`。

### 8.2 管理队列

管理 API 只展示未过期的持久 pending 记录，按数据库 id 递增分页。管理员 allow 或 deny 时必须提供决定有效期；更新只匹配仍为 pending 且未过期的 id，避免覆盖并发决定或过期记录。

## 9. 联系人交换协议

### 9.1 Requested Access

请求权限按 API 聚合，不携带 effect：

```json
{
  "/api/1": ["GET", "POST"],
  "/api/2": ["*"]
}
```

这表示对方提出需求，最终是 allow、review 还是 deny 由本方管理员写入 `access_rules` 决定。

### 9.2 Offers 与 Granted Access

`offers` 表示申请方承诺在联系人建立后向对方开放的权限；`granted_access` 表示对方已经向本方开放的权限。两者使用相同的按 API 和 effect 聚合结构：

```json
{
  "/api/1": {
    "allow": ["GET"],
    "review": ["POST"],
    "deny": ["DELETE"]
  }
}
```

同一 API 下，一个方法不得同时出现在多个 effect 数组中。所有 API 路径均按第 4.3 节规范化。

### 9.3 创建联系人

首次创建联系人时，含权限请求的状态为 Pending；没有请求任何权限时直接成为 Active。`description` 是申请方随请求发送的简介，不得超过 80 个 Unicode 字符。接收方以实际收到时间为起点计算 7 天有效期。申请方不提交时间或有效期。

虽然两个权限映射在 JSON 语法上可以省略，但申请方 SHOULD 同时发送自身请求的权限和承诺向对方开放的权限。申请方发送的 `offers` 可以为空对象。

联系人申请不产生任何回调或业务访问规则。申请方提供的 `offers` 仅是声明，不会在发送 POST 时写入 `access_rules`。申请方获批后，应由其自身在合适时机重新查询对方；对方也不负责确认申请方是否在线。

同名记录仍处于 Pending 时，新编号的 POST 返回 409；相同编号和载荷的重试返回原状态。Expired 允许新编号重新申请，Blocked 返回 409。处于 Active 或 Transfered 时，新的申请可更新资料并保持联系人状态。删除联系人会删除整条联系人及其精确规则，但保留申请审计记录。联系人只能从 Active 或 Transfered 变为 Blocked；Pending 和 Expired 都不得被拉黑。拉黑事务 MUST 将该联系人当前的全部精确权限规则保存到 `offers`，删除这些生效规则，再为该联系人明确写入 `POST /std/contact` 的 deny 规则。

### 9.4 本地批准

具有 `PATCH /std/contact/{name}` allow 权限的本地管理员批准时，系统必须验证联系人为未过期的 Pending 或 Transfered，随后在本地事务中直接将状态更新为 Active。该操作不访问网络、不等待对端、也不更新 `grants` 或 `offers`。对方上线后自行发起第 9.5 节的状态查询。

### 9.5 申请方状态查询

申请方使用已认证的 DHTTP/mTLS 身份发起 `GET /std/contact/self?application_id={id}`。端点按编号查找持久申请记录，并验证申请人名称和 SubjectId 与 Visitor 完全一致；不接受调用者提交的身份字段。无编号的查询仍返回当前联系人状态。

响应只包含联系人 `status` 和 `granted_access`。状态不是 Active 时 `granted_access` 必须为空；Active 时它从本方当前 `access_rules` 中收集该精确名称的 allow、review 和 deny 规则。因此返回值始终反映本方本地授权，不承诺申请方在离线期间已经处理该结果。

### 9.6 拉黑与恢复

本地管理员只可将 Active 或 Transfered 联系人改为 Blocked。该操作 MUST 在同一事务中完成以下步骤：将联系人现有的全部精确规则按 `GrantedAccess` 结构写入 `offers`；删除这些规则；写入该联系人对 `POST /std/contact` 的 deny 规则；将状态改为 Blocked。若删除原规则会使任一 `/std/acl` 管理 API 不再具有至少一位 allow 管理员，整个事务必须失败。

取消拉黑只允许 `Blocked -> Active`。实现 MUST 删除拉黑 deny 规则，从 `offers` 恢复原 allow、review 和 deny 规则，清空 `offers`，再将状态改为 Active。数据库提交后必须以同样顺序更新内存策略树。

## 10. HTTP API

### 10.1 通用约定

所有请求和响应体使用 JSON。成功的创建返回 201；成功的修改和删除返回 204；查询返回 200。

分页响应格式为：

```json
{
  "items": [],
  "total": 0,
  "page": 1,
  "page_size": 20
}
```

`page` 默认为 1，必须大于 0。`page_size` 默认为 20，取值范围为 1 至 100。`order` 接受 `asc` 或 `desc`。

数据库唯一约束冲突映射为 409，记录不存在映射为 404，输入或类型错误映射为 400，未分类数据库错误映射为 500。错误响应体当前为纯文本。

### 10.2 联系人 API

#### `POST /std/contact`

请求体：

```json
{
  "application_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "class": "human",
  "description": "Alice",
  "requested_access": {
    "/api/messages": ["GET", "POST"]
  },
  "offers": {
    "/api/profile": {
      "allow": ["GET"],
      "review": [],
      "deny": []
    }
  }
}
```

`application_id` 是发送方生成并在重试中保持不变的 64 位小写十六进制编号。`class`、`requested_access` 和 `offers` 可省略并默认为空；`offers` 为空是合法的。POST 不会建立回调权限或应用任何 `offers`。`description` 必填，可为空字符串，最多 80 个 Unicode 字符。请求体不接受名称、SubjectId 或时间字段；身份只来自已验证的 mTLS Visitor。首次创建返回 201，幂等重试返回 200，均返回申请编号、接收方名称与 SubjectId、状态、收到时间和到期时间。

#### `GET /std/contacts`

支持 `page`、`page_size`、`sort` 和 `order`。`sort` 可选：

- `name` 或兼容别名 `names`；
- `alias`；
- `updated_at`，默认；
- `created_at`；
- `class`。

默认按 `updated_at desc`。除按名称排序外，同值记录以 `name asc` 稳定排序。

#### `GET /std/contact/{name}`

返回单个联系人：

```json
{
  "name": "alice.example",
  "subject_id": "0123...",
  "alias": "Alice",
  "class": "human",
  "description": "Alice",
  "status": "active",
  "created_at": 1785800000,
  "updated_at": 1785800060,
  "expired_after": 1786059200,
  "requested_access": {},
  "granted_access": {},
  "offers": {}
}
```

`status` 使用 `pending`、`active`、`transfered`、`expired` 或
`blocked`。数据库继续使用第 5.2 节定义的整数表示；整数值不属于 HTTP
接口契约。

#### `PATCH /std/contact/{name}`

该接口是本地管理操作。mTLS 来访者必须已经获得该 API 的 allow 权限；来访者可以是当前 profile owner，也可以是其他管理员。请求体支持局部修改 `status` 和 `alias`，但至少必须提供其中一个字段：

```json
{
  "status": "blocked",
  "alias": "Alice"
}
```

`status` 只接受 `active` 或 `blocked`：`active` 表示批准 Pending/Transfered 联系人，或取消拉黑；`blocked` 表示拉黑。空 `alias` 表示清除本地别名。状态转换必须符合第 9.4 和 9.6 节。授权由统一访问控制层在进入联系人处理器前完成；处理器仍要求存在经过 mTLS 认证的 Visitor，但不得再额外限定其名称必须等于 `owner_name`。空对象或未知字段必须被拒绝。

#### `GET /std/contact/self`

申请方状态查询端点。调用者不传名称；服务从已验证的 mTLS Visitor 取得 name 和
SubjectId。携带 `application_id` 时按申请编号返回该申请的 pending/active/expired/denied/revoked 状态、接收方身份和时间；无编号时返回当前联系人状态。Active 时包含当前精确授权：

```json
{
  "name": "alice.example",
  "subject_id": "alice-subject",
  "status": "active",
  "granted_access": {
    "/api/profile": {
      "allow": ["GET"],
      "review": [],
      "deny": []
    }
  }
}
```

`name` 和 `subject_id` 是服务从已验证 Visitor 返回的身份绑定字段，供出站联系人状态
同步校验远端名称和主体是否发生变更；调用方不能提交或覆盖它们。

按 `application_id` 查询时，响应中的 `name` 和 `subject_id` 改为接收方身份，供发送方校验目标；申请人身份仍只从 Visitor 验证，不能由查询参数指定。

未认证调用返回 400，联系人不存在返回 404，SubjectId 与已保存联系人不匹配返回
403。该端点在常规业务 ACL 之外由身份绑定保护，不能用作按名称查询联系人。

#### `DELETE /std/contact/{name}`

删除单个联系人及其精确主体规则。如果该联系人是某个 `/std/acl` 管理 API 规则作用域内最后一位具有 allow 权限的管理员，并且 owner 在该作用域没有 allow 权限，则返回 400。普通业务 API 上的规则不触发这项保护。

#### `DELETE /std/contacts`

请求体 `{"names":["alice.example","bob.example"]}`。操作在单一数据库事务中执行；任一联系人不存在，或整个批次会使任一 `/std/acl` 管理 API 规则作用域不再具有 allow 管理员时，整个批次失败。

### 10.3 访问规则管理 API

`/std/acl/apis` 分页列出 API；`/std/acl/access` 按 API 组织规则；`/std/acl/allow` 按 grantee 名称组织规则。

#### `POST /std/acl/access/{api}`

对路径指定的 API 创建或覆盖一条规则。例如 `/users` 使用 `POST /std/acl/access/users`：

```json
{
  "method": "GET",
  "effect": "allow",
  "grantee": "alice.example"
}
```

请求体不得再携带 `api`，路径是目标 API 的唯一来源。成功返回 204。除 owner 外，精确 grantee 不存在于联系人表时写入失败。修改 `/std/acl` 管理 API 的规则时，操作后的同一 method/API 作用域必须仍有至少一个 `Grantee::One` 或 `Grantee::Group` 具有 allow 权限；普通业务 API 不受这项约束。设置 `*?` 会删除同一 method/API 的 `**` 和 `?`；反向设置同理删除 `*?`。

#### `PATCH /std/acl/allow/{name}`

```json
{
  "method": "GET",
  "api": "/users",
  "effect": "review"
}
```

路径中的 `{name}` 是规则 grantee。该操作修改或覆盖此 grantee 在请求体指定 API/method 上的 effect，成功返回 204。

#### `DELETE /std/acl/allow/{name}`

```json
{
  "method": "GET",
  "api": "/users"
}
```

effect 不属于规则标识，因此删除请求不携带 effect。不存在的规则按幂等删除处理并返回 204。删除 `/std/acl` 管理 API 上最后一条 `One` 或 `Group` allow 管理员规则，并且 owner 已不具备 allow 权限时，返回 400。

#### `GET /std/acl/apis`

分页列出不同 API，而不是一次返回所有规则。查询参数支持 `page`、`page_size`、`sort=api|updated_at` 和 `order`，默认 `updated_at desc`。

```json
{
  "items": [{ "api": "/users", "updated_at": 1785772800 }],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

#### `GET /std/acl/access`

不分页，以 API、方法、effect 三级结构返回全部显式规则：

```json
{
  "/api/2": {
    "GET": {
      "allow": ["alice.example"],
      "review": ["bob.example"],
      "deny": ["?"]
    }
  }
}
```

#### `GET /std/acl/access/{api}`

一个 API 通常只有少量方法和 effect，因此该接口不分页：

路径参数承载完整的规范化 API 路径，但省略开头的 `/`。例如 `/users/profile` 对应 `GET /std/acl/access/users/profile`。

```json
{
  "GET": {
    "allow": ["alice.example"],
    "review": ["bob.example"],
    "deny": ["?"]
  },
  "POST": {
    "allow": ["**"],
    "review": [],
    "deny": []
  }
}
```

#### `GET /std/acl/allow/{name}`

按 grantee 查询其规则，并按 API 分页。支持 `page`、`page_size`、`sort=api|updated_at` 和 `order`。

```json
{
  "items": {
    "/api/1": {
      "GET": {
        "allow": ["alice.example"],
        "review": [],
        "deny": []
      }
    }
  },
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

这里分页单位是 API，不是单条规则；`total` 是该 grantee 关联的不同 API 数量。

#### `GET /std/acl/allow`

不分页，以 grantee、API、effect 的结构返回全部显式规则，effect 数组中存放方法：

```json
{
  "alice.example": {
    "/api/v2": {
      "allow": ["GET", "POST"],
      "review": ["PATCH"],
      "deny": ["DELETE"]
    }
  }
}
```

### 10.4 审批管理 API

#### `GET /std/acl/reviews`

分页列出未过期 pending 审批，按递增数据库 id 排序：

```json
{
  "items": [
    {
      "id": 12,
      "visitor": "alice.example",
      "method": "GET",
      "api": "/private",
      "reason": "matched review rule: GET /private alice.example",
      "expired_after": "2026-08-05T12:00:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

#### `GET /std/acl/review/{id}/status`

供发起审批的业务调用方轮询。该端点不执行常规业务 ACL 匹配，以免状态查询再次进入审批；它必须从已验证 `Visitor` extension 读取身份，并只返回该名称和 `SubjectId` 创建的记录。身份不匹配或 id 不存在返回 404，缺少已验证身份返回 403。

```json
{ "status": "pending" }
```

`status` 为 `pending`、`allowed`、`denied` 或 `expired`。它不会消费 allow/deny 决定。

#### `PATCH /std/acl/review`

```json
{
  "id": 12,
  "action": "deny",
  "expired_after": "2026-08-05T12:00:00Z"
}
```

`action` 只接受 `allow` 或 `deny`，`expired_after` 必填且必须晚于当前时间。成功返回 204；已经决定、已过期或不存在的 id 返回 404。

## 11. 一致性与并发

### 11.1 规则更新

设置或删除规则时，服务持有策略写锁；管理 API 的管理员存续校验与数据库修改在同一事务内完成，事务提交后再更新内存 trie。该写锁覆盖“校验、数据库修改、内存更新”的完整过程，避免并发请求同时通过校验并删除最后一位管理员。数据库失败不会污染内存。

### 11.2 联系人创建与删除

联系人创建先提交数据库，再更新联系人 trie。删除联系人同样持有策略写锁；管理员存续校验、受影响规则收集和联系人删除在同一事务内完成，数据库触发器清理规则；提交后再更新联系人 trie 和策略树。

如果进程在数据库提交与内存更新之间终止，重启加载会从数据库恢复一致状态。当前实现没有针对提交后内存更新失败的在线自动重载机制。

### 11.3 审批状态

pending 到 allow/deny 的转换使用带 `stage = 0` 和有效期条件的单条 `UPDATE`，因此两个管理员并发决定时只有一个成功。已决定记录在匹配的业务请求重试时使用单条 `DELETE ... RETURNING` 消费，避免同一个决定被多个请求重复使用。审批没有内存等待者，也不会因连接关闭而取消。

## 12. 错误处理要求

实现应在进入持久层之前拒绝以下输入：

- 相对 API 路径；
- 小写或无效 HTTP 方法；
- 未知 effect；
- 空 grantee 或格式不完整的组；
- 超过 64 字节或为空的 `SubjectId`；
- Requested Access 中同一 API 的重复方法；
- Granted Access 中同一 API、跨 effect 重复的方法；
- 页码为 0、页大小超出 1 至 100、未知排序方向。

数据库约束与触发器是第二道防线，不应代替 API 层的可读错误。

## 13. 安全考虑

### 13.1 管理 API 的管理员存续保护

本文所称“管理 API”特指规范化路径等于 `/std/acl` 或以 `/std/acl/` 开头的 API，包括规则和审批端点。`/std/contact`、`/std/contacts` 与 `/std/contact/*` 是联系人协议或联系人查询端点，不纳入“始终保留至少一位管理员”的规则作用域；但删除联系人可能连带删除该联系人名下的 `/std/acl` allow 规则，因此删除操作仍必须执行管理员存续检查。

承载应用 MUST 使用本访问控制保护这些端点，不得因为它们属于 ACL 模块就默认公开。

`AccessService` 保存当前 profile 的 owner 名称，用于建立内存策略基线、验证联系人名称和保护管理 API 的管理员存续。该字段不赋予 owner 不可撤销的权限：启动策略会在各规则作用域先加入 owner allow 基线，随后加载的同键显式规则仍可将其改为 review 或 deny，从而允许 owner 本人也受策略管理的托管模式。

每个 `/std/acl` 管理 API 的 `(method, api)` 规则作用域在修改后 MUST 至少保留一个 effect 为 allow 的 `Grantee::One` 或 `Grantee::Group`。满足该条件的主体就是管理员：默认情况下是 owner；也可以是其他精确命名主体或组。

如果 owner 被配置为 review 或 deny，则同一管理作用域必须先有另一位 allow 管理员。任何管理员被改为 review 或 deny、其 allow 规则被删除，或者其联系人记录被删除时，系统都必须验证操作完成后仍有至少一位 allow 管理员；否则拒绝整个操作。`Named`、`Anony` 和 `All` 即使配置为 allow，也不计作管理员。该约束仅作用于 `/std/acl` 管理 API，不限制普通业务 API 的规则配置。

Owner 不写入联系人表。管理路由使用 `AccessService` 持有的 profile owner 名称，并把它作为保留名称：`POST /std/contact` 创建同名联系人时必须返回 400，防止联系人记录覆盖内存 trie 中 owner 的 `SubjectId`。

### 13.2 名称认证与主体连续性

来访者名称由 DHTTP 传输层通过 mTLS 证书验证，不来自普通 HTTP header，也不允许应用调用方自行声明。名称认证证明对端当前合法持有该名称的证书；证书 SKI 中的 `SubjectId` 则绑定签发证书时该名称背后的主体信息。

因此，本模块使用名称决定“是谁”，使用 `SubjectId` 判断“是否仍是先前认识的同一主体”。名称合法转让后，新持有者可以通过 mTLS 名称认证，但其 `SubjectId` 会变化；已有联系人上的 allow 随即降级为 review。承载应用 MUST 从已验证的远端证书构造 `Visitor`，不得从可伪造的应用层字段构造它。

### 13.3 内部 Request ID 派生

Request ID 是服务端生成的 64 字符小写十六进制 SHA-256 摘要。它不通过 HTTP 传输，调用方不得提供、选择或覆盖它。

输入由以下部分组成：

1. `:method` 和 `:path`；
2. 全部普通 HTTP header 名称和原始值；
3. mTLS 验证的来访者名称；
4. 来访者证书 SKI 中的 `SubjectId`。

伪头部和普通 header 先按名称、再按值的字节序排序。每个名称和值使用 64 位大端长度前缀后输入摘要；排序后的 header 集合之后，再以相同长度前缀编码来访者名称和 `SubjectId`。该编码避免字段拼接歧义，并使 header 到达顺序不影响结果。请求 body 当前不参与 request ID。

因为 visitor 名称和 `SubjectId` 均参与计算，审批决定无法被另一身份消费。调用方在状态变为 `allowed` 后必须重试相同请求字段，才能命中并消费该一次性决定。

### 13.4 审批重放

持久 allow/deny 决定是一次性消费，并同时绑定 visitor、SubjectId、method 和 API，从而限制跨主体、跨端点重放。管理员设置的有效期仍应尽可能短。长期访问应使用可审计、可撤销的规则，而不是延长审批有效期。

### 13.5 联系人状态查询隔离

`GET /std/contact/self` 必须仅以传输层已验证的 Visitor 识别调用者，不得接受请求体、
header 或路径中声明的联系人名称。实现必须复核保存的 SubjectId，避免名称转让后
的新主体读取旧主体的联系人状态或规则。该工作流不建立出站 DHTTP 连接，不需要
服务端跟踪对端在线状态、重试通知或访问对端私钥。

## 14. 兼容性与扩展

### 14.1 Schema 演进

当前数据库 schema version 为 1。`src/migrations/0.sql` 定义基线 schema version 0，
包含服务端内部使用的 `access_reviews.request_id` 和当前联系人状态集合；
`src/migrations/1.sql` 新增保存申请回执的 `contact_applications` 表。

服务支持将 version 0 数据库自动升级到 version 1，并直接打开 version 1 数据库。
其他版本（包括 version 2）必须拒绝启动。后续 schema 变更以递增 migration 形式演进；
实现不得静默打开自身不支持的数据库版本。

### 14.2 保留的扩展点

以下能力在数据模型中存在，但尚未形成完整端到端协议：

- 从认证声明提取 `title@issuer` 组并加入授权候选；
- 主动处理名称主体转让并决定 Transfered 状态；
- 对过期 pending 审批执行后台清理。

实现和客户端不得把这些扩展点当作当前版本已经保证的行为。

## 15. 符合性要求

声称符合本规范版本 1 的实现至少必须验证：

1. schema 约束拒绝非法状态、时间类型、SubjectId 长度和规则选择器冲突；
2. 路径按段回退，具体方法优先于 `*`，精确主体优先于类别主体；
3. 未命中规则时拒绝，owner 默认规则在加载后生效；
4. 数据库规则与内存策略在创建、更新和删除后保持一致；
5. 联系人创建不产生访问规则，删除联系人清理精确规则；
6. 本地批准直接写为 Active，不建立对端通知、重试任务或连接等待；
7. `/std/contact/self` 只允许同名且 SubjectId 完全匹配的已验证 visitor 读取自身状态和 Active 时的本地精确授权；
8. 冻结状态拒绝重复申请且保持申请时间戳，只有 Active/Transfered 接受资料更新；删除记录后允许重新申请；
9. review pending 列表正确分页，且只包含未过期记录；
10. review 立即返回 `202`，不保留连接、Future/Waker 或内存等待者；
11. review 状态查询只允许创建该 review 的已验证 visitor，且 allow/deny 决定只能被完全匹配的请求消费一次；
12. `/std/acl` 管理 API 的规则变更和联系人删除不会移除最后一位 allow 管理员，普通业务 API 不受这项限制。

## 16. IANA 考虑

本文档不请求 IANA 分配任何名称、端口、媒体类型或协议参数。

## 17. 参考资料

- RFC 2119, _Key words for use in RFCs to Indicate Requirement Levels_.
- RFC 8174, _Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words_.
- SQLite Documentation, _CREATE TABLE_, _CREATE TRIGGER_, and _UPSERT_.
- `src/migrations/0.sql`，基线数据库 schema version 0 的权威定义。
- `src/migrations/1.sql`，schema version 1 的申请回执表迁移。
- `access/src/policy.rs`，规则表示与匹配算法的权威实现。
- `access/src/service.rs`，加载、授权与持久审批流程的权威实现。
- `access/src/api.rs` 及 `access/src/api/`，HTTP 管理协议的权威实现。
