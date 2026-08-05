# Access Control 数据模型与管理协议

## 实现规范，版本 0

### 文档状态

本文档描述 `access_control` crate 当前实现的数据模型、授权算法和 HTTP 管理接口。它采用 IETF RFC 常见的组织方式与规范性语言，但不是 IETF 提案或互联网标准。

本文档以数据库 migration 0 及当前公开 API 为准。除非明确标记为“扩展点”或“安全考虑”，本文描述的是已经实现的行为，而不是未来规划。

## 摘要

`access_control` 为每个 identity profile 提供一套独立的、以 SQLite 持久化的访问控制能力。系统将访问控制拆分为三个相互关联但语义独立的部分：

1. 联系人用于绑定可读名称与经过认证的主体标识；
2. 访问规则用于决定某个主体能否调用特定 HTTP 方法和 API 路径；
3. 审批记录用于承载不能立即允许或拒绝的请求。

设计的核心约束是：名称由传输层 mTLS 认证，`SubjectId` 用于确认该名称背后的主体是否发生转让；规则是本地入站授权的唯一事实来源；联系人交换的权限声明只描述双方提出或公开的能力，不能替代本地规则；实时审批与持久审批可以重叠，但管理界面只展示 live 项，并由 live 审批清理重叠的持久记录。

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

**Live Review**
: 仅存在于当前进程内存中、并持有等待中请求状态的实时审批。

**Persistent Review**
: 存储在 SQLite 中、以 `(visitor, request_id)` 标识的可跨请求使用的审批记录。

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
- 数据库连接、内存策略树和实时审批注册表的生命周期不一致。

### 3.2 名称与主体标识分离

规则以名称表达，便于审计和人工管理。该名称不是应用层任意填写的 HTTP header，而是传输层从 mTLS 对端证书认证得到的 DHTTP 名称。认证层同时从证书 SKI 中取得 `SubjectId`；SKI 是签发证书时依据该名称背后的主体信息形成的 hash。

名称本身很难被未授权方冒充；`SubjectId` 解决的是名称合法转让或主体信息变化后的连续性问题。授权入口要求经过认证的名称和 `SubjectId` 同时出现或同时缺失。名称与本地联系人记录匹配、但 `SubjectId` 不匹配时，即使规则结果为 `allow`，系统也必须将请求降级为 `review`，使名称转让能够被发现并经管理员确认。

### 3.3 规则与联系人权限声明分离

`access_rules` 是本 profile 对入站请求实施授权的唯一持久化事实来源。

联系人中的两个权限字段具有不同方向：

- `requests`：对方希望本方开放的权限；
- `grants`：对方已经向本方开放的权限；
- `offers`：联系人申请方承诺在合法批准回调后向接收方开放、但当前尚未生效的权限。

本方管理员批准对方请求时，应先在 `access_rules` 中建立最终规则，再执行联系人 `local_approval`。批准过程会从规则表收集该联系人的实际授权，并通过通知器发送给对方。系统 MUST NOT 将管理员审批结果重复存入联系人 `grants` 字段。

这种分离消除了两个本地事实来源之间的同步竞争，并允许 `deny`、组规则、匿名规则等并不属于联系人声明的规则正常存在。

### 3.4 实时审批与持久审批分离

没有 `RequestId` 的请求只能实时等待；带有 `RequestId` 的已命名请求同时获得持久记录，使管理员能够在请求连接消失后作出决定。

二者不能简单合并：实时审批持有唤醒请求所需的进程内状态，持久审批则提供跨连接、跨请求的决定缓存。因此管理 API 分别列出两类审批；重叠项只在 live 列表展示，并由 live 决定清理持久记录。

## 4. 数据表示

### 4.1 时间

数据库中的 `created_at`、`updated_at` 和 `expired_after` 均为 SQLite `INTEGER`，值为 UTC Unix 时间戳，单位为秒。

使用整数的原因是避免文本时间的解析、排序和时区歧义，并使范围查询及索引比较保持数值语义。联系人 POST/响应中的三个时间使用 Unix 秒；联系人 PATCH 的 `If-Modified-Since` 使用标准 HTTP-date。持久审批 API 的 `expired_after` 使用 RFC 3339 日期时间字符串。

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

## 5. 数据库规范

### 5.1 模块版本表

`module` 表记录 schema 所属模块及版本。数据库 MUST 只包含一行模块记录。当前 schema 的固定值为：

```text
module_name = access
version     = 0
license     = Apache-2.0
```

服务启动时：

1. 若不存在 `module` 表，则在事务中执行 migration 0；
2. 若存在，则读取当前版本并按顺序执行尚未应用的 migration；
3. 数据库版本高于当前实现支持的版本时，启动必须失败；
4. migration 与版本更新必须位于同一事务中。

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
| `status`      | INTEGER | `0..5`                                                                |
| `expired_after` | INTEGER | 申请方指定的联系人申请失效时间，Unix 秒时间戳                       |
| `updated_at`  | INTEGER | 申请方发送的申请更新时间，Unix 秒时间戳                               |
| `created_at`  | INTEGER | 申请方发送的申请创建时间，Unix 秒时间戳                               |

联系人状态为：

|  值 | 名称                  | 含义                                         |
| --: | --------------------- | -------------------------------------------- |
|   0 | Pending | 等待建立或批准                         |
|   1 | Syncing | 本方已批准，正在或等待向对方同步授权结果 |
|   2 | Active  | 已激活，可继续同步权限                 |
|   3 | Transfered | 名称所代表的主体已经发生转让         |
|   4 | Expired   | Pending 申请超过有效期且未获批准     |
|   5 | Blocked   | 已被本方拉黑，拒绝重新申请和权限更新 |

首次 HTTP 创建写入 Pending，并原样保存申请方发送的 `created_at`、`updated_at` 和 `expired_after`。接收方验证 `created_at <= updated_at < expired_after`，并按申请方指定的 `expired_after` 判断申请是否有效。Pending、Syncing、Expired 和 Blocked 的申请资料与授权资料处于冻结状态，重复 POST 必须返回冲突且不得改变时间戳。只有 Active 和 Transfered 接受后续 POST，并在保持当前状态的同时替换资料和三个时间戳。

实现可以在读取或修改联系人时惰性地把 `status = Pending AND expired_after <= now` 的记录更新为 Expired。过期转换只改变状态，不改变 `updated_at`。过期记录必须保留以供审计，不得由过期处理自动删除，也不得接受本地批准。唯一的补偿例外是来自申请接收方的批准 PATCH：若其 `If-Modified-Since` 严格早于记录的 `expired_after`，申请方即使已显示 Expired 也必须接受该批准并转为 Active。

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
| `request_id`    | TEXT    | 非空请求标识                     |
| `visitor`       | TEXT    | 非空访问者名称                   |
| `visitor_sid`   | BLOB    | 1 至 64 字节                     |
| `method`        | TEXT    | 大写 HTTP 方法                   |
| `api`           | TEXT    | 绝对路径                         |
| `stage`         | INTEGER | `0` pending、`1` allow、`2` deny |
| `reason`        | TEXT    | 非空审批原因                     |
| `expired_after` | INTEGER | 决定或待审批记录的失效时间       |
| `updated_at`    | INTEGER | Unix 秒时间戳                    |
| `created_at`    | INTEGER | Unix 秒时间戳                    |

唯一键为 `(visitor, request_id)`。同一键还必须持续绑定同一 `method` 和 `api`；在记录未过期时也必须绑定同一 `visitor_sid`。尝试使用相同键访问其他方法、路径或身份时必须返回错误。

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
- 匿名请求携带 `RequestId` 并进入 review 时 MUST 被拒绝，因为持久审批无法安全绑定 visitor。

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
- `Reviewing(id, state, registry)`：调用方等待 `state`，由管理 API 允许、拒绝或由请求生命周期取消。

## 8. 审批协议

### 8.1 无 RequestId 的请求

系统只创建 live review，不创建 `access_reviews` 数据库记录。管理员针对其 live `id` 作出的决定只完成该请求。

### 8.2 带 RequestId 的请求

RequestId 由请求方按第 13.3 节算法生成，但它是可选的。只有请求明确携带 RequestId，并且同时具有经 mTLS 验证的名称和 `SubjectId` 时，才可以创建 persistent review。处理顺序为：

1. 服务使用当前请求的 method、path、普通 header、来访者名称和 `SubjectId` 重新计算 RequestId；
2. 请求携带值与计算结果不同则拒绝，不得创建或消费 persistent review；
3. 在事务中查找与 visitor、RequestId、SubjectId、method 和 API 完全匹配且尚未过期的已决定记录；
4. 若存在，删除该记录并立即返回其 allow 或 deny 结果；
5. 否则检查 `(visitor, request_id)` 是否已经绑定其他 method 或 API，冲突则拒绝；
6. 有效记录绑定其他 `SubjectId` 时拒绝；
7. 不存在记录时创建有效期一天的 pending；
8. 已过期记录重置为 pending，并更新 `SubjectId`、原因和有效期；
9. pending 请求同时进入 live registry，等待管理员处理。

已决定的 persistent review 是一次性决定：成功匹配后通过 `DELETE ... RETURNING` 原子消费。它不是长期访问规则。长期授权必须写入 `access_rules`。

### 8.3 列表去重

live 与 persistent 列表分别分页。若某个 `(visitor, request_id)` 同时存在于两处：

- 它 MUST 显示在 live 列表；
- 它 MUST 从 persistent 列表的 `total` 和 `items` 中排除。

这样前端可以分别展示“当前仍在等待的连接”和“离线待处理记录”，同时不会让管理员对同一请求看到两个独立任务。

### 8.4 决定联动

当 live review 具有重叠的 pending persistent 记录时，审批 live 项必须先删除该持久记录，再立即完成 live 请求。这个决定正被当前请求消费，不写入有效期，也不要求 `expired_after`。

persistent 项只有在没有对应 live 项时才会显示和被审批，因此审批 persistent 项只更新数据库，不反向查找或完成 live 请求。若两类状态在列表读取后发生竞态，后续 live 审批仍以删除 persistent 项并完成当前请求为准。

同一 RequestId 对应同一个规范化请求。直接审批其中一个 live 项会完成内存中所有具有相同 RequestId 的 live 等待者。

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

首次创建联系人时，状态固定为 Pending。`description` 是申请方随请求发送的简介，不得超过 80 个 Unicode 字符。申请方同时发送 `created_at`、`updated_at` 和 `expired_after`，接收方保存这些时间并按 `expired_after` 判断有效性。

申请有效期不宜过短，以免正常的离线、网络延迟或人工处理时间导致申请过早失效；也不宜过长，以免扩大未决申请和延迟批准的风险窗口。申请方 SHOULD 使用 3 天作为默认和建议有效期，并 SHOULD NOT 设置超过 7 天的有效期。

虽然两个权限映射在 JSON 语法上可以省略，但申请方 SHOULD 同时发送自身请求的权限和承诺向对方开放的权限。申请方发送的 `offers` 可以为空对象。

申请方在向对方发送 POST 之前，MUST 先为该对方名称写入精确的回调规则：方法为 PATCH，API 为 `/contact`，effect 为 allow。该回调规则是联系人建立协议的引导权限，不代表联系人已经获得其他业务 API 权限；即使申请进入 Expired，回调规则也 MUST 保留，以支持第 9.5 节的延迟批准补偿。

除回调端点外，申请方承诺开放的其他权限在申请期间只是待授予权限。申请方 MUST 保存这份待授予权限，但 MUST NOT 在发送 POST 时提前写入生效的 `access_rules`。只有收到并接受第 9.5 节的 PATCH 后，才将整份待授予权限正式授予对方。

创建联系人时，系统统一写入该联系人对固定 `PATCH /contact` 端点的 allow 回调规则；无论联系人记录来自本地发起申请还是远端 POST，都不使用绕过回调规则的创建路径。该操作不会提前应用 `offers` 中承诺的业务访问规则。

同名记录处于 Pending、Syncing、Expired 或 Blocked 时，POST MUST 返回 409，且数据库、联系人 trie 和三个时间戳 MUST 保持不变。处于 Active 或 Transfered 时，POST 可以替换 `subject_id`、`class`、`description`、`requests`、`offers` 和三个时间戳，但 MUST 保持原状态。删除联系人会删除整条记录及该联系人作为精确 grantee 的全部权限规则；记录不存在后，同名主体可以重新申请并创建新的 Pending 记录。联系人只能从 Active 或 Transfered 变为 Blocked；Pending、Syncing 和 Expired 都不得被拉黑。拉黑事务 MUST 将该联系人当前的全部精确权限规则保存到 `offers`，删除这些生效规则，再为该联系人明确写入 `POST /contact` 和 `PATCH /contact` 的 deny 规则。

### 9.4 本地批准

具有 `PATCH /contact/{name}` allow 权限的本地管理员发起批准时，顺序具有事务外的远端依赖：

1. 验证联系人存在且状态为未过期的 Pending、Syncing、Active 或 Transfered；过期的 Pending 必须先转为 Expired 并拒绝批准；
2. 将 Pending、Active 或 Transfered 写为 Syncing；Syncing 表示重试，不改变状态；所有转换均保持申请方时间戳不变；
3. 从 `access_rules` 收集该联系人作为精确 grantee 的全部 allow、review 和 deny 规则；
4. 通过 `ContactNotifier` 向对方发送授权更新；
5. 仅在通知成功后，将本地 `offers` 记为对方已经兑现的 `grants`，清空 `offers`，并把联系人状态更新为 Active。

通知不可用时返回 503；对端通知失败时返回 502；两种情况下本地状态保持 Syncing。有该 API allow 权限的管理员可以对同一联系人再次发起 PATCH，重新收集当前规则并重试通知。

通知不构成分布式事务：对方已成功处理通知、但本地数据库随后写入失败时，双方可能暂时不一致。调用方 SHOULD 使用幂等重试；对端授权更新对 Pending、Expired 补偿、Active 和 Transfered 可重复应用。

当前 pishoo 集成通过已建立的 DHTTP 连接向以下固定地址发送通知：

```text
PATCH https://{contact}/contact
Content-Type: application/json
If-Modified-Since: <stored updated_at as HTTP-date>
```

请求体为第 10.2 节定义的 `granted_access`。接收方不依赖路径参数或额外的 `kind` 字段，而是使用 mTLS 已认证的来访者名称查找对应联系人。

### 9.5 对端授权更新

收到 `PATCH /contact` 时，本方使用 mTLS 已认证的来访者名称查找联系人并将请求识别为对端授权更新。请求必须携带 `If-Modified-Since`，其值是对端保存的本申请 `updated_at`。

- Pending：当请求头时间严格早于 `expired_after` 时接受，并转为 Active；
- Expired：适用相同判断，作为对端离线期间批准的补偿接受；
- Active 或 Transfered：接受授权更新，结果为 Active；
- Syncing 或 Blocked：拒绝更新。

成功接受 PATCH 时，申请方 MUST 在同一数据库事务中将先前保存的待授予权限写入该联系人的 `access_rules`，再替换 `grants`、清空 `offers` 并把状态更新为 Active。内存策略树 MUST 在事务提交后同步更新。该过程不改变申请方的三个时间戳。请求头时间大于或等于 `expired_after` 时，不得触发 Pending/Expired 补偿，也不得授予任何待授予权限。

### 9.6 拉黑与恢复

本地管理员只可将 Active 或 Transfered 联系人改为 Blocked。该操作 MUST 在同一事务中完成以下步骤：将联系人现有的全部精确规则按 `GrantedAccess` 结构写入 `offers`；删除这些规则；写入该联系人对 `POST /contact` 和 `PATCH /contact` 的 deny 规则；将状态改为 Blocked。若删除原规则会使任一 `/acl` 管理 API 不再具有至少一位 allow 管理员，整个事务必须失败。

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

#### `POST /contact`

请求体：

```json
{
  "name": "alice.example",
  "subject_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
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
  },
  "created_at": 1785800000,
  "updated_at": 1785800060,
  "expired_after": 1786059200
}
```

`class`、`requested_access` 和 `offers` 可省略并默认为空；`offers` 为空是合法的。申请方在发送 POST 前必须实际开放固定的 `PATCH /contact` 回调权限；`offers` 中的权限只暂存，等合法批准 PATCH 到达后再在事务中正式授予。`description` 必须由申请方提供，可以是空字符串，但不得超过 80 个 Unicode 字符。三个时间字段必须由申请方提供并满足 `created_at <= updated_at < expired_after`；有效期 SHOULD 遵循第 9.3 节的建议。mTLS 来访者名称和 SubjectId 必须分别等于请求体中的 `name` 和 `subject_id`。冻结状态的同名记录返回 409，Active/Transfered 记录按第 9.3 节更新。

#### `GET /contacts`

支持 `page`、`page_size`、`sort` 和 `order`。`sort` 可选：

- `name` 或兼容别名 `names`；
- `alias`；
- `updated_at`，默认；
- `created_at`；
- `class`。

默认按 `updated_at desc`。除按名称排序外，同值记录以 `name asc` 稳定排序。

#### `GET /contact/{name}`

返回单个联系人：

```json
{
  "name": "alice.example",
  "subject_id": "0123...",
  "alias": "Alice",
  "class": "human",
  "description": "Alice",
  "status": 2,
  "created_at": 1785800000,
  "updated_at": 1785800060,
  "expired_after": 1786059200,
  "requested_access": {},
  "granted_access": {},
  "offers": {}
}
```

#### `PATCH /contact/{name}`

该接口是本地管理操作。mTLS 来访者必须已经获得该 API 的 allow 权限；来访者可以是当前 profile owner，也可以是其他管理员。请求体支持局部修改 `status` 和 `alias`，但至少必须提供其中一个字段：

```json
{
  "status": "blocked",
  "alias": "Alice"
}
```

`status` 只接受 `syncing`、`blocked` 或 `active`：`syncing` 表示批准或重试通知；`blocked` 表示拉黑；`active` 仅用于取消拉黑。空 `alias` 表示清除本地别名。状态转换必须符合第 9.4 和 9.6 节。授权由统一访问控制层在进入联系人处理器前完成；处理器仍要求存在经过 mTLS 认证的 Visitor，但不得再额外限定其名称必须等于 `owner_name`。空对象或未知字段必须被拒绝。

#### `PATCH /contact`

该接口是固定的对端回调入口，不含联系人名称路径参数，也不使用 `kind` 字段。联系人名称取自 mTLS 已认证的 Visitor；请求体必须包含 `granted_access`：

```http
If-Modified-Since: Tue, 04 Aug 2026 12:00:00 GMT
```

```json
{
  "granted_access": {
    "/api/profile": {
      "allow": ["GET"],
      "review": [],
      "deny": []
    }
  }
}
```

#### `DELETE /contact/{name}`

删除单个联系人及其精确主体规则。如果该联系人是某个 `/acl` 管理 API 规则作用域内最后一位具有 allow 权限的管理员，并且 owner 在该作用域没有 allow 权限，则返回 400。普通业务 API 上的规则不触发这项保护。

#### `DELETE /contacts`

请求体 `{"names":["alice.example","bob.example"]}`。操作在单一数据库事务中执行；任一联系人不存在，或整个批次会使任一 `/acl` 管理 API 规则作用域不再具有 allow 管理员时，整个批次失败。

### 10.3 访问规则管理 API

`/acl/apis` 分页列出 API；`/acl/access` 按 API 组织规则；`/acl/allow` 按 grantee 名称组织规则。

#### `POST /acl/access/{api}`

对路径指定的 API 创建或覆盖一条规则。例如 `/users` 使用 `POST /acl/access/users`：

```json
{
  "method": "GET",
  "effect": "allow",
  "grantee": "alice.example"
}
```

请求体不得再携带 `api`，路径是目标 API 的唯一来源。成功返回 204。除 owner 外，精确 grantee 不存在于联系人表时写入失败。修改 `/acl` 管理 API 的规则时，操作后的同一 method/API 作用域必须仍有至少一个 `Grantee::One` 或 `Grantee::Group` 具有 allow 权限；普通业务 API 不受这项约束。设置 `*?` 会删除同一 method/API 的 `**` 和 `?`；反向设置同理删除 `*?`。

#### `PATCH /acl/allow/{name}`

```json
{
  "method": "GET",
  "api": "/users",
  "effect": "review"
}
```

路径中的 `{name}` 是规则 grantee。该操作修改或覆盖此 grantee 在请求体指定 API/method 上的 effect，成功返回 204。

#### `DELETE /acl/allow/{name}`

```json
{
  "method": "GET",
  "api": "/users"
}
```

effect 不属于规则标识，因此删除请求不携带 effect。不存在的规则按幂等删除处理并返回 204。删除 `/acl` 管理 API 上最后一条 `One` 或 `Group` allow 管理员规则，并且 owner 已不具备 allow 权限时，返回 400。

#### `GET /acl/apis`

分页列出不同 API，而不是一次返回所有规则。查询参数支持 `page`、`page_size`、`sort=api|updated_at` 和 `order`，默认 `updated_at desc`。

```json
{
  "items": [{ "api": "/users", "updated_at": 1785772800 }],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

#### `GET /acl/access`

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

#### `GET /acl/access/{api}`

一个 API 通常只有少量方法和 effect，因此该接口不分页：

路径参数承载完整的规范化 API 路径，但省略开头的 `/`。例如 `/users/profile` 对应 `GET /acl/access/users/profile`。

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

#### `GET /acl/allow/{name}`

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

#### `GET /acl/allow`

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

#### `GET /acl/reviews/live`

分页列出实时审批，按递增 live id 排序：

```json
{
  "items": [
    {
      "kind": "live",
      "id": 7,
      "request_id": "9b1d5c7f4e2a60819384756647382910aabbccddeeff00112233445566778899",
      "visitor": "alice.example",
      "method": "GET",
      "api": "/private",
      "reason": "matched review rule: GET /private alice.example",
      "expired_after": null
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

#### `GET /acl/reviews/persistent`

分页列出 stage 为 pending 且未在 live 列表中展示的持久审批，按数据库 id 递增排序。响应形状与 live 相同，但 `kind` 为 `persistent`，且 `request_id`、`visitor` 和 `expired_after` 存在。

#### `PATCH /acl/review`

审批实时项：

```json
{ "kind": "live", "id": 7, "action": "allow" }
```

审批持久项：

```json
{
  "kind": "persistent",
  "id": 12,
  "action": "deny",
  "expired_after": "2026-08-05T12:00:00Z"
}
```

`action` 只接受 `allow` 或 `deny`。live 决定不需要 `expired_after`，即使它与 persistent 记录重叠；该 persistent 记录会被直接删除。只有 persistent 决定必须提供 `expired_after`，且写入值必须满足数据库的时间约束。成功返回 204；已经决定或不存在的 id 返回 404。

## 11. 一致性与并发

### 11.1 规则更新

设置或删除规则时，服务持有策略写锁；管理 API 的管理员存续校验与数据库修改在同一事务内完成，事务提交后再更新内存 trie。该写锁覆盖“校验、数据库修改、内存更新”的完整过程，避免并发请求同时通过校验并删除最后一位管理员。数据库失败不会污染内存。

### 11.2 联系人创建与删除

联系人创建先提交数据库，再更新联系人 trie。删除联系人同样持有策略写锁；管理员存续校验、受影响规则收集和联系人删除在同一事务内完成，数据库触发器清理规则；提交后再更新联系人 trie 和策略树。

如果进程在数据库提交与内存更新之间终止，重启加载会从数据库恢复一致状态。当前实现没有针对提交后内存更新失败的在线自动重载机制。

### 11.3 审批状态

live review 状态通过互斥锁保护，并通过 Future/Waker 唤醒等待请求。批准、拒绝和取消是终态；重复决定不会改变已经结束的状态。

持久决定的消费使用单条 `DELETE ... RETURNING`，以避免同一个决定被多个请求重复使用。

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

本文所称“管理 API”特指规范化路径等于 `/acl` 或以 `/acl/` 开头的 API，包括规则和审批端点。`/contact`、`/contacts` 与 `/contact/*` 是联系人协议或联系人查询端点，不纳入“始终保留至少一位管理员”的规则作用域；但删除联系人可能连带删除该联系人名下的 `/acl` allow 规则，因此删除操作仍必须执行管理员存续检查。

承载应用 MUST 使用本访问控制保护这些端点，不得因为它们属于 ACL 模块就默认公开。

`AccessService` 保存当前 profile 的 owner 名称，用于建立内存策略基线、验证联系人名称和保护管理 API 的管理员存续。该字段不赋予 owner 不可撤销的权限：启动策略会在各规则作用域先加入 owner allow 基线，随后加载的同键显式规则仍可将其改为 review 或 deny，从而允许 owner 本人也受策略管理的托管模式。

每个 `/acl` 管理 API 的 `(method, api)` 规则作用域在修改后 MUST 至少保留一个 effect 为 allow 的 `Grantee::One` 或 `Grantee::Group`。满足该条件的主体就是管理员：默认情况下是 owner；也可以是其他精确命名主体或组。

如果 owner 被配置为 review 或 deny，则同一管理作用域必须先有另一位 allow 管理员。任何管理员被改为 review 或 deny、其 allow 规则被删除，或者其联系人记录被删除时，系统都必须验证操作完成后仍有至少一位 allow 管理员；否则拒绝整个操作。`Named`、`Anony` 和 `All` 即使配置为 allow，也不计作管理员。该约束仅作用于 `/acl` 管理 API，不限制普通业务 API 的规则配置。

Owner 不写入联系人表。管理路由使用 `AccessService` 持有的 profile owner 名称，并把它作为保留名称：`POST /contact` 创建同名联系人时必须返回 400，防止联系人记录覆盖内存 trie 中 owner 的 `SubjectId`。

### 13.2 名称认证与主体连续性

来访者名称由 DHTTP 传输层通过 mTLS 证书验证，不来自普通 HTTP header，也不允许应用调用方自行声明。名称认证证明对端当前合法持有该名称的证书；证书 SKI 中的 `SubjectId` 则绑定签发证书时该名称背后的主体信息。

因此，本模块使用名称决定“是谁”，使用 `SubjectId` 判断“是否仍是先前认识的同一主体”。名称合法转让后，新持有者可以通过 mTLS 名称认证，但其 `SubjectId` 会变化；已有联系人上的 allow 随即降级为 review。承载应用 MUST 从已验证的远端证书构造 `Visitor`，不得从可伪造的应用层字段构造它。

### 13.3 RequestId 派生

RequestId 是请求方按本节算法生成并选择是否携带的 64 字符小写十六进制 SHA-256 摘要。服务器不得为每个入站请求自动补充 RequestId；它只在请求已经携带 RequestId 时重新计算并验证。

输入由以下部分组成：

1. `:method` 和 `:path`；
2. 全部普通 HTTP header 名称和原始值；
3. mTLS 验证的来访者名称；
4. 来访者证书 SKI 中的 `SubjectId`。

伪头部和普通 header 先按名称、再按值的字节序排序。每个名称和值使用 64 位大端长度前缀后输入摘要；排序后的 header 集合之后，再以相同长度前缀编码来访者名称和 `SubjectId`。该编码避免字段拼接歧义，并使 header 到达顺序不影响结果。请求 body 当前不参与 RequestId。

RequestId 的传输字段本身独立于参与摘要的普通 header 集合，不参与自身摘要。因为来访者名称和 `SubjectId` 均参与计算，同一个 RequestId 无法合法用于其他主体或其他请求。没有携带 RequestId 的请求不执行这项计算，只能进入 live 审批。

### 13.4 审批重放

持久 allow/deny 决定是一次性消费，并同时绑定 visitor、SubjectId、method 和 API，从而限制跨主体、跨端点重放。管理员设置的有效期仍应尽可能短。长期访问应使用可审计、可撤销的规则，而不是延长审批有效期。

### 13.5 通知真实性

`ContactNotifier` 只抽象传输，不在本模块内定义对端认证、重试或消息签名。承载应用 MUST 通过已认证的 DHTTP 通道发送联系人授权更新，并确认接收方身份与目标联系人一致。

## 14. 兼容性与扩展

### 14.1 Schema 演进

数据库版本 0 尚未发布，因此本规范涉及的 schema 调整直接收敛在 `0.sql`。首个正式发布版本之后，任何数据库结构变更才必须新增顺序 migration，并在成功执行后更新 `module.version`。实现不得静默打开高于自身支持版本的数据库。

### 14.2 保留的扩展点

以下能力在数据模型中存在，但尚未形成完整端到端协议：

- 从认证声明提取 `title@issuer` 组并加入授权候选；
- 主动处理名称主体转让并决定 Transfered 状态；
- 对过期 pending 审批执行后台清理。

实现和客户端不得把这些扩展点当作当前版本已经保证的行为。

## 15. 符合性要求

声称符合本规范版本 0 的实现至少必须验证：

1. schema 约束拒绝非法状态、时间类型、SubjectId 长度和规则选择器冲突；
2. 路径按段回退，具体方法优先于 `*`，精确主体优先于类别主体；
3. 未命中规则时拒绝，owner 默认规则在加载后生效；
4. 数据库规则与内存策略在创建、更新和删除后保持一致；
5. 联系人创建不产生访问规则，删除联系人清理精确规则；
6. 本地批准在通知前进入 Syncing，通知失败可重试，通知成功才进入 Active；
7. 对端授权更新由 mTLS 来访者身份而非 `kind` 字段识别；成功接受时正式应用待授予权限，过期补偿严格比较 `If-Modified-Since < expired_after`；
8. 冻结状态拒绝重复申请且保持申请时间戳，只有 Active/Transfered 接受资料更新；删除记录后允许重新申请；
9. live 与 persistent 列表均正确分页，重叠记录只显示在 live；
10. live 审批删除重叠的 persistent 记录，persistent 审批不反向操作 live；
11. 持久决定只能被完全匹配的请求消费一次；
12. `/acl` 管理 API 的规则变更和联系人删除不会移除最后一位 allow 管理员，普通业务 API 不受这项限制。

## 16. IANA 考虑

本文档不请求 IANA 分配任何名称、端口、媒体类型或协议参数。

## 17. 参考资料

- RFC 2119, _Key words for use in RFCs to Indicate Requirement Levels_.
- RFC 8174, _Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words_.
- SQLite Documentation, _CREATE TABLE_, _CREATE TRIGGER_, and _UPSERT_.
- `access/src/migrations/0.sql`，数据库 schema 的权威定义。
- `access/src/policy.rs`，规则表示与匹配算法的权威实现。
- `access/src/service.rs`，加载、授权与持久审批流程的权威实现。
- `access/src/api.rs` 及 `access/src/api/`，HTTP 管理协议的权威实现。
