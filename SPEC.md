# 联系人与 ACL 协议

本节由当前 daccess 管理 Router 提供。除另有说明外，管理请求经过统一 ACL，不额外将所有管理操作限定为所有者。Pishoo 负责从真实 DHTTP/mTLS 连接建立 Visitor；不接受 HTTP header 伪造名称或 SubjectId。

## 路由

| 方法与路径 | 行为 |
| --- | --- |
| GET /std/contact/list | 分页联系人；支持 page、page_size（1–100）、sort、order、search、modified_since |
| GET /std/contact?name=alice.smith~ | 查询指定联系人 |
| 内部 `AccessService::record_outbound_contact` | 仅供宿主记录真实连接确认的出站联系人，不注册 HTTP PUT、不产生授权 |
| PATCH /std/contact?name=alice.smith~ | 修改别称、关系状态或有效期 |
| DELETE /std/contact?name=alice.smith~ | 删除单个联系人及精确主体 ACL |
| DELETE /std/contact | JSON names 非空数组，事务性批量删除 |
| POST /std/contact | 远端本人提交申请；from/to 表达方向，名称与 SubjectId 校验 Visitor |
| GET /std/contact?name=NAME | 管理者读取详情；普通访问者只读取与自身真实主体绑定的最小状态和当前授权 |
| GET /std/acl/status?id={id} | 查询调用者的审批状态；记录必须属于 Visitor 的名称及 SubjectId |

Pishoo 补充以下路由，同样先经统一 ACL：

| 方法与路径 | 行为 |
| --- | --- |
| POST /std/contact | 本端发起；JSON from、to、description、requested_capabilities、offered_capabilities，可选 expires_after 或 valid_before；202返回联系人投影 |
| GET /std/contact?name=NAME、GET /std/contact/list | 管理查询合并后台投递状态，未验证主体的意图具有 null id/subject_id、delivery_status 和 delivery_error |
| GET /std/contact/{name}/profile/avatar | 使用远端提供的头像；校验保存的 SubjectId，无本地覆盖或上传接口 |

独立 /std/contact/application、/std/contact/status、/std/contact/requests 及刷新/删除任务入口均已移除；旧 /std/contacts、/std/contact/{name} CRUD、/std/contact/self 和 /std/contact/local/* 路由被移除。

## 联系人管理

PUT 接受 subject_id、alias、class、description、status、requested_access、offers、expires_after、valid_before。description 最多 80 字符；alias 最多 80 字符，不允许控制字符。status 仅 pending 或 active，省略时 pending。name 支持完整名称或以 ~ 结尾的 .dhttp.net 简写，不允许 owner 保留名称。

PUT 在事务中保存完整资源，保持 id、created_at 和已有 ACL。已有 active 不降回 pending，blocked 必须显式通过 PATCH 解除；同名不同 SubjectId 返回 409，不把旧授权转移给新身份。未提供有效期时，已有资源保留到期时间，新资源默认 7 天。requested_access、offers 为声明，最终权限只由 access_rules 决定；不接受写入 granted_access。

PATCH 接受 status、alias、expires_after、valid_before，至少一个字段。空 alias 清除别称；active 接受 pending/transfered 或解除 blocked；blocked 拉黑 active/transfered。拉黑保留拒绝规则与原权限快照；不删除联系人。更改关系状态不等于授予聊天权限。原有最后一位 ACL 管理员保护继续适用。

本端发起申请可以先进入本地投递队列；无能力选择时不探测对端能力或权限。未知对端在首次经认证回执后创建绑定 SubjectId 的 pending 联系人，有无聊天权限都保留在联系人目录。投递任务记录 contact_id 与 SubjectId；联系人删除、重建、换主体或拉黑后不能被旧任务恢复。旧任务在首次认证回执后补全绑定。

远端 application_id 与载荷保持原有幂等规则；已有 active 联系人再次申请能力时保持 active。

## 时间与增量读取

- updated_at：服务端维护的最后修改时间，Unix 秒。
- expires_after：写入参数，从当前时刻起的有效秒数，必须为正整数。
- valid_before：写入参数／响应字段，绝对到期 Unix 秒，写入时须晚于当前时刻。
- expires_after 与 valid_before 二选一；拒绝同时提供及整数溢出。
- modified_since：列表包含 updated_at >= 此值的联系人，保留同一秒内的更新；客户端按名称合并去重。
- 增量列表还返回 deleted: [{name, updated_at}]。首次全量不返回历史删除标记；重建联系人会清除旧标记。

开始同步前记录本端时间作为下一轮边界，并读取全部分页；不能将结束时刻作为边界而漏掉读取期间的修改。删除标记独立于分页返回，客户端去重。数据库内部 expired_after 列及公共 Rust ContactRecord 的原字段保留，HTTP 联系人和申请回执统一序列化为 valid_before。ACL 审批列表的 expired_after 表示待办到期时间，已批准的 ACL 无此到期字段。

## 统一 ACL

中间件不按路径跳过判断；内部管理请求也调用 AccessService::auth。默认 deny 与 owner 基线 allow 保留。管理处理器不再次要求 owner。POST /std/contact 的本端申请要求真实所有者名称和主体同时匹配；提供能力时仍核验 PATCH /std/acl/allow 权限，目标使用 name query。

规则仍按方法和路径段前缀匹配，不使用 query 区分授权范围。联系人 GET 通过 GET /std/contact/list 的 ACL 判断是否具有目录管理权；没有目录权限时只允许查询自己的名称且必须匹配已保存的 SubjectId，返回最小关系状态及当前授权。

Named／All 授权面向已验证具名身份或所有访问者，不依赖历史联系人记录的 SubjectId；其 allow 不会因历史主体变更再生成审批。One／Group 等针对身份的 allow 仍在同名 SubjectId 变化时转审批。回执处理器在 ACL 之后继续核对记录归属，不能读取其他身份的记录。

daccess 建库不写入默认 ACL。Pishoo 仅首次初始化写入 GET /std/contact allow **、GET /std/acl/status allow **、POST /std/contact allow **，并显式设置 GET /std/contact/list deny *? 以阻断父路径继承，以及公开 Profile／Workspace／能力发现规则。所有规则允许修改、拒绝、删除，重启不补回；本端发起核验真实所有者及所选授权写入权限，不能伪造 from 代发。

其他 ACL 查询、写入、审批、管理员保护及策略优先级沿用上游 0.1.1；见 UPSTREAM_SPEC.md 的相应算法说明，旧路径和旧 SubjectId 广泛 allow 行为以本文为准。

## 业务请求触发审核

调用者直接请求业务接口，由接收方统一 ACL 判断，不先申请能力或探测对方权限。合法请求头 `If-Reviewed` 仅允许单个 `waiting` 或 `break`，缺省为 `break`；非法值或重复头返回 400。ACL allow 正常执行，deny 返回 403；匿名 review 拒绝且不建待办。

- `review + waiting`：只登记内存实时待办并等待原请求；批准后继续执行原业务，拒绝返回 403。请求 Future 取消、适配器超时或进程退出时清理，不将待办落库。适配器须设置有界等待；Pishoo 上限 300 秒。
- `review + break`：保存异步待办，返回 `400 Bad Request`、`Cache-Control: no-store` 和 `{"error":"need_review","review_id":12,"status_url":"/std/acl/status?id=12"}`。默认待办期限 1 天。调用者稍后重试原业务；可选查询状态，不必先访问联系人状态。

异步去重键由服务端计算：`SHA256("dhttp/request-id/1" + NUL + LP(method) + LP(normalized_path) + LP(visitor) + LP(subject_id))`，LP 为 8 字节大端长度及原始字节。路径去除 query 并沿用 ACL 规范化；普通请求头、query、正文不参与去重。外部 Request-Id 不控制审核。

### 审批管理与授权范围

`GET /std/acl/review/list?status=pending|expired&kind=all|live|persistent` 默认 pending/all，合并后按 requested_at/id 倒序分页。每条有 `kind`；实时待办 expired_after=null，只出现在 pending。实时 id 与持久 id 是两个命名空间，PATCH 必须携带 kind（省略兼容为 persistent）。已断开或超时的实时待办不显示为过期历史。

`PATCH /std/acl/review`：`{"id":12,"kind":"persistent","action":"allow"}`，action 为 allow/deny；不需要决定有效期。`DELETE /std/acl/review?id={id}` 仍只删除已过期的异步 pending 记录。

批准在一个数据库事务中写入该具名身份对原 method 和规范化 API 路径的普通 `allow`，更新对应异步记录，提交后更新策略索引并唤醒同一身份、SubjectId、method、path 的所有实时等待。后续访问直接通过 ACL，重启仍有效，直到管理员修改、撤销或删除联系人。拒绝对称写入普通 `deny`。ACL 路径段前缀匹配与其他规则一致，不绑定某次请求正文或某条消息，不扩大到其他 method。

已存在联系人须仍匹配原 SubjectId，且不能通过批准撤销拉黑；否则返回 409，先显式处理联系人身份或关系冲突。陌生身份审批时建立 pending 联系人用于保存可信 SubjectId，不接受好友关系，不修改已有别称、关系状态或其他权限。审批入口自身经过统一 ACL，并保留最后管理员保护。

联系人申请／接受仅处理关系，requested_access 不再由 Workspace 合成访问审批；真正的访问审批来自业务请求。新远端联系人申请即使未声明 requested_access 也保持 pending，已有 active 关系保留。

已批准记录的状态是历史回执，当前访问始终由 ACL 决定。

## 数据库结构迁移

保留 `src/migrations/0.sql`、`1.sql` 和 `2.sql` 的版本迁移链。新库先创建基线结构，已有 v0/v1 数据库在原库中按版本事务升级到 v2。v2 重建联系人表以允许过期后修改、使用重复别称，并增加更新时间索引、删除记录和触发器。迁移保留联系人、ACL、审批和申请回执数据，以及联系人 id 和自增序列。

迁移只调整结构，不改写历史 ACL 路径、不删除规则、不插入默认授权。旧接口规则由管理员自行调整。迁移失败回滚当前事务，不自动创建新库替换原库。无法识别的格式和不支持的版本报错并保留原文件。已有数据库升级或重启均不补默认规则。


## Query 管理资源

`GET/POST /std/acl/access?api=/std/message`，`GET/PATCH/DELETE /std/acl/allow?name=NAME`。GET 缺省目标保留原全部树响应，有目标保留原单对象响应。api 要求开头 /，name 保留特殊 Grantee（?、*?、**、组名@签发者）。标准 query 编码，重复、空目标及写入缺目标为 400。

`GET /std/acl/review/list`，`GET /std/acl/status?id=ID`，`DELETE /std/acl/review?id=ID`。id 必须唯一且为正整数；PATCH /std/acl/review 的 body 不变。状态查询继续绑定真实 Visitor 的名称和主体。旧对象路径不再注册，旧对象级授权不自动转换为固定入口管理权限。

`/std/acl/permissions` 仍由宿主提供只读 GET；PUT/DELETE 由其他任务实施。
