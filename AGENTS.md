# daccess 项目协作规则

## 仓库结构

- `src/` 是独立的 Rust `access_control` 库，包含访问决策、联系人、审批、SQLite 持久化与 Axum 管理 API。
- 管理界面由 pishoo 的 Workspace 持有；本仓库不包含或构建前端静态资源。
- `SPEC.md` 是数据模型、状态机与 HTTP API 的协议依据；改变对外行为时同步更新实现、测试和文档。
- pishoo 负责 DHTTP/mTLS 身份验证、profile 生命周期和 Workspace 前端；库的检查与测试通过 Cargo 执行，前端开发、构建与 E2E 在 pishoo 仓库执行。

## 分层规范文件

- 根目录 `AGENTS.md` 的通用规则适用于整个仓库。
- 同时修改多个范围时，必须读取并遵守所有相关目录的 `AGENTS.md`；若目标目录存在更深层的规范文件，也必须一并读取。
- 规则发生冲突时，以更接近目标文件的规范为准；`AGENTS.override.md` 优先于同目录的 `AGENTS.md`。

## 安全与协议边界

- 来访者名称和 `SubjectId` 必须来自已经验证的 mTLS 对端身份；不得信任普通 HTTP header 中的同名字段。
- 每个 identity profile 必须拥有独立的 `AccessService` 和 SQLite 数据库，不得跨 profile 共享服务状态。
- 保持默认 deny、profile owner 默认 allow、SubjectId 变更转审批及最后一位管理者保护等安全不变量。
- review request ID 必须由服务端根据请求内容和认证身份派生；不得接受客户端提供或覆盖该值。
- 改动管理 API 时，同时核对 `SPEC.md`、Rust 导出类型、pishoo Workspace 的协议类型与调用方，以及相关测试。

## Git 规则

- 未经用户明确要求，绝不执行 `git add` 或任何会改变 index/staged 状态的操作。
- 尤其在用户已有暂存文件时，只修改工作区并说明未暂存改动，不能污染用户的 staged diff。
- 不覆盖或丢弃用户的本地修改；遇到不相关修改时保留并绕开它们。

## 验证规则

- 优先执行与修改范围相符的局部静态检查；需要测试时，选择定向测试。
- 未经用户明确要求，不执行编译，尤其不得随意触发 workspace 全量编译、前端完整构建或完整 E2E。
- 跨越 daccess 与 pishoo Workspace 的改动，需要分别说明各仓库的验证情况和未执行项目。
