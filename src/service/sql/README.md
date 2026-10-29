# SQL sources

| 路径 | 用途 |
| --- | --- |
| `schema.sql` | 新空库的基线结构 |
| `migrations/v1_add_application_receipts.sql` | 联系人申请回执 |
| `migrations/v2_update_contact_lifecycle.sql` | 联系人更新、删除记录与索引 |
| `migrations/v3_add_review_decisions.sql` | 审批决定、额度及待审唯一性 |

`AccessService::migrate` 按上述顺序执行，每步使用原有事务，并维护 `module.version`（不使用 PRAGMA user_version）。当前版本为 v3；保留数据及历史 ACL 路径，不补默认授权。`UPSTREAM_SPEC.md` 保留已发布 0.1.1 的历史源码路径。宿主的固定 Git 依赖、商店 vendor 不随本地目录整理更新。
