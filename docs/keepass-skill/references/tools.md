# KeePassMCP 工具完整参考（18 个）

来源：插件 `ToolRegistry.All()`（tools/list 实时 schema 为准）。信封约定：MCP `tools/call` 结果在 `result.content[0].text`（内嵌 JSON，`ok` / `error.code`）；HTTP 错误 401=token 无效、403=Host 白名单外。

## 只读（6）

| 工具 | 参数 | 权限 | 说明 |
|---|---|---|---|
| `list_databases` | 无 | 无 | 列出打开/锁定库（id=库路径、锁定状态、条目/分组数；无明文） |
| `list_groups` | `database_id`*、`parent_uuid`? | 无 | 分组树；`parent_uuid` 只返回子树 |
| `list_entries` | `database_id`*、`group_uuid`?、`recursive`?、`limit`? | 无 | 分组下条目摘要（受保护字段掩码）；缺省 `group_uuid`=根组直接条目；`recursive=true` 全库平铺（含全部子组，每条带 `group_path` 供聚合） |
| `get_entry` | `database_id`*、`entry_uuid`* | 无 | 条目完整信息（受保护字段 `[protected]`） |
| `search_entries` | `database_id`*、`query`*、`scope`?（all/title/username/url/notes）、`limit`? | 无 | 关键词搜索（受保护字段不参与） |
| `get_audit_log` | `limit`?（默认 50）、`since`?（RFC3339） | `_mcp_audit_default=1` | 最近审计记录（只记字段名不记值） |

## 密钥访问（1）

| 工具 | 参数 | 权限 | 说明 |
|---|---|---|---|
| `read_secret` | `database_id`*、`entry_uuid`*、`fields`?（默认全部受保护字段） | 条目 `_mcp_read_protected=1` 或 default 允许 | 明文唯一出口；配置条目禁止（`token_entry_protected`）；访问记审计 |

## 写（11）

所有写工具支持 `dry_run`?（预览零副作用）。`*`=必传。

| 工具 | 必传参数 | 权限 | 说明 |
|---|---|---|---|
| `rename_entry` | `database_id`、`entry_uuid`、`new_title` | `_mcp_write` | 重命名 |
| `update_entry_fields` | `database_id`、`entry_uuid`、`fields`（`{字段名:新值}`） | 非保护字段 `_mcp_write`；含 Password 等保护字段 `_mcp_write_protected`；`_mcp_*` 保留（reserved_field） | 更新字段（保护字段值仅写入，不进读出口/审计/备份） |
| `move_entry` | `database_id`、`entry_uuid`、`target_group_uuid` | `_mcp_move` | 移动条目；**已在目标组 → `no_op`（error 形态，实为已满足，非失败）** |
| `create_entry` | `database_id`、`group_uuid`、`title` | 免权限 | 创建（fields 可含 Password；`generate_password`:{length 4..128 默认16, charset all/alnum/lower/upper/digits/special 或自定义} 插件内生成主推；`_mcp_*` 保留） |
| `create_group` | `database_id`、`name`；`parent_group_uuid`?（默认根） | `_mcp_write` | 建分组；真跑响应 `changes[0].target.uuid`=真实组 uuid（dry-run 为占位预览值） |
| `rename_group` | `database_id`、`group_uuid`、`new_name` | `_mcp_write` | 重命名分组 |
| `delete_group` | `database_id`、`group_uuid`、`confirm`*（必须 true） | `_mcp_move` | 删分组及其全部子组与条目（预览列出将删条目数） |
| `add_tag` | `database_id`、`entry_uuid`、`tag` | `_mcp_write` | 加标签 |
| `remove_tag` | `database_id`、`entry_uuid`、`tag` | `_mcp_write` | 移除标签 |
| `backup_database` | `database_id` | `_mcp_backup_default=1` | 整库非保护字段快照，返回 `backup_id` |
| `restore_backup` | `database_id`、`backup_id`、`confirm`*（必须 true） | `_mcp_backup_default=1` | 回滚非保护字段（保护字段不触碰） |
| `save_database` | `database_id` | `_mcp_save_default=1` | 显式落盘（保存前自动整库快照） |

## 权限字段（`_mcp_*`）速查

- 条目显式字段优先：`_mcp_read` / `_mcp_read_protected` / `_mcp_write` / `_mcp_write_protected` / `_mcp_move` / `_mcp_list`（`=0` 对客户端隐身）
- 无字段 → 配置条目 default 最严聚合（`_mcp_read_default` 等九项）→ 内置硬编码
- 内置默认：read/write/move/list=允许；read_protected/write_protected/audit/backup/save=拒绝
- 配置条目 = 任意条目含 `_mcp_config=1`（多条目并集；`_mcp_scope_self=1` 不并入全局）
- 无配置条目时插件自动创建 `MCPServerConfiguration`（回环 127.0.0.1:6789 + 随机 token）

## 常见错误码

`database_not_found`（database_id 不对/未开）、`database_locked`（锁定）、`permission_denied`（字段授权不足）、`reserved_field`（写 `_mcp_*`）、`token_entry_protected`（读配置条目）、`unknown_tool`、`host_unavailable`（KeePass 未加载）、`no_op`（已满足目标——如 move 到当前组，实为成功语义）。

## 使用须知补充

- **没有 `delete_entry`**：删单条/批量 = 建临时分组 → `move_entry` 移入 → `delete_group`（confirm=true）。
- **uuid**：服务端统一大写 hex（32 位）输出，**查找大小写不敏感**——任何大小写均可传。
- **`list_groups` 的 `entry_count` 含全部子组条目**（递归计数），不是仅直接条目。
- **全库平铺**：`list_entries` 传 `recursive=true` 一次返回全部子组条目（带 `group_path`），整理/审计场景默认用它，免逐组遍历。

## 响应标注

- 配置条目与 `_mcp_read=0` 隐藏条目：`title=[protected]`、`protected_field_names=["*"]`，且携带非敏感标志 `is_config_entry=true`——客户端可编程跳过/标注，无需猜测。
- 所有响应 `Content-Type: application/json; charset=utf-8`，按 UTF-8 解码中文（勿按 Latin-1，否则中文组名乱码）。
