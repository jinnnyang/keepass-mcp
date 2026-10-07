---
name: keepass-skill
description: 连接 KeePassMCP（KeePass 原生 MCP 插件）存取密码库条目、密钥与元数据。当 Agent 需要查询/搜索/创建/更新/移动 KeePass 条目、读取密码库分组结构、读取或生成密码、整理标签、备份/回滚/审计、保存库时使用。适用于用户提到 KeePass/密码库/密钥条目/凭证存储，或需要从本机密码库取回/写入凭证信息。
---

# KeePassMCP 使用指南

KeePassMCP 是运行在 KeePass 进程内的 MCP 服务（Streamable HTTP，仅回环 127.0.0.1）。本 Skill 教会 Agent 如何连接并安全地使用它。

## 前置条件（先检查，不满足先向用户说明）

1. **KeePass 已运行且已解锁目标密码库**——未解锁或锁定时，任何对库的操作返回 `database_locked`。
2. **插件已加载**：`%APPDATA%\KeePassMCP\keepassmcp.log` 有 `KeePassMCP initialized`。
3. **连接信息存在**：`%APPDATA%\KeePassMCP\connection.json`（含 `url` 与 `headers.Authorization`）。可用环境变量 `KeePassMCP_DATA_DIR` 覆盖数据目录。

## 连接

- 端点：`http://127.0.0.1:<port>/mcp`（端口每次启动可能变化，**以 connection.json 为准**）
- 鉴权：HTTP 头 `Authorization: Bearer <token>`（token 即库内配置条目的鉴权密钥，由 KeePass 配置页管理）
- 协议：MCP Streamable HTTP，JSON-RPC 2.0。**无会话（stateless）**：`initialize` 握手后无需 `notifications/initialized`、无需回传会话头，直接 POST + Bearer 即可
- 信封：工具结果在 `result.content[0].text`（内嵌 JSON，`ok`/`error.code`）；HTTP 401/403=鉴权层失败；200+`isError=true`=工具业务失败
- 所有响应为 UTF-8（`charset=utf-8`），客户端按 UTF-8 解码中文，勿按 Latin-1

读取连接信息（PowerShell）：

```powershell
$c = Get-Content "$env:APPDATA\KeePassMCP\connection.json" -Raw | ConvertFrom-Json
$c.url; $c.mcp_client.headers.Authorization
```

快速自检（curl）：

```powershell
curl.exe -X POST $c.url -H "Authorization: $($c.mcp_client.headers.Authorization)" `
  -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"agent","version":"0"}}}'
```

## 安全铁律（不可违反）

1. **受保护字段永不出现明文**：所有读出口（`get_entry`/`list_entries`/`search_entries` 等）对 `Protect="True"` 字段与 `_mcp_` 字段一律输出 `[protected]`。不要把 `[protected]` 当作缺失或失败。
2. **明文唯一出口**：`read_secret` 返回受保护字段明文一次，需条目 `_mcp_read_protected=1`（或配置条目 default 允许）——**无权限返回 `permission_denied`，不弹窗**。配置条目（`_mcp_config=1`）禁止读取（`token_entry_protected`）。明文只用于一次性用途，不写入会话记录。
3. **`_mcp_` 前缀字段是插件保留**：`create_entry`/`update_entry_fields` 写入 `_mcp_*` 字段一律拒绝（`reserved_field`）。
4. **创建条目免权限，改已有需授权**（Q1 三态）：`create_entry` 无需权限（含写入 Password）；改已有条目按字段授权（非保护字段需 `_mcp_write`，含 Password 需 `_mcp_write_protected`，移动需 `_mcp_move`，均可用配置条目 default 聚合）。
5. **写操作先 `dry_run=true`**：所有写工具支持预览（零副作用：不落库/不备份/不审计），预览含保护字段一律掩码。确认无误后再去掉 dry_run 执行。
6. **破坏性操作必须 `confirm=true`**：`delete_group`、`restore_backup` 必须显式传 `confirm=true`，否则拒绝。
7. **`database_id` 必传**：除 `list_databases`/`get_audit_log` 外所有库相关工具必须传 `database_id`（来自 `list_databases` 返回的 `id` 字段，即库路径），否则 `database_not_found`。
8. **审计/备份/保存默认拒绝**：`get_audit_log` 需 `_mcp_audit_default=1`、`backup_database`/`restore_backup` 需 `_mcp_backup_default=1`、`save_database` 需 `_mcp_save_default=1`（配置条目字段，默认 0）。
9. **锁库即拒绝**：KeePass 锁库后请求返回 `database_locked`，先请用户解锁。

## 标准工作流

### 1. 起步

1. `list_databases` → 拿到库 `id`、锁定状态、条目/分组数。
2. `list_groups`（传 `database_id`）→ 分组树，定位目标分组 `uuid`。

### 2. 查询条目

- `list_entries`（`database_id` + 可选 `group_uuid`/`limit`）→ 条目摘要。**全库平铺用 `recursive=true`**（一次返回全部子组条目，每条带 `group_path` 供聚合，免去逐组遍历）——整理/审计场景默认用它。
- `search_entries`（`database_id` + `query` + 可选 `scope`）→ 关键词搜索（受保护字段不参与搜索）。
- `get_entry`（`database_id` + `entry_uuid`）→ 完整信息（受保护字段 `[protected]`）。
- 明确需要明文时：`read_secret`（需授权，见铁律 2），仅读所需字段名。

> uuid 与计数口径：所有工具返回的 uuid 由服务端统一大写 hex（32 位），**查找一律大小写不敏感**（大小写任意均可）；`list_groups` 的分组 `entry_count` **含全部子组条目**（递归计数），不是"仅直接条目"。

### 3. 创建新条目（含密码）

优先用插件生成密码（明文不经 Agent 上下文）：

```json
{ "database_id": "<id>", "group_uuid": "<uuid>", "title": "服务名",
  "generate_password": { "length": 20, "charset": "alnum" },
  "fields": { "UserName": "user@example.com", "URL": "https://..." } }
```

也可 `fields` 直接传 `Password`（值仅此处写入）。dry_run 预览 → 执行。

### 4. 整理/更新

- 重命名：`rename_entry`；改字段：`update_entry_fields`（`fields: {字段名: 新值}`）；移动：`move_entry`；标签：`add_tag`/`remove_tag`；分组：`create_group`/`rename_group`/`delete_group`（confirm）。
- 全部先 `dry_run=true`。

> **没有单条删除工具**（无 `delete_entry`）：删除单条 = 建临时分组 → `move_entry` 移入 → `delete_group`（confirm=true）整组删除。批量删除同法（全移入一个临时组一次删）。
>
> **响应语义**：`move_entry` 目标组与当前组相同 → 返回 `no_op`（error 形态，实为已满足，非失败，批量脚本勿判失败）；`create_group` 真跑响应 `changes[0].target.uuid` 即真实组 uuid（dry-run 才是占位预览值），无需再 list 遍历。

### 5. 备份/审计/保存

- 写操作执行前插件自动生成非保护字段快照；`backup_database` 手动整库快照 → 返回 `backup_id`；`restore_backup` 按 `backup_id` 回滚非保护字段（confirm）。
- `get_audit_log` 查看写执行与密钥访问记录（只记字段名不记值）。
- 默认手动保存：Agent 的改动在内存，需 `save_database`（`_mcp_save_default=1`）显式落盘，或提示用户按 Ctrl+S。

## 插件行为说明

- **写操作后 UI 自动刷新**：KeePassMCP 直改内存 `PwDatabase`（绕过 KeePass 的 UI 事件），写工具**真跑**成功后插件主动刷新主窗体分组树/条目列表（`UpdateUI`，经 UiWrite 统一挂接）——MCP 建组/删组/移动后 KeePass 界面即时可见，**无需重开库**。dry-run 不触发刷新（未改库）。
- 不依赖 KeePass「定时自动刷新」选项（周期长且可能被关闭）。早期版本未主动刷新，需重开库才显示，已修复。
- 依赖 KeePass 主窗体存在（正常运行即有）；无活动库/异常时刷新静默降级（不影响 MCP 响应）。

## 错误处理

| 错误码 | 含义 | 处置 |
|---|---|---|
| `database_not_found` | `database_id` 未打开/不对 | 重查 `list_databases` 的 `id` |
| `database_locked` | 库已锁定 | 请用户解锁后重试 |
| `permission_denied` | 无字段授权（读/写/审计/备份/保存） | 需用户在 KeePass 配置条目或条目标记加 `_mcp_*` 字段 |
| `reserved_field` | 写入 `_mcp_` 前缀字段 | 不得写入保留字段 |
| `token_entry_protected` | 试图读取配置条目明文 | 配置条目禁止读取 |
| `approval_denied/timeout` | （旧体系遗留，不应出现） | 见上，当前为字段授权 |
| `unknown_tool` | 工具名错误 | 对照 tools/list 检查 |

## 工具完整参考

全部 18 个工具的名称、参数、权限要求见 [references/tools.md](references/tools.md)。不确定参数时先 `tools/list` 拉取最新 schema。
