# KeePassMCP

**KeePass 原生 MCP 插件**：对本机暴露 MCP 服务（Streamable HTTP），本地 Agent 连接后**可见/可操作除掩码字段外的所有字段**——重新分类、重新命名、整理元数据，密码等受保护字段在协议层、实现层、数据层三层不可达。

> 状态：**设计完成，实施交接中**。设计见 [docs/DESIGN.md](docs/DESIGN.md)；**实施请读 [docs/HANDOFF.md](docs/HANDOFF.md)**（自包含规格：工具/资源/掩码/安全/验收标准）。

## 一句话定位

KeePass 进程内嵌 MCP 门卫：按 KDBX `Protect` 标志自动掩码，Agent 只能读写元数据（标题/URL/备注/自定义字段/分组/标签），永远拿不到密码明文。

## 核心设计

- **掩码边界**：`Protect="True"` 字段 → 不可见（输出 `[protected]`）、不可操作（工具 schema 不含、实现层拒绝）
- **传输**：Streamable HTTP，仅绑定 `127.0.0.1` 回环 + Bearer token 鉴权
- **写保护**：所有写工具支持 `dry_run=true` 变更预览（与执行共用同一变更计算函数）；破坏性操作需 `confirm=true`；变更前自动备份 + 审计日志
- **锁库联动**：KeePass 锁定即拒绝一切读写

## 架构

```mermaid
flowchart LR
    subgraph "KeePass 进程（本机）"
        K["KeePass 2.x"] --> P["KeePassMCP 插件<br>(.NET Framework 4.8)"]
        P --> L["KeePassLib API"]
        P --> S["MCP Server<br>(Streamable HTTP 127.0.0.1)"]
        S --> A["审计 + 变更备份"]
    end
    C["本地 Agent<br>(MCP 客户端)"] -- "localhost + token" --> S
```

## MCP 工具（设计）

- 只读：`list_databases` / `list_groups` / `list_entries` / `get_entry` / `search_entries` / `get_audit_log`
- 写（元数据）：`rename_entry` / `update_entry_fields` / `move_entry` / `create_group` / `rename_group` / `delete_group` / `add_tag` / `remove_tag` / `create_entry` / `backup_database`
- 资源：`keepass://groups`、`keepass://entries/{uuid}`、`keepass://audit` 等

## 目录

```
keepass-mcp/
├── docs/DESIGN.md       # 设计方案（决策记录）
├── docs/HANDOFF.md      # ★实施交接文档（编码会话直接读这份）
├── src/                 # 插件工程（由实施会话创建）
└── README.md
```

## 决策记录

- 2026-10-01 掩码：仅按 `Protect` 标志，UserName 不加入默认掩码（可见可操作），配置可追加
- 2026-10-01 dry-run：写操作需预览，预览与执行共用同一变更计算函数
- 2026-10-01 连接：标准 MCP 客户端配置（`type: http` + Bearer token）

## 下一步

已交接给实施会话，按 [docs/HANDOFF.md](docs/HANDOFF.md) §13 顺序推进：P0 验证（MCP SDK 兼容性 + HttpListener）→ P1 只读 → P2 写操作 → P3 打磨。
