# KeePass MCP 插件设计方案（探索阶段）

> 状态：**设计已澄清（两轮访谈），待 P0 验证后实施**
> 日期：2026-10-01（第二轮访谈定稿密钥访问边界）
> 定位：通用 KeePass 2.x 插件，对本机暴露 MCP 服务；本地 Agent（moirai 生态或其他 MCP 客户端）连接后**可见/可操作除掩码字段外的所有字段**（重新分类、重新命名、整理元数据等）；创建条目时可写入密钥，读取/修改已有密钥需审批（§6.7）
> 标记：〔设计〕= 设计决策（未验证）　〔待验证〕= 需实现前验证　〔参考〕= 参考生态先例

---

## 1. 目标与边界

**做什么**：让本地 AI Agent 通过 MCP 协议，对 KeePass 中已解锁的数据库执行**元数据整理**——重命名条目、改 URL/备注/自定义字段、条目跨分组移动（重新分类）、分组/标签管理、搜索与审计。

**明确不做**（安全边界）：
- 掩码字段（KDBX `Protect="True"` 的字段：密码、PIN、密钥等）**默认不可见、不可操作、不进入常规工具参数**
- **密钥访问边界（2026-10-01 访谈定稿，ADR-0001）**：创建新条目时可写入密钥（免审批）；读取已有密钥明文（`read_secret`）、修改已有密钥字段需**密钥访问审批**（§6.7）
- **明文不变量**：任何读出口/资源/审计/备份**永不含保护字段明文**；不允许把保护字段值复制进可见字段（schema 排除 + 全审计，不做内容比对）
- 不导出数据库、不做主密钥管理
- 即使 Agent 被诱导/被注入，常规路径也拿不到密码明文；唯一例外是审批通过的 `read_secret` 单次返回

---

## 2. 架构总览

```mermaid
flowchart LR
    subgraph "KeePass 进程（本机）"
        K["KeePass 2.x 主程序"] --> P["MCP 插件<br>(.NET Framework 4.8)"]
        P --> L["KeePassLib API<br>(PwDatabase/PwEntry)"]
        P --> S["MCP Server<br>(Streamable HTTP, 127.0.0.1)"]
        S --> A["审计日志 + 变更备份"]
    end
    subgraph "本机 Agent 侧"
        C["MCP 客户端<br>(moirai / Claude Desktop / 自建)"]
    end
    C -- "localhost:端口<br>token 鉴权" --> S
```

〔设计〕要点：
- **传输用 Streamable HTTP**（Agent 无法把 GUI 应用当子进程 spawn，stdio 不可行）
- **只绑 127.0.0.1 回环** + token 鉴权（见 §6）
- 插件在 KeePass **解锁状态下**才开放读写；锁库即拒绝（见 §6.3）

---

## 3. 掩码规则（核心安全边界）

| 规则 | 实现 | 状态 |
|------|------|------|
| 字段级掩码 | KDBX 中字段的 **Protected 标志**（`<Value Protect="True">`）→ 掩码 | 〔设计〕 |
| 密码类字段 | `Password` 及用户标记保护的字段 → 永远掩码 | 〔设计〕 |
| 用户名字段 | 默认**不**掩码（**已确认 2026-10-01**：UserName 不加入默认掩码，可见可操作）；仍保留配置追加能力 | 〔设计〕✓已决 |
| 掩码呈现 | 读取时输出占位符 `[protected]` / `••••`，**绝不返回明文** | 〔设计〕 |
| 掩码不可写 | 常规写工具的参数 schema **不包含**保护字段；`update_entry_fields` 出现保护字段名 → 需审批（§6.7），未审批则拒绝 | 〔设计〕 |
| 创建可写密钥 | `create_entry` 可携带保护字段值（Agent 传值或插件内生成），免审批（ADR-0001） | 〔决策〕✓已决 |
| 审批读改 | `read_secret` / 修改已有保护字段需密钥访问审批（白名单免审批 + UI 弹窗） | 〔决策〕✓已决 |
| 敏感字段清单 | 插件配置允许追加"额外掩码字段名"（如 UserName、自定义敏感项） | 〔设计〕 |

〔参考〕KeePassRPC 同样把"受保护字段不暴露给外部进程"作为第一原则；差异是本插件按 Protect 标志自动判定，而非硬编码字段名。

---

## 4. MCP 工具清单（Tools）

### 4.1 只读类

| 工具 | 说明 | 输出要点 |
|------|------|----------|
| `list_databases` | 列出已打开/解锁的数据库 | 名称、路径、锁定状态 |
| `list_groups` | 分组树（可按库过滤） | 树形结构、UUID |
| `list_entries` | 某分组/全库条目列表 | UUID、标题、组路径、掩码字段清单 |
| `get_entry` | 条目详情 | 全部**非掩码**字段值；掩码字段仅显示 `[protected]` |
| `read_secret` | 读取条目保护字段明文（需审批） | 白名单条目免审批；非白名单走弹窗审批（§6.7）；返回 `{fields: {name: value}}`，审计逐字段记录 |
| `search_entries` | 按标题/URL/备注/标签搜索 | 同 list_entries |
| `get_audit_log` | 查询插件审计日志 | 时间、操作、对象、结果 |

### 4.2 写类（仅元数据，掩码字段不可达）

| 工具 | 说明 | 安全约束 |
|------|------|----------|
| `rename_entry` | 改条目标题 | 标题非保护字段 |
| `update_entry_fields` | 改 URL/备注/自定义字段（非保护） | schema 排除保护字段；请求含保护字段名 → 拒绝 |
| `move_entry` | 条目跨分组移动（重新分类） | 目标分组须存在；默认保留回收站语义 |
| `create_group` / `rename_group` / `delete_group` | 分组管理 | delete_group 须 `confirm=true` 二次确认 |
| `add_tag` / `remove_tag` | 标签管理 | 仅元数据 |
| `create_entry` | 新建条目（可含密钥，免审批） | `fields` 可含保护字段（Agent 传值）；或 `generate_password: {length, charset}` 由插件内生成直接落库（明文不经 Agent 上下文，主推路径，ADR-0001） |
| `backup_database` | 触发变更前快照/手动备份 | 写操作前置自动备份（见 §6.4） |

〔设计〕写操作共性：**先备份后变更**（备份到插件数据目录或 KeePass 回收站语义），变更成功后写审计日志；`delete_group` 等破坏性操作要求显式 `confirm` 参数。
**dry-run 机制（已确认 2026-10-01）**：所有写工具支持 `dry_run=true` 参数（默认 false）。置真时**只计算并返回变更预览**（将重命名 N 个条目、将移动 X→Y 组、将删除组及其 M 个条目等），不落库；破坏性操作（delete_group 等）在 `dry_run=false` 时仍要求 `confirm=true` 二次确认。

---

## 5. MCP 资源清单（Resources）

按 MCP 规范，资源 = 只读数据 URI，供 Agent 直接读取（不进工具参数）：

| URI 模式 | 内容 |
|----------|------|
| `keepass://groups` | 全库分组树（JSON 结构） |
| `keepass://groups/{uuid}/entries` | 某分组下条目列表 |
| `keepass://entries/{uuid}` | 条目详情（同 get_entry 掩码规则） |
| `keepass://entries/{uuid}/fields` | 字段清单（含保护标志，不含明文） |
| `keepass://audit` | 最近审计日志 |

〔设计〕资源与工具共用同一掩码层，保证"能读的都能操作、能操作的都能读"。

---

## 6. 安全模型

### 6.1 传输与绑定
- 仅监听 `127.0.0.1:<端口>`（默认随机端口，插件启动时选定）
- 拒绝非回环来源（DNS 重绑定防护：校验 Host 头为 localhost/127.0.0.1）

### 6.2 鉴权
- 插件启动生成随机 token，写入 `%APPDATA%` 下**仅当前用户可读**的配置文件（如 `keepass-mcp/token.txt`，0600 权限）
- Agent 连接时在 Header 携带 `Authorization: Bearer <token>`
- 支持 `--token <path>` 或环境变量注入（给 moirai 等自建 Agent 用）

### 6.3 锁库联动
- 监听 KeePass 的锁/解锁事件（`FileLocked` / `FileOpened`）
- 锁定时 MCP 返回 `database_locked` 状态，**所有读写工具拒绝**
- 解锁后自动恢复

### 6.4 审计与回滚
- 每次写操作记录审计行：时间、工具、参数摘要、对象 UUID、结果
- 变更前自动备份：把涉及条目/分组的当前状态序列化为 JSON（**不含保护字段明文**，只备份结构+非掩码值），存插件数据目录
- 提供 `restore_backup <id>` 工具（仅插件管理员，需二次确认）

### 6.5 dry-run 预览层（已确认 2026-10-01）
- 写工具 `dry_run=true` 时返回结构化变更预览（对象、动作、旧值→新值、影响条目数），**不落库、不写备份**
- 预览结果与真实执行共用同一变更计算函数 → 预览所见即执行所得（防"预览一套、执行一套"）
- 建议 Agent 工作流：写操作先 `dry_run=true` → 人工/Agent 检查预览 → `dry_run=false` 执行

### 6.6 掩码不可写的强制层
- **协议层**：常规工具 schema 里不出现保护字段参数；仅 `create_entry` / `read_secret` 例外
- **实现层**：`update_entry_fields` 对请求中的保护字段名：未审批 → 拒绝（防绕过）；审批通过 → 允许（§6.7）
- **数据层**：读出口统一走掩码序列化器，杜绝遗漏路径

### 6.7 密钥访问审批（2026-10-01 访谈定稿，ADR-0001/0002）
- **模型**：创建写密钥免审批；读取明文（`read_secret`）与修改已有保护字段需审批
- **两级审批**：
  1. **密钥访问白名单**（按条目 UUID 配置，选项页可增删）：白名单内条目免审批直接访问，全程审计
  2. **KeePass UI 弹窗**：非白名单条目在 KeePass 主窗口弹确认框（显示库/条目/字段/操作类型），默认 60s 超时按拒绝；拒绝/超时均不返回明文
- **弹窗线程**：经 `host.MainWindow` UI 线程 marshal（HANDOFF §2 线程模型）
- **明文去向**：审批通过后明文仅出现在该次 `read_secret` 返回中，会进入 Agent 上下文（用户已接受）；审计逐字段记录"何时、谁、读/改了哪个条目的哪个字段"
- **审计**：所有审批事件（允许/拒绝/超时）与密钥访问均写审计日志；审计与备份永不含明文

---

## 7. 技术选型与兼容性

| 项 | 选型 | 说明 |
|----|------|------|
| 插件宿主 | KeePass 2.x 插件 API（`KeePass.Plugins.Plugin`） | 官方插件体系，可访问 KeePassLib |
| 运行时 | .NET Framework 4.8（KeePass 2.x 当前目标） | 兼容性前提 |
| MCP 实现 | 官方 C# SDK（ModelContextProtocol **2.2.0**，netstandard2.0 目标）〔P0-a 已验证 2026-10-01〕 | net48 加载运行成功；传输用 StreamServerTransport + HttpListener 适配 |
| HTTP 宿主 | Kestrel（若 SDK 支持）或 HttpListener（.NET Framework 原生，最稳） | 〔待验证〕 |
| 数据访问 | KeePassLib（PwDatabase/PwGroup/PwEntry/ProtectedStringDictionary） | 插件内直接引用 |
| 掩码判定 | `PwEntry.Strings` 中 `ProtectedString.IsProtected` | 原生 API |
| Agent 连接形态（已确认） | **标准 MCP 客户端配置**：客户端配置文件声明 `type: http` + `url: http://127.0.0.1:<端口>` + `headers: {Authorization: Bearer <token>}`；token 由插件生成后供用户粘贴进配置 | 〔设计〕✓已决 |

---

## 8. 风险与待验证

1. **MCP C# SDK 在 .NET Framework 4.8 的可用性** → **已解决（P0-a）**：ModelContextProtocol 2.2.0 带 netstandard2.0 目标，net48 加载运行正常；P1 需验证 StreamServerTransport + HttpListener 的接线
2. **插件与 KeePass 主程序线程模型**：MCP HTTP 服务在后台线程跑，操作 KeePassLib 需注意 UI 线程同步（KeePass 大量 API 假设在 UI 线程）〔待验证〕——弹窗审批（P3）前必须验证
3. **多库支持**：KeePass 支持多文档，工具需明确 `database_id` 参数〔设计〕
4. **KDBX 4.1 自定义数据/标签**：标签与公共自定义数据的读写 API 需核对〔待验证〕
5. **Agent 误操作防护**：批量移动/重命名仍可能造成用户不期望的变更 → 备份+审计+（可选）dry-run 预览参数〔设计〕
6. **与 KeePassRPC 端口冲突/生态并存**：默认端口随机可避免冲突〔设计〕
7. **KeePass 2.60 插件加载门槛**（P0-b2 新发现）：插件 DLL 的 ProductName 必须为 "KeePass Plugin"，否则静默跳过；PluginCompatibility 为自动缓存非白名单〔已解决，见 HANDOFF §9.2〕

---

## 9. 与生态既有方案对比

| 方案 | 形态 | 协议 | 掩码 | 与本方案差异 |
|------|------|------|------|--------------|
| KeePassRPC | KeePass 插件 | JSON-RPC（浏览器扩展） | 保护字段不暴露 | 面向浏览器扩展，非 MCP |
| keepassxc-browser 协议 + MCP 适配 | KeePassXC 侧 | keepassxc-browser + MCP 适配层 | 依赖实现 | 需 KeePassXC 而非 KeePass，间接适配 |
| **本方案** | KeePass 原生插件 | **原生 MCP**（Streamable HTTP） | **Protect 标志自动掩码** | 原生集成、掩码规则自动、本机 Agent 直连 |

〔参考〕差异化价值：**KeePass 进程内原生 MCP + 按 Protect 标志的自动掩码**，避免 KeePassXC 引入和协议转换层。

---

## 10. 里程碑建议（若推进）

1. **P0 验证**：MCP SDK/自研协议在 .NET Framework 4.8 跑通最小 echo 服务；KeePass 插件加载 MCP 服务成功
2. **P1 只读**：list/search/get + 资源 URI + 掩码层
3. **P2 写操作**：重命名/改字段/移动/分组管理 + 备份审计 + 锁库联动
4. **P3 打磨**：多库、标签、配置 UI（KeePass 选项页）、dry-run、restore

---

## 11. 待用户决策

- [x] ~~掩码默认清单~~ **已决（2026-10-01）**：仅按 Protect 标志；UserName 不加入默认掩码（可见可操作），配置仍可追加
- [x] ~~写操作 dry-run~~ **已决（2026-10-01）**：需要 dry-run 预览（§4.2 / §6.5），预览与执行共用同一变更计算函数
- [x] ~~Agent 连接方式~~ **已决（2026-10-01）**：标准 MCP 客户端配置（§7 表格末行），token 由插件生成供用户配置
- [x] ~~密钥边界~~ **已决（2026-10-01 第二轮访谈）**：创建可写密钥（免审批）、读改需审批（白名单+弹窗）、明文永不进入读出口/审计/备份（ADR-0001/0002）
- [x] ~~客户端集~~ **已决（2026-10-01 第二轮访谈）**：通用标准 MCP 客户端为契约；P1 验收用 moirai + Claude Desktop
- [x] ~~写自主权~~ **已决（2026-10-01 第二轮访谈）**：白名单自主 + 全局"写需确认"开关
- [x] ~~落盘~~ **已决（2026-10-01 第二轮访谈）**：可配置，默认手动保存

## 12. 下一步（P1 只读）

P0 已全部验证通过（2026-10-01）：SDK 2.2.0 net48 加载 ✓ / HttpListener 非管理员随机端口绑定 ✓ / 插件在便携版 2.60.0 加载 ✓ / 掩码判定 API ✓。进入 **P1 只读**（按 HANDOFF §13）：
1. 插件骨架内启动 MCP HTTP 服务（StreamServerTransport + HttpListener 适配），`initialize`/`ping` 跑通
2. token 生成/持久化/校验（%APPDATA%\KeePassMCP\token）
3. 锁定联动 + list_databases/list_groups/list_entries/get_entry/search_entries + 资源 URI
4. MaskedEntrySerializer 掩码序列化器（P0-c 已确认 API 形态）
