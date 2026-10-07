# KeePassMCP

KeePassMCP 是一个 KeePass 2.x 原生插件，向本机 MCP 客户端暴露受控的密码库访问能力：Agent 可整理库结构与元数据、创建带密钥的条目；读取/修改已有密钥需审批；保护字段明文除审批通过的单次返回外永不离开 KeePass。

## Language

**库 (Database)**:
一个已打开并解锁的 KeePass 密码库（PwDatabase）。KeePass 可同时打开多个库，工具以 `database_id` 区分。
_Avoid_: 数据库文件、vault

**条目 (Entry)**:
库中的一条凭证记录（PwEntry）：标题、用户名、URL、备注、标签、自定义字段与保护字段。
_Avoid_: record、item

**分组 (Group)**:
条目的层级容器（PwGroup），构成库的分组树；条目可跨分组移动（重新分类）。

**保护字段 (Protected Field)**:
KDBX 中 `Protect="True"` 或名为 Password 的字段。不变量：除审批通过的单次读取外，其明文绝不离开 KeePass；任何读出口、审计、备份均不含明文。
_Avoid_: secret、敏感字段（"敏感字段"指附加掩码清单，是配置概念）

**掩码 (Masking)**:
对保护字段的统一输出处理：一律输出 `[protected]` 占位符并列出字段名清单，绝不返回明文。

**密钥写入 (Secret Write)**:
创建新条目时把保护字段值写入库中的能力（Agent 传值或插件内生成），免审批；是唯一免审批的密钥写入路径。
_Avoid_: set password、save secret

**密钥访问审批 (Secret Access Approval)**:
读取已有保护字段明文（`read_secret`）或修改已有保护字段前的人工授权。两级：白名单条目免审批（全程审计）；非白名单条目弹 KeePass 确认框，默认超时拒绝。

**密钥访问白名单 (Secret Access Whitelist)**:
插件配置中按条目 UUID 列出的、免审批访问保护字段的条目集合。区别于"写操作自主度"。

**写操作自主度 (Write Autonomy)**:
Agent 执行元数据写操作（重命名/改非保护字段/移动/分组/标签）的权限分级：常规操作自主执行，破坏性/批量操作需 `confirm=true`；可被全局"写需确认"开关收紧。
_Avoid_: permission、权限（权限指 token/ACL，属鉴权概念）

**dry-run 预览**:
写操作执行前计算并返回的变更预览，不落库、不写备份、不写审计；预览与执行共用同一变更计算函数。

**审计日志 (Audit Log)**:
`%APPDATA%\KeePassMCP\audit.jsonl` 的 JSONL 记录；覆盖全部写操作、密钥访问与审批事件；永不包含保护字段明文。
_Avoid_: log

**客户端技能 (Client Skill)**:
豆包/Agent 侧配套的 KeePassMCP 使用技能，归档于 [docs/keepass-skill/](docs/keepass-skill/)：`SKILL.md`（连接、安全铁律、标准工作流）+ `references/tools.md`（18 工具全参速查与错误码）。
