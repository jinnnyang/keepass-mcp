# 0003 授权模型：库内 `_mcp_*` 字段体系（取代弹窗审批与标签）

- Status: accepted (2026-10-03)，2026-10-03 评审修复后语义定稿（Amended）
- Supersedes: 0002（弹窗审批 + 白名单 + 标签组合废止）
- 评审：`docs/review/0003-design-review-2026-10-03.md`（三位专家分域评审，无阻断级问题；本版已吸收 H1/H2/H3/H5 与字段增补建议）

## 决策

授权模型从"config.json 白名单 + 标签 + KeePass UI 弹窗审批"重构为**纯库内 `_mcp_*` 字符串字段体系**，字段即授权，判定不依赖任何外部状态。

### 配置条目（`_mcp_config=1` 标记，库内任意条目，多条目并集生效）

| 字段 | 默认值 | 语义 |
|---|---|---|
| `_mcp_server` | `1` | 启用监听；**全部生效配置条目为 `0` 时服务停止且不启动**（2026-10-03 定稿：`_mcp_server=0` 即停用，字段名与语义必须一致） |
| `_mcp_listening` | `127.0.0.1:6789` | 监听地址端口；`;` 分隔多地址；端口占用自动 +1 重试 |
| `_mcp_token` | 随机 32B hex | 鉴权 token 并集（`;` 分隔），任一匹配即放行；并集为空 → 取消鉴权（回环限定下开放）。**2026-10-03 起为 Password 的同步镜像**（双字段绑定：Password 为权威输入框，`_mcp_token` 保持与其一致，见下方"token 双字段绑定"） |
| `_mcp_scope_self` | `0` | `1` = 该配置条目不并入全局 token/监听/default 聚合（保留为所属库按库路由预留；防共享库配置漂移） |
| `_mcp_read_default` | `1` | 默认允许读未保护字段 |
| `_mcp_read_protected_default` | `0` | 默认拒绝读保护字段 |
| `_mcp_write_default` | `1` | 默认允许写未保护字段 |
| `_mcp_write_protected_default` | `0` | 默认拒绝写保护字段 |
| `_mcp_move_default` | `1` | 默认允许移动/删除条目 |
| `_mcp_list_default` | `1` | 默认允许条目出现在客户端查询列表（0 = 全局隐身） |
| `_mcp_audit_default` | `0` | `1` 才允许客户端读 get_audit_log（2026-10-03 增补，评审 M3） |
| `_mcp_backup_default` | `0` | `1` 才允许触发 backup_database（2026-10-03 增补，评审 M6） |
| `_mcp_save_default` | `0` | `1` 才允许 save_database 显式落盘（2026-10-03 增补，P6-3l；保存前生成整库非保护字段快照供回滚） |

库内无任何配置条目时，插件自动创建 `MCPServerConfiguration` 条目并写入默认参数（监听 `127.0.0.1:6789`、随机 token、上表默认值）。

### token 双字段绑定（2026-10-03 增补）

用户在前端（KeePass 条目编辑界面的 **Password 输入框**）直接查看/修改鉴权 token：

- **读取（`ReadToken`）**：Password 非空 → 用之（用户编辑 Password 即生效；Password 为 KeePass 原生保护字段，消除"忘勾保护"风险）；Password 为空 → 回退 `_mcp_token`（兼容绑定前自动创建的旧条目）
- **同步（`SyncTokenFields`，P6-3m 双向版）**：进程内快照记录每配置条目上次同步的 `(Password, _mcp_token)`，保存/启动时对比判定——仅 Password 变 → 覆盖 `_mcp_token`；仅 `_mcp_token` 变 → 覆盖 Password（Advanced 页修改同样生效）；两字段同时变 → 冲突 Password 优先（记警告）；`_mcp_token` 被清空 → Password 填回；Password 为空 → 不动（保留回退路径）。触发点：**FileSavingPre**（保存前同步、随本次落盘）+ **Start**（重启后首次见 → Password 权威一致化修复）+ RefreshToken 兜底；同步后置所属库 `db.Modified`。快照仅存内存，重启即失效（退回 Password 权威一致化语义）
- **创建（`EnsureDefaultConfig`）**：Password 与 `_mcp_token` 同时写入相同随机值
- 语义声明：修改 token 请编辑 Password 输入框；在 Advanced 页直接改 `_mcp_token` 会在下次同步时被 Password 覆盖

### 普通条目权限字段（显式，优先级高于 default）

`_mcp_read` / `_mcp_read_protected` / `_mcp_write` / `_mcp_write_protected` / `_mcp_move` / `_mcp_list`——值 `1`=允许、`0`=显式拒绝；`_mcp_list=0` 条目对客户端隐身（不出现在列表/枚举结果）。

### 判定优先级

1. **条目显式字段**（六项权限）→
2. **生效配置条目 default 布尔最严聚合**（2026-10-03 定稿，评审 H5）：遍历全部生效配置条目（scope_self=1 排除），任一显式值 `0` → 拒绝；全部显式值 `1` → 允许；全部缺失 → 硬编码。**顺序无关**；Audit/Backup 仅走 default 链（无条目级字段）→
3. **硬编码默认**（仅 move/read/write 未保护允许；保护字段与审计/快照一律拒绝）。

### 移除

- 审批弹窗（UiApprovalProvider / ApprovalForm / confirm_writes）——KeePass 删除语义为移回收站、可回滚，且客户端无永久删除能力，弹窗阻塞收益 < 成本
- 白名单 `KeePassMCP-Whitelist` / 黑名单 `KeePassMCP-Blacklist` 标签
- config.json `secret_whitelist`（config.json 仅保留 `extraMaskedFields`）

## 安全护栏

1. 所有 `_mcp_` 前缀字段读出口一律掩码（含 token，不依赖 Protected 标志——防用户忘勾保护导致明文出口）
2. 配置条目整条目掩码（`protected_field_names=["*"]`）与备份排除规则保留
3. 无鉴权态（token 并集为空）仅限本机回环监听；默认模板保证有 token，无鉴权须用户显式清空
4. 删除/移动全审计；客户端无清空回收站能力（KeePass 回收站为唯一回滚通道）
5. **restore_backup 双闸门**（2026-10-03 修复，评审 H1/H2）：backupId 白名单正则（`^\d{17}_[a-z0-9_]+_[0-9a-f]{8}$`）拒绝路径遍历；恢复循环内逐条目 Write 权限判定，`_mcp_write=0`（或默认拒绝）条目标记 restore_skip 不回写
6. **`_mcp_server=0` 真停监听**（2026-10-03 修复，评审 H3）：Start/RefreshToken 均按 ResolveServerEnabled 判定

## 后果

- 授权完全随库走（备份/迁移/多机同步天然一致），无外部配置漂移
- 配置即代码：用户用 KeePass 原生 UI 或 P7 tab 直接编辑字段
- 判定是纯函数（条目字段 → default 最严聚合 → 硬编码），可完整探针化（217 项断言全绿）
- 0002 失效，但审计日志格式与 60s 超时语义移除前已运行业务不受影响
- **已知限制**（评审 M5）：`_mcp_scope_self` 仅防"自带 scope_self=1 的配置条目并入全局集"；攻击者在共享库放置无 scope_self 标记的 `_mcp_config=1` 条目仍会并入 token/监听集——多库会话需审计打开库中的配置条目，或后续按库路由（已推迟）
