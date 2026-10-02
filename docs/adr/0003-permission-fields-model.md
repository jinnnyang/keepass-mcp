# 0003 授权模型：库内 `_mcp_*` 字段体系（取代弹窗审批与标签）

- Status: accepted (2026-10-03)
- Supersedes: 0002（弹窗审批 + 白名单 + 标签组合废止）

## 决策

授权模型从"config.json 白名单 + 标签 + KeePass UI 弹窗审批"重构为**纯库内 `_mcp_*` 字符串字段体系**，字段即授权，判定不依赖任何外部状态。

### 配置条目（`_mcp_config=1` 标记，库内任意条目，多条目并集生效）

| 字段 | 默认值 | 语义 |
|---|---|---|
| `_mcp_server` | `1` | 启用监听 |
| `_mcp_listening` | `127.0.0.1:6789` | 监听地址端口；`;` 分隔多地址；端口占用自动 +1 重试 |
| `_mcp_token` | 随机 32B hex | 鉴权 token 并集（`;` 分隔），任一匹配即放行；并集为空 → 取消鉴权（回环限定下开放） |
| `_mcp_read_default` | `1` | 默认允许读未保护字段 |
| `_mcp_read_protected_default` | `0` | 默认拒绝读保护字段 |
| `_mcp_write_default` | `1` | 默认允许写未保护字段 |
| `_mcp_write_protected_default` | `0` | 默认拒绝写保护字段 |
| `_mcp_move_default` | `1` | 默认允许移动/删除条目 |
| `_mcp_list_default` | `1` | 默认允许条目出现在客户端查询列表（0 = 全局隐身） |

库内无任何配置条目时，插件自动创建 `MCPServerConfiguration` 条目并写入默认参数（监听 `127.0.0.1:6789`、随机 token、上表默认值）。

### 普通条目权限字段（显式，优先级高于 default）

`_mcp_read` / `_mcp_read_protected` / `_mcp_write` / `_mcp_write_protected` / `_mcp_move` / `_mcp_list`——值 `1`=允许、`0`=显式拒绝；`_mcp_list=0` 条目对客户端隐身（不出现在列表/枚举结果）。

### 判定优先级

条目显式字段 → 配置条目 default 字段 → 硬编码默认（仅 move/read/write 未保护允许；保护字段一律拒绝）。

### 移除

- 审批弹窗（UiApprovalProvider / ApprovalForm / confirm_writes）——KeePass 删除语义为移回收站、可回滚，且客户端无永久删除能力，弹窗阻塞收益 < 成本
- 白名单 `KeePassMCP-Whitelist` / 黑名单 `KeePassMCP-Blacklist` 标签
- config.json `secret_whitelist`（config.json 仅保留 `extraMaskedFields`）

## 安全护栏

1. 所有 `_mcp_` 前缀字段读出口一律掩码（含 token，不依赖 Protected 标志——防用户忘勾保护导致明文出口）
2. 配置条目整条目掩码（`protected_field_names=["*"]`）与备份排除规则保留
3. 无鉴权态（token 并集为空）仅限本机回环监听；默认模板保证有 token，无鉴权须用户显式清空
4. 删除/移动全审计；客户端无清空回收站能力（KeePass 回收站为唯一回滚通道）

## 后果

- 授权完全随库走（备份/迁移/多机同步天然一致），无外部配置漂移
- 配置即代码：用户用 KeePass 原生 UI 或 P7 tab 直接编辑字段
- 判定是纯函数（条目字段 → default → 硬编码），可完整探针化
- 0002 失效，但审计日志格式与 60s 超时语义移除前已运行业务不受影响
