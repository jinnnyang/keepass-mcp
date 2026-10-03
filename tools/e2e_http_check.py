#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KeePassMCP 端到端 HTTP 实测（真实库，掩码化输出）。

用法: python tools/e2e_http_check.py [--url http://127.0.0.1:6789/mcp]
前置: KeePass 已启动且库已解锁。
MCP 信封: tools/call 结果在 result.content[0].text（JSON 字符串）+ result.isError。
所有输出对条目标题打码；核心断言是"响应中不含明文 token"。
"""
import json
import os
import sys
import urllib.error
import urllib.request

URL = "http://127.0.0.1:6789/mcp"


def load_token():
    d = os.environ.get("KeePassMCP_DATA_DIR") or os.path.join(
        os.environ.get("APPDATA", ""), "KeePassMCP")
    with open(os.path.join(d, "connection.json"), "r", encoding="utf-8") as f:
        cfg = json.load(f)
    auth = cfg["mcp_client"]["headers"]["Authorization"]
    assert auth.startswith("Bearer "), "connection.json 无 Bearer 头"
    return auth[len("Bearer "):], cfg


def call(method, params=None, token=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    req = urllib.request.Request(
        URL, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def call_tool(name, args, token):
    """标准信封解析：返回 (ok, data_dict, error_code)。"""
    st, txt = call("tools/call", {"name": name, "arguments": args}, token=token)
    if st != 200:
        return False, {}, "http_%s" % st
    j = json.loads(txt)
    res = j.get("result") or {}
    if res.get("isError"):
        try:
            err = json.loads(res["content"][0]["text"])
        except Exception:
            return False, {}, "parse_error"
        return False, err.get("error", {}).get("code"), err
    try:
        data = json.loads(res["content"][0]["text"])
    except Exception:
        data = res
    return bool(data.get("ok")), data.get("data", {}), None


def mask_title(s):
    return s[:2] + "…" + s[-1:] if len(s) > 6 else "…"


PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("[PASS] " if ok else "[FAIL] ") + name + ("  | " + detail if detail else ""))


def as_list(data, key):
    return data if isinstance(data, list) else (data.get(key) or [])


def main():
    global URL
    if "--url" in sys.argv:
        URL = sys.argv[sys.argv.index("--url") + 1]
    token, cfg = load_token()
    print("== 服务: %s ==" % cfg.get("url", URL))

    # 0) 鉴权负路径
    st, _ = call("initialize", {})
    check("鉴权: 无 token → 401", st == 401, "status=%s" % st)
    st, _ = call("initialize", {}, token="deadbeef" * 8)
    check("鉴权: 错误 token → 401", st == 401, "status=%s" % st)

    # 1) initialize + tools/list
    st, txt = call("initialize", {}, token=token)
    check("initialize → 200", st == 200, "status=%s" % st)
    st, txt = call("tools/list", {}, token=token)
    tools = json.loads(txt).get("result", {}).get("tools", [])
    check("tools/list 工具数 ≥ 15", len(tools) >= 15, "count=%s" % len(tools))

    # 2) list_databases → database_id（库路径）
    ok, data, err = call_tool("list_databases", {}, token)
    check("list_databases → ok", ok, "err=%s" % err)
    dbs = as_list(data, "databases")
    check("list_databases 非空", len(dbs) > 0, "count=%s" % len(dbs))
    if not dbs:
        print("  [原始]" + json.dumps(data, ensure_ascii=False)[:400])
        return 1
    db_id = dbs[0].get("id") or dbs[0].get("path") or dbs[0].get("name")
    print("   [库] " + mask_title(str(db_id)) + " | open=%s" % dbs[0].get("open"))

    # 3) list_entries（数量 + 标题打码；断言响应不含明文 token）
    ok, data, err = call_tool("list_entries", {"database_id": db_id, "limit": 2000}, token)
    check("list_entries → ok", ok, "err=%s" % err)
    entries = as_list(data, "entries")
    check("list_entries 非空", len(entries) > 0, "count=%s" % len(entries))
    if entries:
        sample = entries[0]
        print("   [样本] " + mask_title(str(sample.get("title", "")))
              + " | masked=%s" % sample.get("masked_fields"))
    st, txt = call("tools/call", {"name": "list_entries", "arguments": {"database_id": db_id, "limit": 2000}}, token=token)
    check("list_entries 响应不含明文 token", token not in txt)

    # 4) 配置条目：search 定位（整条目掩码 → 标题显示 [protected]，
    #    按标题/字段匹配不到，故用 search_entries 按标题词命中）
    ok, data, err = call_tool("search_entries", {"database_id": db_id, "query": "MCPServerConfiguration"}, token)
    hits = as_list(data, "entries") or as_list(data, "results")
    cfg_uuid = hits[0].get("uuid") if hits else None
    check("找到配置条目（search）", cfg_uuid is not None)
    if cfg_uuid:
        ok, data, err = call_tool("get_entry", {"database_id": db_id, "entry_uuid": cfg_uuid}, token)
        check("get_entry 配置条目 → ok", ok, "err=%s" % err)
        s = json.dumps(data, ensure_ascii=False)
        check("配置条目整条目掩码（无 token 明文）", token not in s)
        check("配置条目 protected_field_names=[*]", (data.get("protected_field_names") or []) == ["*"])
        # 铁律：配置条目禁止 read_secret（token_entry_protected）
        ok, code, err = call_tool("read_secret", {"database_id": db_id, "entry_uuid": cfg_uuid}, token)
        check("read_secret 配置条目 → token_entry_protected",
              not ok and code == "token_entry_protected", "code=%s" % code)

    # 5) get_entry 普通条目 → 掩码
    norm_uuid = None
    for e in entries:
        if (e.get("custom_fields") or {}).get("_mcp_config") != "1" and e.get("title") != "MCPServerConfiguration":
            norm_uuid = e.get("uuid"); break
    check("找到普通条目", norm_uuid is not None)
    if norm_uuid:
        ok, data, err = call_tool("get_entry", {"database_id": db_id, "entry_uuid": norm_uuid}, token)
        check("get_entry 普通条目 → ok", ok, "err=%s" % err)
        print("   [样本] " + mask_title(str(data.get("title", ""))) + " | masked=%s" % data.get("masked_fields"))

    # 6) read_secret 普通条目 → 默认拒绝（_mcp_read_protected=0）
    if norm_uuid:
        ok, code, err = call_tool("read_secret", {"database_id": db_id, "entry_uuid": norm_uuid}, token)
        check("read_secret 默认拒绝（permission_denied）", not ok and code == "permission_denied",
              "code=%s" % code)

    # 7) dry-run 写：create_entry 预览（不落盘）
    ok, data, err = call_tool("create_entry", {
        "database_id": db_id, "title": "E2E dry-run 验证条目",
        "fields": {"UserName": "e2e-check"}, "dry_run": True}, token)
    check("create_entry dry-run → ok 且不落盘", ok and data.get("dry_run") is True,
          "err=%s" % err)

    # 8) 审计默认拒绝（_mcp_audit_default=0）
    ok, code, err = call_tool("get_audit_log", {}, token)
    check("get_audit_log 默认拒绝（permission_denied）", not ok and code == "permission_denied",
          "code=%s" % code)

    # 9) save_database（P6-3l）：dry-run 必测；真实保存需 E2E_SAVE_REAL=1 才执行（回归默认零副作用）
    ok, data, err = call_tool("save_database", {"database_id": db_id, "dry_run": True}, token)
    check("save_database dry-run → 预览且不落盘",
          ok and data.get("dry_run") is True and data.get("snapshot_planned") is True,
          "err=%s" % err)
    if os.environ.get("E2E_SAVE_REAL") == "1":
        ok, data, err = call_tool("save_database", {"database_id": db_id}, token)
        check("save_database 真实保存 → saved + backup_id",
              ok and data.get("saved") is True and bool(data.get("backup_id")), "err=%s" % err)

    # 9) 全库无配置条目时 default 拒绝 → 已验证；此处收尾
    print("\n=== 结果：%d 通过 / %d 失败 ===" % (len(PASS), len(FAIL)))
    if FAIL:
        print("失败项: " + ", ".join(FAIL))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
