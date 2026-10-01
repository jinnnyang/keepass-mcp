using System.Collections.Generic;

namespace KeePassMCP.Core
{
    // JSON 键名与 HANDOFF §8 线协议一致（小写/下划线），直接用属性名匹配。
    // 受保护字段值一律以 "[protected]" 占位，明文永不进入 DTO。

    public sealed class DatabaseDto
    {
        public string id { get; set; }
        public string name { get; set; }
        public string path { get; set; }
        public bool locked { get; set; }
        public int group_count { get; set; }
        public int entry_count { get; set; }
    }

    public sealed class GroupDto
    {
        public string uuid { get; set; }
        public string name { get; set; }
        public string parent_uuid { get; set; }
        public int entry_count { get; set; }
        public List<GroupDto> child_groups { get; set; }
    }

    /// <summary>列表/搜索用的条目摘要（不含受保护字段值与 notes）。</summary>
    public sealed class EntrySummaryDto
    {
        public string uuid { get; set; }
        public string title { get; set; }
        public string username { get; set; }
        public string group_path { get; set; }
        public List<string> tags { get; set; }
        public List<string> protected_field_names { get; set; }
    }

    /// <summary>get_entry 完整条目 DTO。</summary>
    public sealed class EntryDto
    {
        public string uuid { get; set; }
        public string title { get; set; }
        public string username { get; set; }
        public string url { get; set; }
        public string notes { get; set; }
        public List<string> tags { get; set; }
        public string group_path { get; set; }
        public Dictionary<string, string> custom_fields { get; set; }
        public List<string> protected_field_names { get; set; }
        public Dictionary<string, string> protected_fields { get; set; }
        public string created { get; set; }
        public string modified { get; set; }
    }
}
