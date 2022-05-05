package admin

import (
    "encoding/json"

    "github.com/deatil/lakego-doak/lakego/collection"

    "github.com/deatil/lakego-doak-admin/admin/model"
)

// 账号所属分组
func GetGroups(adminid string) []map[string]any {
    var info = model.Admin{}

    groups := make([]map[string]any, 0)

    // 附件模型
    err := model.NewAdmin().
        Where("id = ?", adminid).
        Preload("Groups").
        First(&info).
        Error
    if err != nil {
        return groups
    }

    // 结构体转map
    data, _ := json.Marshal(&info)
    adminData := map[string]any{}
    json.Unmarshal(data, &adminData)

    // 格式化分组
    adminGroups := adminData["Groups"].([]map[string]any)
    groups = collection.Collect(adminGroups).
        Select("id", "title", "description").
        ToMapArray()

    return groups
}

// 当前账号所属分组
func GetGroupIds(adminid string) []string {
    // 格式化分组
    adminGroups := GetGroups(adminid)
    ids := collection.
        Collect(adminGroups).
        Pluck("id").
        ToStringArray()

    return ids
}

// 权限
func GetRules(groupids []string) []map[string]any {
    list := make([]map[string]any, 0)

    // 附件模型
    err := model.NewAuthRule().
        Preload("RuleAccesses", "group_id in (?)", groupids).
        Select([]string{
            "id", "parentid",
            "title",
            "url", "method",
            "slug", "description",
        }).
        Where("status = ?", 1).
        Order("listorder ASC").
        Find(&list).
        Error
    if err != nil {
        return make([]map[string]any, 0)
    }

    return list
}

// 权限ID列表
func GetRuleids(groupids []string) []string {
    // 格式化分组
    list := GetRules(groupids)
    ids := collection.
        Collect(list).
        Pluck("id").
        ToStringArray()

    return ids
}

