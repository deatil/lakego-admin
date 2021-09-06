package admin

import (
    "encoding/json"

    "lakego-admin/lakego/collection"

    "lakego-admin/admin/model"
)

// 账号所属分组
func GetGroups(adminid string) []map[string]interface{} {
    var info = model.Admin{}

    groups := make([]map[string]interface{}, 0)

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
    adminData := map[string]interface{}{}
    json.Unmarshal(data, &adminData)

    // 格式化分组
    adminGroups := adminData["Groups"].([]map[string]interface{})
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
func GetRules(groupids []string) []map[string]interface{} {
    list := make([]map[string]interface{}, 0)

    // 附件模型
    err := model.NewAuthRule().
        Preload("RuleAccesses", "group_id in (?)", groupids).
        Select([]string{
            "id", "parentid",
            "title",
            "url", "method",
            "description",
        }).
        Where("status = ?", 1).
        Order("listorder ASC").
        Find(&list).
        Error
    if err != nil {
        return nil
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

