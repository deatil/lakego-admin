package authrule

import (
    "github.com/deatil/lakego-doak/lakego/tree"
    "github.com/deatil/lakego-doak/lakego/collection"

    "github.com/deatil/lakego-doak/admin/model"
)

// 全部权限
func GetAllRule() []map[string]interface{} {
    list := make([]map[string]interface{}, 0)

    // 附件模型
    err := model.NewAuthRule().
        Select([]string{
            "id", "parentid",
            "title",
            "url", "method",
            "slug", "description",
        }).
        Where("status = ?", 1).
        Order("listorder ASC").
        Order("add_time ASC").
        Find(&list).
        Error
    if err != nil {
        return make([]map[string]interface{}, 0)
    }

    return list
}
// 获取 Children
func GetChildren(ruleid string) []map[string]interface{} {
    list := make([]map[string]interface{}, 0)

    // 附件模型
    err := model.NewAuthRule().
        Where("status = ?", 1).
        Order("listorder ASC").
        Order("add_time ASC").
        Find(&list).
        Error
    if err != nil {
        return make([]map[string]interface{}, 0)
    }

    childrenList := tree.New().
        WithData(list).
        GetListChildren(ruleid, "asc")

    return childrenList
}

// 获取 Children
func GetChildrenFromRuleids(ruleids []string) []map[string]interface{} {
    data := make([]map[string]interface{}, 0)
    for _, id := range ruleids {
        children := GetChildren(id)
        data = append(data, children...)
    }

    list := collection.Collect(data).
        Collapse().
        ToMapArray()

    return list
}

// 获取 ChildrenIds
func GetChildrenIds(ruleid string) []string {
    list := GetChildren(ruleid)

    if len(list) == 0 {
        return []string{}
    }

    ids := collection.Collect(list).
        Pluck("id").
        ToStringArray()

    return ids
}

// 获取 ChildrenIds
func GetChildrenIdsFromRuleids(ruleids []string) []string {
    list := GetChildrenFromRuleids(ruleids)

    if len(list) == 0 {
        return []string{}
    }

    ids := collection.Collect(list).
        Pluck("id").
        ToStringArray()

    return ids
}

// 获取 Children
func GetChildrenFromData(data []map[string]interface{}, ruleid string) []map[string]interface{} {
    childrenList := tree.New().
        WithData(data).
        GetListChildren(ruleid, "asc")

    return childrenList
}

// 获取 ChildrenIds
func GetChildrenIdsFromData(data []map[string]interface{}, ruleid string) []string {
    list := GetChildrenFromData(data, ruleid)

    if len(list) == 0 {
        return []string{}
    }

    ids := collection.Collect(list).
        Pluck("id").
        ToStringArray()

    return ids
}


