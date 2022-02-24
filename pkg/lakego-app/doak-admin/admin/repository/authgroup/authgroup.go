package authgroup

import (
    "github.com/deatil/lakego-doak/lakego/tree"
    "github.com/deatil/lakego-doak/lakego/collection"

    "github.com/deatil/lakego-doak-admin/admin/model"
)

// 获取 Children
func GetChildren(groupid string) []map[string]interface{} {
    list := make([]map[string]interface{}, 0)

    // 附件模型
    err := model.NewAuthGroup().
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
        GetListChildren(groupid, "asc")

    return childrenList
}

// 获取 Children
func GetChildrenFromGroupids(groupids []string) []map[string]interface{} {
    data := make([]map[string]interface{}, 0)
    for _, id := range groupids {
        children := GetChildren(id)
        data = append(data, children...)
    }

    return data
}

// 获取 ChildrenIds
func GetChildrenIds(groupid string) []string {
    // 格式化分组
    list := GetChildren(groupid)

    if len(list) == 0 {
        return []string{}
    }

    ids := collection.Collect(list).
        Pluck("id").
        ToStringArray()

    return ids
}

// 获取 ChildrenIds
func GetChildrenIdsFromGroupids(groupids []string) []string {
    // 格式化分组
    list := GetChildrenFromGroupids(groupids)

    if len(list) == 0 {
        return []string{}
    }

    ids := collection.Collect(list).
        Pluck("id").
        ToStringArray()

    return ids
}

// 获取 Children
func GetChildrenFromData(data []map[string]interface{}, groupid string) []map[string]interface{} {
    childrenList := tree.New().
        WithData(data).
        GetListChildren(groupid, "asc")

    return childrenList
}

// 获取 ChildrenIds
func GetChildrenIdsFromData(data []map[string]interface{}, groupid string) []string {
    list := GetChildrenFromData(data, groupid)

    if len(list) == 0 {
        return []string{}
    }

    ids := collection.Collect(list).
        Pluck("id").
        ToStringArray()

    return ids
}

