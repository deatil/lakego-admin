package authgroup

import (
    "lakego-admin/lakego/tree"
    "lakego-admin/lakego/collection"

    "lakego-admin/admin/model"
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
        return nil
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

    list := collection.Collect(data).
        Collapse().
        ToMapArray()

    return list
}

// 获取 ChildrenIds
func GetChildrenIds(groupid string) []string {
    // 格式化分组
    list := GetChildren(groupid)
    ids := collection.Collect(list).
        Pluck("id").
        ToStringArray()

    return ids
}

// 获取 ChildrenIds
func GetChildrenIdsFromGroupids(groupids []string) []string {
    // 格式化分组
    list := GetChildrenFromGroupids(groupids)
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

    ids := collection.Collect(list).
        Pluck("id").
        ToStringArray()

    return ids
}

