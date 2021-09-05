package authrule

import (
    "lakego-admin/lakego/collection"

    "lakego-admin/admin/model"
)

// 全部权限
func GetAllRule() []map[string]interface{} {
    list := male([]map[string]interface{}, 0)

    // 附件模型
    err := model.NewAuthRule().
        Select([]string{
            "id", "parentid",
            "title",
            "url", "method",
            "description",
        }).
        Where("status = ?", 1).
        Order("listorder ASC").
        Order("add_time ASC").
        Find(&list).
        Error
    if err != nil {
        return nil
    }

    return list
}

