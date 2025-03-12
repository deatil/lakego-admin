package permission

import (
    "github.com/deatil/lakego-doak/lakego/facade"

    "github.com/deatil/lakego-doak-admin/admin/model"
)

/**
 * 重设权限
 *
 * @create 2021-9-25
 * @author deatil
 */
func ResetPermission() bool {
    // 清空原始数据
    model.ClearRulesData()

    // 权限
    ruleList := make([]model.AuthRuleAccess, 0)
    err := model.NewAuthRuleAccess().
        Preload("Rule", "status = ?", 1).
        Find(&ruleList).
        Error
    if err != nil {
        return false
    }

    ruleListMap := model.FormatStructToArrayMap(ruleList)

    // 分组
    groupList := make([]model.AuthGroupAccess, 0)
    err2 := model.NewAuthGroupAccess().
        Preload("Group", "status = ?", 1).
        Find(&groupList).
        Error
    if err2 != nil {
        return false
    }

    groupListMap := model.FormatStructToArrayMap(groupList)

    perm := facade.Permission

    // 添加权限
    if len(ruleListMap) > 0 {
        for _, rv := range ruleListMap {
            rule := rv["Rule"].(map[string]any)

            perm.AddPolicy(rv["group_id"].(string), rule["url"].(string), rule["method"].(string))
        }
    }

    // 添加权限
    if len(groupListMap) > 0 {
        for _, gv := range groupListMap {
            perm.AddRoleForUser(gv["admin_id"].(string), gv["group_id"].(string))
        }
    }

    return true
}

