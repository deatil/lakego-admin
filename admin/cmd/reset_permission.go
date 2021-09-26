package cmd

import (
    "fmt"

    "github.com/spf13/cobra"

    "lakego-admin/lakego/facade/casbin"

    "lakego-admin/admin/model"
)

/**
 * 重设权限
 *
 * > ./main lakego-admin:reset-permission
 * > main.exe lakego-admin:reset-permission
 * > go run main.go lakego-admin:reset-permission
 *
 * @create 2021-9-25
 * @author deatil
 */
var ResetPermissionCmd = &cobra.Command{
    Use: "lakego-admin:reset-permission",
    Short: "lakego-admin reset enforcer'permission.",
    Example: "{execfile} lakego-admin:reset-permission",
    SilenceUsage: true,
    PreRun: func(cmd *cobra.Command, args []string) {

    },
    Run: func(cmd *cobra.Command, args []string) {
        ResetPermission()
    },
}

// 重设权限
func ResetPermission() {
    // 清空原始数据
    casbin.New().ClearData()

    // 权限
    ruleList := make([]model.AuthRuleAccess, 0)
    err := model.NewAuthRuleAccess().
        Preload("Rule", "status = ?", 1).
        Find(&ruleList).
        Error
    if err != nil {
        fmt.Println("权限同步失败")
        return
    }

    ruleListMap := model.FormatStructToArrayMap(ruleList)

    // 分组
    groupList := make([]model.AuthGroupAccess, 0)
    err2 := model.NewAuthGroupAccess().
        Preload("Group", "status = ?", 1).
        Find(&groupList).
        Error
    if err2 != nil {
        fmt.Println("权限同步失败")
        return
    }

    groupListMap := model.FormatStructToArrayMap(groupList)

    // casbin
    cas := casbin.New()

    // 添加权限
    if len(ruleListMap) > 0 {
        for _, rv := range ruleListMap {
            rule := rv["Rule"].(map[string]interface{})

            cas.AddPolicy(rv["group_id"].(string), rule["auth_url"].(string), rule["method"].(string))
        }
    }

    // 添加权限
    if len(groupListMap) > 0 {
        for _, gv := range groupListMap {
            cas.AddRoleForUser(gv["admin_id"].(string), gv["group_id"].(string))
        }
    }

    fmt.Println("权限同步成功")
}

