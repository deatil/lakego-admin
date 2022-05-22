package cmd

import (
    "fmt"

    "github.com/deatil/lakego-doak/lakego/command"

    "github.com/deatil/lakego-doak-admin/admin/permission"
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
var ResetPermissionCmd = &command.Command{
    Use: "lakego-admin:reset-permission",
    Short: "lakego-admin reset enforcer'permission.",
    Example: "{execfile} lakego-admin:reset-permission",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {

    },
    Run: func(cmd *command.Command, args []string) {
        ResetPermission()
    },
}

// 重设权限
func ResetPermission() {
    // 重设权限
    res := permission.ResetPermission()
    if res == false {
        fmt.Println("权限同步失败")
        return
    }

    fmt.Println("权限同步成功")
}

