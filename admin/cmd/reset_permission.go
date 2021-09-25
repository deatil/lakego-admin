package cmd

import (
    "fmt"

    "github.com/spf13/cobra"
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
        fmt.Println("成功！")
    },
}

