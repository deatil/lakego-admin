package cmd

import (
    "fmt"

    "github.com/spf13/cobra"
)

/**
 * 导入路由信息
 *
 * > ./main lakego-admin:import-route
 * > main.exe lakego-admin:import-route
 * > go run main.go lakego-admin:import-route
 *
 * @create 2021-9-26
 * @author deatil
 */
var ImportRouteCmd = &cobra.Command{
    Use: "lakego-admin:import-route",
    Short: "lakego-admin import route'info.",
    Example: "{execfile} lakego-admin:import-route",
    SilenceUsage: true,
    PreRun: func(cmd *cobra.Command, args []string) {

    },
    Run: func(cmd *cobra.Command, args []string) {
        ImportRoute()
    },
}

// 导入路由信息
func ImportRoute() {
    fmt.Println("账号退出成功")
}

