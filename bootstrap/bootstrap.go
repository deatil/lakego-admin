package bootstrap

import (
    "os"
    "github.com/spf13/cobra"

    "github.com/deatil/lakego-admin/lakego/app"
    "github.com/deatil/lakego-admin/lakego/provider"
    _ "github.com/deatil/lakego-admin/lakego/facade/database"
)

var rootCmd = &cobra.Command{
    Use: "lakego-admin",
    Short: "lakego-admin",
    SilenceUsage: true,
    Long: `lakego-admin`,
    Args: func(cmd *cobra.Command, args []string) error {
        return nil
    },
    PersistentPreRunE: func(*cobra.Command, []string) error {
        return nil
    },
    Run: func(cmd *cobra.Command, args []string) {
    },
}

// 执行
func Execute() {
    args := os.Args

    if len(args) > 1 {
        RunCmd()

        if err := rootCmd.Execute(); err != nil {
            os.Exit(-1)
        }
    } else {
        RunServer()
    }
}

// 导入服务提供者
func LoadServiceProvider() {
    if len(providers) > 0 {
        for _, p := range providers {
            provider.AppendProvider(p)
        }
    }
}

// 运行
func RunApp(console bool) {
    newApp := app.New()

    // 导入服务提供者
    LoadServiceProvider()

    // 注册
    allProviders := provider.GetAllProvider()
    newApp.Registers(allProviders)

    // 脚本
    newApp.WithRootCmd(rootCmd)

    if console {
        newApp.WithRunningInConsole(true)
    } else {
        newApp.WithRunningInConsole(false)
    }

    // 运行
    newApp.Run()
}

// 运行 api 服务
func RunServer() {
    RunApp(false)
}

// 加载脚本
func RunCmd() {
    RunApp(true)
}

