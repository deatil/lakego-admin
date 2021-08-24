package bootstrap

import (
    "os"
    "github.com/spf13/cobra"

    "lakego-admin/lakego/app"
    "lakego-admin/lakego/provider"
    providerInterface "lakego-admin/lakego/provider/interfaces"
    adminProvider "lakego-admin/admin/provider/admin"
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
    // admin 后台路由
    adminServiceProvider := &adminProvider.ServiceProvider{}
    provider.AppendProvider(func() providerInterface.ServiceProvider {
        return adminServiceProvider
    })
}

// 运行
func GetRunApp() *app.App {
    newApp := app.New()

    // 导入服务提供者
    LoadServiceProvider()

    // 注册
    allProviders := provider.GetAllProvider()
    newApp.Registers(allProviders)

    // 脚本
    newApp.WithRootCmd(rootCmd)

    return newApp
}

// 运行 api 服务
func RunServer() {
    newApp := GetRunApp()

    newApp.WithRunningInConsole(false)

    newApp.Run()
}

// 加载脚本
func RunCmd() {
    newApp := GetRunApp()

    newApp.WithRunningInConsole(true)

    newApp.LoadServiceProvider()
}

