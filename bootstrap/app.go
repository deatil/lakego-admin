package bootstrap

import (
    "os"
    "github.com/spf13/cobra"

    "lakego-admin/lakego/app"
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

// 运行 api 服务
func RunServer() {
    newApp := app.New()

    newApp.WithRunningInConsole(false)

    // admin 后台路由
    adminServiceProvider := &adminProvider.ServiceProvider{}
    newApp.Register(func() providerInterface.ServiceProvider {
        return adminServiceProvider
    })

    newApp.Run()
}

// 加载脚本
func RunCmd() {
    newApp := app.New()

    newApp.WithRunningInConsole(true)

    newApp.WithRootCmd(rootCmd)

    // admin 后台路由
    adminServiceProvider := &adminProvider.ServiceProvider{}
    newApp.Register(func() providerInterface.ServiceProvider {
        return adminServiceProvider
    })

    newApp.LoadServiceProvider()
}

