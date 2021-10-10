package app

import (
    "os"
    "github.com/spf13/cobra"

    "github.com/deatil/lakego-admin/lakego/provider"
    providerInterface "github.com/deatil/lakego-admin/lakego/provider/interfaces"
    _ "github.com/deatil/lakego-admin/lakego/facade/database"
)

// 实例化
func NewBootstrap() *Bootstrap {
    b := &Bootstrap{}

    return b
}

// 脚本
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

/**
 * 系统引导
 *
 * @create 2021-10-10
 * @author deatil
 */
type Bootstrap struct {
    // 注册的服务提供者
    providers []func() providerInterface.ServiceProvider
}

// 执行
func (b *Bootstrap) Execute() {
    args := os.Args

    if len(args) > 1 {
        b.RunCmd()
    } else {
        b.RunServer()
    }
}

// 运行服务
func (b *Bootstrap) RunServer() {
    b.RunApp(false)
}

// 加载脚本
func (b *Bootstrap) RunCmd() {
    b.RunApp(true)

    if err := rootCmd.Execute(); err != nil {
        os.Exit(-1)
    }
}

// 添加服务提供者
func (b *Bootstrap) WithServiceProvider(f func() providerInterface.ServiceProvider) *Bootstrap {
    b.providers = append(b.providers, f)

    return b
}

// 批量添加服务提供者
func (b *Bootstrap) WithServiceProviders(funcs []func() providerInterface.ServiceProvider) *Bootstrap {
    if len(funcs) > 0 {
        for _, f := range funcs {
            b.WithServiceProvider(f)
        }
    }

    return b
}

// 运行
func (b *Bootstrap) RunApp(console bool) {
    newApp := New()

    // 导入服务提供者
    b.loadServiceProvider()

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

// 导入服务提供者
func (b *Bootstrap) loadServiceProvider() {
    if len(b.providers) > 0 {
        for _, p := range b.providers {
            provider.AppendProvider(p)
        }
    }
}

