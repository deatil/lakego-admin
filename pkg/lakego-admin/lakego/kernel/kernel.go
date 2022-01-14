package kernel

import (
    "os"
    "net"

    "github.com/deatil/lakego-admin/lakego/app"
    "github.com/deatil/lakego-admin/lakego/command"
    "github.com/deatil/lakego-admin/lakego/provider"
    "github.com/deatil/lakego-admin/lakego/provider/interfaces"
    lakegoProvider "github.com/deatil/lakego-admin/lakego/service/lakego"

    _ "github.com/deatil/lakego-admin/lakego/facade/database"
)

// 实例化
func New() *Kernel {
    // 实例化核心
    kernel := &Kernel{}

    // 导入服务提供者
    kernel.loadDefaultServiceProvider()

    return kernel
}

// 脚本
var rootCmd = &command.Command{
    Use: "lakego-admin",
    Short: "lakego-admin",
    SilenceUsage: true,
    Long: `lakego-admin`,
    Args: func(cmd *command.Command, args []string) error {
        return nil
    },
    PersistentPreRunE: func(*command.Command, []string) error {
        return nil
    },
    Run: func(cmd *command.Command, args []string) {
    },
}

/**
 * 核心
 *
 * @create 2021-10-10
 * @author deatil
 */
type Kernel struct {
    // 注册的服务提供者
    providers []func() interfaces.ServiceProvider

    // 自定义运行监听
    NetListener net.Listener
}

// 执行
func (this *Kernel) Terminate() {
    args := os.Args

    if len(args) > 1 {
        this.RunCmd()
    } else {
        this.RunServer()
    }
}

// 运行服务
func (this *Kernel) RunServer() {
    this.RunApp(false)
}

// 加载脚本
func (this *Kernel) RunCmd() {
    this.RunApp(true)

    if err := rootCmd.Execute(); err != nil {
        os.Exit(-1)
    }
}

// 默认服务提供者
func (this *Kernel) loadDefaultServiceProvider() {
    this.WithServiceProvider(func() interfaces.ServiceProvider {
        return &lakegoProvider.ServiceProvider{}
    })
}

// 添加服务提供者
func (this *Kernel) WithServiceProvider(f func() interfaces.ServiceProvider) *Kernel {
    this.providers = append(this.providers, f)

    return this
}

// 批量添加服务提供者
func (this *Kernel) WithServiceProviders(funcs []func() interfaces.ServiceProvider) *Kernel {
    if len(funcs) > 0 {
        for _, f := range funcs {
            this.WithServiceProvider(f)
        }
    }

    return this
}

// 设置自定义监听
func (this *Kernel) WithNetListener(listener net.Listener) *Kernel {
    this.NetListener = listener

    return this
}

// 运行
func (this *Kernel) RunApp(console bool) {
    newApp := app.New()

    // 导入服务提供者
    this.loadServiceProvider()

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

    // 设置自定义监听
    if this.NetListener != nil {
        newApp.WithNetListener(this.NetListener)
    }

    // 运行
    newApp.Run()
}

// 导入服务提供者
func (this *Kernel) loadServiceProvider() {
    if len(this.providers) > 0 {
        for _, p := range this.providers {
            provider.AppendProvider(p)
        }
    }
}

