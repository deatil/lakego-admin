package interfaces

import (
    "github.com/spf13/cobra"
    providerInterface "lakego-admin/lakego/provider/interfaces"
)

type App interface {
    // 注册服务提供者
    Register(func() providerInterface.ServiceProvider)

    // 批量注册服务提供者
    Registers([]func() providerInterface.ServiceProvider)

    // 脚本
    WithRootCmd(*cobra.Command)

    // 获取脚本
    GetRootCmd() *cobra.Command

    // 命令行状态
    WithRunningInConsole(bool)

    // 获取命令行状态
    GetRunningInConsole() bool
}
