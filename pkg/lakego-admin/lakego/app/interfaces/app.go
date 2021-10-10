package interfaces

import (
    "github.com/spf13/cobra"
    providerInterface "github.com/deatil/lakego-admin/lakego/provider/interfaces"
)

/**
 * App 接口
 *
 * @create 2021-6-19
 * @author deatil
 */
type App interface {
    // 注册服务提供者
    Register(func() providerInterface.ServiceProvider)

    // 批量注册服务提供者
    Registers([]func() providerInterface.ServiceProvider)

    // 脚本
    WithRootCmd(*cobra.Command)

    // 设置启动前函数
    WithBooting(func())

    // 设置启动后函数
    WithBooted(func())

    // 获取脚本
    GetRootCmd() *cobra.Command

    // 命令行状态
    WithRunningInConsole(bool)

    // 获取命令行状态
    RunningInConsole() bool
}
