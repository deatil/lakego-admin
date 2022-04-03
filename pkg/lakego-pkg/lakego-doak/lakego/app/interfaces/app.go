package interfaces

import (
    "github.com/deatil/lakego-doak/lakego/command"
    providerInterface "github.com/deatil/lakego-doak/lakego/provider/interfaces"
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
    WithRootCmd(*command.Command)

    // 设置启动前函数
    WithBooting(func())

    // 设置启动后函数
    WithBooted(func())

    // 获取脚本
    GetRootCmd() *command.Command

    // 命令行状态
    WithRunningInConsole(bool)

    // 获取命令行状态
    RunningInConsole() bool

    // 是否为开发者模式
    IsDev() bool
}
