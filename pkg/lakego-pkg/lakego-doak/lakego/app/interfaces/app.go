package interfaces

import (
    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/schedule"
    iprovider "github.com/deatil/lakego-doak/lakego/provider/interfaces"
)

/**
 * App 接口
 *
 * @create 2021-6-19
 * @author deatil
 */
type App interface {
    // 注册服务提供者
    Register(func() iprovider.ServiceProvider) iprovider.ServiceProvider

    // 批量注册服务提供者
    Registers([]func() iprovider.ServiceProvider)

    // 获取
    GetRegister(any) iprovider.ServiceProvider

    // 反射获取服务提供者名称
    GetProviderName(any) string

    // GetLoadedProviders
    GetLoadedProviders() map[string]bool

    // ProviderIsLoaded
    ProviderIsLoaded(string) bool

    // 脚本
    WithRootCmd(*command.Command)

    // 设置启动前函数
    WithBooting(func())

    // 设置启动后函数
    WithBooted(func())

    // 获取脚本
    GetRootCmd() *command.Command

    // 获取计划任务
    GetSchedule() *schedule.Schedule

    // 命令行状态
    WithRunningInConsole(bool)

    // 获取命令行状态
    RunningInConsole() bool

    // 是否为已运行
    IsRunned() bool

    // 是否为开发者模式
    IsDev() bool
}
