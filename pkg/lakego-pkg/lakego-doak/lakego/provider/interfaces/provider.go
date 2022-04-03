package interfaces

import (
    "github.com/deatil/lakego-doak/lakego/router"
)

/**
 * 服务提供者接口
 *
 * @create 2021-6-19
 * @author deatil
 */
type ServiceProvider interface {
    // 设置 App
    WithApp(interface{})

    // 设置路由
    WithRoute(*router.Engine)

    // 获取
    GetRoute() *router.Engine

    // 注册
    Register()

    // 引导
    Boot()

    // 设置启动前函数
    WithBooting(func())

    // 设置启动后函数
    WithBooted(func())

    // 启动前回调
    CallBootingCallback()

    // 启动后回调
    CallBootedCallback()
}
