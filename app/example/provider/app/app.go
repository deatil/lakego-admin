package app

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/lakego/provider"
    providerInterface "github.com/deatil/lakego-admin/lakego/provider/interfaces"

    "github.com/deatil/lakego-admin/admin/support/route"

    // 路由
    router "app/example/route"
    command "app/example/cmd"
    exampleProvider "app/example/provider/example"
)

/**
 * 服务提供者
 *
 * @create 2021-10-11
 * @author deatil
 */
type ServiceProvider struct {
    provider.ServiceProvider
}

// 注册
func (s *ServiceProvider) Register() {
    // 脚本
    s.loadCommand()

    // 路由
    s.loadRoute()

    // 注册额外服务提供者
    s.registerProviders()
}

/**
 * 导入脚本
 */
func (s *ServiceProvider) loadCommand() {
    // 用户信息
    s.AddCommand(command.ExampleCmd)
}

/**
 * 导入路由
 */
func (s *ServiceProvider) loadRoute() {
    // 后台路由，包括后台使用的所有中间件
    route.AddRoute(func(engine *gin.RouterGroup) {
        router.Route(engine)
    })

    // 常规 gin 路由，除 gin 自带外没有任何中间件
    s.AddRoute(func(engine *gin.Engine) {
        engine.GET("/example", func(ctx *gin.Context) {
            ctx.JSON(200, gin.H{
                "data": "例子显示信息",
            })
        })
    })
}

/**
 * 注册额外服务提供者
 */
func (s *ServiceProvider) registerProviders() {
    // 注册
    s.GetApp().Register(func() providerInterface.ServiceProvider {
        return &exampleProvider.ServiceProvider{}
    })
}

