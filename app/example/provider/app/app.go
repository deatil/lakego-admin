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
func (this *ServiceProvider) Register() {
    // 脚本
    this.loadCommand()

    // 路由
    this.loadRoute()

    // 注册额外服务提供者
    this.registerProviders()
}

/**
 * 导入脚本
 */
func (this *ServiceProvider) loadCommand() {
    // 用户信息
    this.AddCommand(command.ExampleCmd)
}

/**
 * 导入路由
 */
func (this *ServiceProvider) loadRoute() {
    // 后台路由，包括后台使用的所有中间件
    route.AddRoute(func(engine *gin.RouterGroup) {
        router.Route(engine)
    })

    // 常规 gin 路由，除 gin 自带外没有任何中间件
    this.AddRoute(func(engine *gin.Engine) {
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
func (this *ServiceProvider) registerProviders() {
    // 注册
    this.GetApp().Register(func() providerInterface.ServiceProvider {
        return &exampleProvider.ServiceProvider{}
    })
}

