package app

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/lakego/provider"
    "github.com/deatil/lakego-admin/lakego/facade/config"
    pathTool "github.com/deatil/lakego-admin/lakego/support/path"
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

    // 配置
    this.loadSetting()

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
 * 导入配置
 */
func (this *ServiceProvider) loadSetting() {
    // 配置
    path := "{root}/app/example/config/example.yml"

    // 格式化路径
    path = pathTool.FormatPath(path)

    // 设置配置
    this.MergeConfigFrom(path, "example")

    // 推送
    // go run main.go lakego:publish --tag=example-config
    toPath := "{root}/config/example.yml"
    toPath = pathTool.FormatPath(toPath)
    this.Publishes(map[string]string{
        path: toPath,
    }, "example-config")
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
            // 测试自定义配置数据
            exampleData := config.New("example").GetString("Default")

            ctx.JSON(200, gin.H{
                "data": "例子显示信息",
                "exampleData": exampleData,
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

