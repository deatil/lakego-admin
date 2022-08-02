package provider

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-filesystem/filesystem"
    "github.com/deatil/lakego-doak/lakego/path"
    "github.com/deatil/lakego-doak/lakego/provider"
    providerInterface "github.com/deatil/lakego-doak/lakego/provider/interfaces"

    "github.com/deatil/lakego-doak-admin/admin/support/route"

    // 路由
    router "app/example/route"
    command "app/example/cmd"
    exampleView "app/example/view"
)

/**
 * 服务提供者
 *
 * @create 2021-10-11
 * @author deatil
 */
type ExampleServiceProvider struct {
    provider.ServiceProvider
}

// 引导
func (this *ExampleServiceProvider) Boot() {
    // 脚本
    this.loadCommand()

    // 配置
    this.loadSetting()

    // 路由
    this.loadRoute()

    // 导入视图方法
    this.loadViewFuncs()

    // 注册额外服务提供者
    this.registerProviders()
}

/**
 * 导入脚本
 */
func (this *ExampleServiceProvider) loadCommand() {
    // 用户信息
    this.AddCommand(command.ExampleCmd)
}

/**
 * 导入配置
 */
func (this *ExampleServiceProvider) loadSetting() {
    // 合并配置
    toDefaultFile := path.FormatPath("{root}/config/default/example.yml")
    if filesystem.New().Exists(toDefaultFile) {
        this.MergeConfigFrom(toDefaultFile, "example")
    }

    configFile := path.FormatPath("{root}/app/example/resources/config/example.yml")
    toConfigFile := path.FormatPath("{root}/config/example.yml")

    // 推送已注册的全部
    // > go run main.go lakego:publish --all

    // 推送当前服务提供者已注册数据
    // > go run main.go lakego:publish --provider=app/example/provider/app/ServiceProvider

    // 推送文件
    // > go run main.go lakego:publish --tag=example-config --force
    this.Publishes(this, map[string]string{
        configFile: toConfigFile,
        // configFile: toDefaultFile,
    }, "example-config")

    // 视图
    viewPath := path.FormatPath("{root}/app/example/resources/view")
    toViewPath := path.FormatPath("{root}/resources/view/example")

    // 推送文件夹
    // > go run main.go lakego:publish --tag=example-view --force
    this.Publishes(this, map[string]string{
        viewPath: toViewPath,
    }, "example-view")

    // 视图
    this.LoadViewsFrom(toViewPath, "example")
}

/**
 * 导入路由
 */
func (this *ExampleServiceProvider) loadRoute() {
    // 后台路由，包括后台使用的所有中间件
    route.AddRoute(func(engine *gin.RouterGroup) {
        router.Route(engine)
    })

    // 常规 gin 路由，除 gin 自带外没有任何中间件
    this.AddRoute(func(engine *gin.Engine) {
        router.GinRoute(engine)
    })
}

/**
 * 导入视图方法
 */
func (this *ExampleServiceProvider) loadViewFuncs() {
    // 添加自定义方法
    this.AddViewFunc("formatData", exampleView.FormatData)
}

/**
 * 注册额外服务提供者
 */
func (this *ExampleServiceProvider) registerProviders() {
    // 注册
    this.GetApp().Register(func() providerInterface.ServiceProvider {
        return &OtherServiceProvider{}
    })
}

