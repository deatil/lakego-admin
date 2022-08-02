package provider

import (
    "path/filepath"
    "github.com/deatil/lakego-filesystem/filesystem"
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/publish"
    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/config/adapter"
    pathTool "github.com/deatil/lakego-doak/lakego/path"
    viewFunc "github.com/deatil/lakego-doak/lakego/view/funcs"
    viewFinder "github.com/deatil/lakego-doak/lakego/view/finder"
    appInterface "github.com/deatil/lakego-doak/lakego/app/interfaces"
)

/**
 * 服务提供者
 *
 * @create 2021-7-11
 * @author deatil
 */
type ServiceProvider struct {
    // 启动 app
    App appInterface.App

    // 路由
    Route *router.Engine

    // 启动前
    BootingCallback func()

    // 启动后
    BootedCallback func()
}

// 设置
func (this *ServiceProvider) WithApp(app any) {
    this.App = app.(appInterface.App)
}

// 获取
func (this *ServiceProvider) GetApp() appInterface.App {
    return this.App
}

// 设置
func (this *ServiceProvider) WithRoute(route *router.Engine) {
    this.Route = route
}

// 获取
func (this *ServiceProvider) GetRoute() *router.Engine {
    return this.Route
}

// 添加脚本
func (this *ServiceProvider) AddCommand(cmd *command.Command) {
    if this.App != nil {
        this.App.GetRootCmd().AddCommand(cmd)
    }
}

// 添加脚本
func (this *ServiceProvider) AddCommands(cmds []any) {
    for _, cmd := range cmds {
        this.AddCommand(cmd.(*command.Command))
    }
}

// 添加路由
func (this *ServiceProvider) AddRoute(f func(*router.Engine)) {
    if this.Route != nil {
        f(this.Route)
    }
}

// 添加路由分组
func (this *ServiceProvider) AddGroup(conf map[string]string, f func(*router.RouterGroup)) {
    // 分组前缀
    prefix, ok := conf["prefix"]
    if !ok {
        return
    }

    // 中间件
    middleware, ok2 := conf["middleware"]
    if !ok2 {
        return
    }

    // 中间件
    groupMiddlewares := router.GetMiddlewares(middleware)

    // 使用中间件
    this.AddRoute(func(engine *router.Engine) {
        // 路由
        group := engine.Group(prefix)
        {
            group.Use(groupMiddlewares...)
            {
                f(group)
            }
        }
    })
}

// 设置启动前函数
func (this *ServiceProvider) WithBooting(f func()) {
    this.BootingCallback = f
}

// 设置启动后函数
func (this *ServiceProvider) WithBooted(f func()) {
    this.BootedCallback = f
}

// 启动前回调
func (this *ServiceProvider) CallBootingCallback() {
    if this.BootingCallback != nil {
        (this.BootingCallback)()
    }
}

// 启动后回调
func (this *ServiceProvider) CallBootedCallback() {
    if this.BootedCallback != nil {
        (this.BootedCallback)()
    }
}

// 配置信息
func (this *ServiceProvider) MergeConfigFrom(path string, key string) {
    // 格式化路径
    path = pathTool.FormatPath(path)

    newPath, err := filepath.Abs(path)
    if err == nil {
        adapter.InstancePath().WithPath(key, newPath)
    }
}

// 注册视图
func (this *ServiceProvider) LoadViewsFrom(path string, namespace string) {
    viewFinder := viewFinder.Instance()

    paths := config.New("view").GetStringSlice("paths")
    if len(paths) > 0 {
        for _, viewPath := range paths {
            appPath := pathTool.FormatPath(viewPath) + "/pkg/" + namespace

            if filesystem.New().Exists(appPath) {
                viewFinder.AddNamespace(namespace, []string{appPath})
            }
        }
    }

    // 格式化路径
    path = pathTool.FormatPath(path)

    viewFinder.AddNamespace(namespace, []string{path})
}

// 添加视图用方法
func (this *ServiceProvider) AddViewFunc(name string, fn any) {
    viewFunc.Instance().AddFunc(name, fn)
}

// 推送
func (this *ServiceProvider) Publishes(obj any, paths map[string]string, group string) {
    publish.Instance().Publish(obj, paths, group)
}

// 注册
func (this *ServiceProvider) Register() {
    // 注册
}

// 引导
func (this *ServiceProvider) Boot() {
    // 引导
}

