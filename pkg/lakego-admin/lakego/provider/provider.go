package provider

import (
    "github.com/deatil/lakego-admin/lakego/view"
    "github.com/deatil/lakego-admin/lakego/router"
    "github.com/deatil/lakego-admin/lakego/publish"
    "github.com/deatil/lakego-admin/lakego/command"
    "github.com/deatil/lakego-admin/lakego/support/file"
    "github.com/deatil/lakego-admin/lakego/facade/config"
    "github.com/deatil/lakego-admin/lakego/config/adapter"
    appInterface "github.com/deatil/lakego-admin/lakego/app/interfaces"
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
func (this *ServiceProvider) WithApp(app interface{}) {
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
func (this *ServiceProvider) AddCommands(cmds []interface{}) {
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
    adapter.NewPathInstance().WithPath(key, path)
}

// 注册视图
func (this *ServiceProvider) LoadViewsFrom(path string, namespace string) {
    viewFinder := view.NewInstance()

    paths := config.New("view").GetStringSlice("Paths")
    if len(paths) > 0 {
        for _, viewPath := range paths {
            appPath := viewPath + "/pkg/" + namespace

            if exists, _ := file.PathExists(appPath); exists {
                viewFinder.AddNamespace(namespace, []string{appPath})
            }
        }
    }

    viewFinder.AddNamespace(namespace, []string{path})
}

// 推送
func (this *ServiceProvider) Publishes(paths map[string]string, group string) {
    publish.NewInstance().Publish(this, paths, group)
}

// 注册
func (this *ServiceProvider) Register() {
    // 注册
}

// 引导
func (this *ServiceProvider) Boot() {
    // 引导
}

