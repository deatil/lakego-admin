package provider

import (
    "github.com/spf13/cobra"
    "github.com/gin-gonic/gin"

    appInterface "lakego-admin/lakego/app/interfaces"
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
    Route *gin.Engine

    // 启动前
    BootingCallback func()

    // 启动后
    BootedCallback func()
}

// 设置
func (s *ServiceProvider) WithApp(app interface{}) {
    s.App = app.(appInterface.App)
}

// 获取
func (s *ServiceProvider) GetApp() appInterface.App {
    return s.App
}

// 设置
func (s *ServiceProvider) WithRoute(route *gin.Engine) {
    s.Route = route
}

// 获取
func (s *ServiceProvider) GetRoute() *gin.Engine {
    return s.Route
}

// 添加脚本
func (s *ServiceProvider) AddCommand(cmd *cobra.Command) {
    if s.App != nil {
        s.App.GetRootCmd().AddCommand(cmd)
    }
}

// 添加脚本
func (s *ServiceProvider) AddCommands(cmds []interface{}) {
    for _, cmd := range cmds {
        s.AddCommand(cmd.(*cobra.Command))
    }
}

// 添加路由
func (s *ServiceProvider) AddRoute(f func(*gin.Engine)) {
    if s.Route != nil {
        f(s.Route)
    }
}

// 设置启动前函数
func (s *ServiceProvider) WithBooting(f func()) {
    s.BootingCallback = f
}

// 设置启动后函数
func (s *ServiceProvider) WithBooted(f func()) {
    s.BootedCallback = f
}

// 启动前回调
func (s *ServiceProvider) CallBootingCallback() {
    if s.BootingCallback != nil {
        (s.BootingCallback)()
    }
}

// 启动后回调
func (s *ServiceProvider) CallBootedCallback() {
    if s.BootedCallback != nil {
        (s.BootedCallback)()
    }
}

// 注册
func (s *ServiceProvider) Register() {
    // 注册
}

// 引导
func (s *ServiceProvider) Boot() {
    // 引导
}

