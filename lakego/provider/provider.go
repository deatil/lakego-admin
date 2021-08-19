package provider

import (
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

// 注册
func (s *ServiceProvider) Register() {
}

// 引导
func (s *ServiceProvider) Boot() {
}

