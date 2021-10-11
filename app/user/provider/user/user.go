package admin

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/lakego/provider"
    "github.com/deatil/lakego-admin/admin/support/route"

    // 路由
    router "app/user/route"
    command "app/user/cmd"
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
}

/**
 * 导入脚本
 */
func (s *ServiceProvider) loadCommand() {
    // 用户信息
    s.AddCommand(command.UserInfoCmd)
}

/**
 * 导入路由
 */
func (s *ServiceProvider) loadRoute() {
    route.AddRoute(func(engine *gin.RouterGroup) {
        router.Route(engine)
    })
}

