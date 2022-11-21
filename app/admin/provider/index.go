package provider

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-doak/lakego/provider"
    admin_route "github.com/deatil/lakego-doak-admin/admin/support/route"

    // 路由
    "app/admin/route"
)

/**
 * 服务提供者
 *
 * @create 2022-11-21
 * @author deatil
 */
type Index struct {
    provider.ServiceProvider
}

// 引导
func (this *Index) Boot() {
    // 路由
    this.loadRoute()
}

/**
 * 导入路由
 */
func (this *Index) loadRoute() {
    // 后台路由，包括后台使用的所有中间件
    admin_route.AddRoute(func(engine *gin.RouterGroup) {
        route.Route(engine)
    })
}

