package provider

import (
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/provider"

    admin_route "github.com/deatil/lakego-doak-admin/admin/support/route"

    database_router "github.com/deatil/lakego-doak-database/database/route"
)

/**
 * 服务提供者
 *
 * @create 2022-5-28
 * @author deatil
 */
type Database struct {
    provider.ServiceProvider
}

// 注册
func (this *Database) Register() {}

// 引导
func (this *Database) Boot() {
    // 路由
    this.loadRoute()
}


/**
 * 导入路由
 */
func (this *Database) loadRoute() {
    // 后台路由
    admin_route.AddRoute(func(engine *router.RouterGroup) {
        database_router.Route(engine)
    })
}

