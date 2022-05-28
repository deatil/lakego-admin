package provider

import (
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/provider"

    "github.com/deatil/lakego-doak-admin/admin/support/route"

    databaseRouter "github.com/deatil/lakego-doak-database/database/route"
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
    route.AddRoute(func(engine *router.RouterGroup) {
        databaseRouter.Route(engine)
    })
}

