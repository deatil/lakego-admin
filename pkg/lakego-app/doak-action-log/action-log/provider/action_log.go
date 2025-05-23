package provider

import (
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/provider"

    admin_route "github.com/deatil/lakego-doak-admin/admin/support/route"

    log_router "github.com/deatil/lakego-doak-action-log/action-log/route"
    log_middleware "github.com/deatil/lakego-doak-action-log/action-log/middleware/actionlog"
)

// 路由中间件
var routeMiddlewares = map[string]router.HandlerFunc{
    // 操作日志
    "lakego-admin.action-log": log_middleware.Handler(),
}

// 中间件分组
var middlewareGroups = map[string][]string{
    // 操作日志
    "lakego-admin": {
        "lakego-admin.action-log",
    },
}

/**
 * 服务提供者
 *
 * @create 2021-10-11
 * @author deatil
 */
type ActionLog struct {
    provider.ServiceProvider
}

// 注册
func (this *ActionLog) Register() {
    // 中间件
    this.loadMiddleware()
}

// 引导
func (this *ActionLog) Boot() {
    // 路由
    this.loadRoute()
}

/**
 * 导入中间件
 */
func (this *ActionLog) loadMiddleware() {
    // 导入中间件
    for name, value := range routeMiddlewares {
        router.AliasMiddleware(name, value)
    }

    // 导入中间件分组
    for groupName, middlewares := range middlewareGroups {
        for _, middleware := range middlewares {
            router.PushMiddlewareToGroup(groupName, middleware)
        }
    }
}

/**
 * 导入路由
 */
func (this *ActionLog) loadRoute() {
    // 后台路由
    admin_route.AddRoute(func(engine *router.RouterGroup) {
        log_router.Route(engine)
    })
}

