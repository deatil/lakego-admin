package admin

import (
    "github.com/gin-gonic/gin"
    "lakego-admin/lakego/lake"
    "lakego-admin/lakego/config"
    "lakego-admin/lakego/provider"
    "lakego-admin/lakego/http/code"
    "lakego-admin/lakego/http/route"
    "lakego-admin/lakego/http/response"
    "lakego-admin/lakego/http/route/middleware"

    // 中间件
    "lakego-admin/admin/middleware/exception"
    "lakego-admin/admin/middleware/authorization"
    "lakego-admin/admin/middleware/cors"
    "lakego-admin/admin/middleware/permission"

    // 路由
    adminRoute "lakego-admin/admin/router"

    // 脚本
    "lakego-admin/admin/cmd"
)

// 路由中间件
var routeMiddlewares map[string]gin.HandlerFunc = map[string]gin.HandlerFunc{
    // 异常处理
    "lakego.exception": exception.Handler(),

    // 跨域处理
    "lakego.cors": cors.Handler(),

    // token 验证
    "lakego.auth": authorization.Handler(),

    // 权限检测
    "lakego.permission": permission.Handler(),
}

// 中间件分组
var middlewareGroups map[string]interface{} = map[string]interface{}{
    "lakego-admin": []string{
        "lakego.exception",
        "lakego.cors",
        "lakego.auth",
        "lakego.permission",
    },
}

// 服务提供者
type ServiceProvider struct {
    provider.ServiceProvider
}

// 注册
func (s *ServiceProvider) Register() {
    if s.App.GetRunningInConsole() {
        // 脚本
        s.loadCmd()
    } else {
        // 中间件
        s.loadMiddleware()

        // 分组
        s.loadGroup()

        // 路由
        s.loadRoute()
    }
}

/**
 * 导入脚本
 */
func (s *ServiceProvider) loadCmd() {
    s.App.GetRootCmd().AddCommand(cmd.InstallCmd)
}

/**
 * 导入中间件
 */
func (s *ServiceProvider) loadMiddleware() {
    m := middleware.GetInstance()

    for name, value := range routeMiddlewares {
        m.WithMiddleware(name, value)
    }
}

/**
 * 导入中间件分组
 */
func (s *ServiceProvider) loadGroup() {
    m := middleware.GetInstance()

    for name, value := range middlewareGroups {
        for _, group := range value.([]string) {
            m.WithGroup(name, group)
        }
    }
}

/**
 * 导入路由
 */
func (s *ServiceProvider) loadRoute() {
    conf := config.New("admin")

    prefix := "/" + conf.GetString("Route.Group") + "/*"

    // 未知路由处理
    s.Route.NoRoute(func (ctx *gin.Context) {
        if lake.MatchPath(ctx, prefix, "") {
            response.Error(ctx, "未知路由", code.StatusInvalid)
        }
    })

    // 未知调用方式
    s.Route.NoMethod(func (ctx *gin.Context) {
        if lake.MatchPath(ctx, prefix, "") {
            response.Error(ctx, "访问错误", code.StatusInvalid)
        }
    })

    // 后台路由及设置中间件
    m := route.GetMiddlewares(conf.GetString("Route.Middleware"))

    // 路由
    admin := s.Route.Group(conf.GetString("Route.Group"))
    {
        admin.Use(m...)
        {
            adminRoute.Route(admin)
        }
    }
}

