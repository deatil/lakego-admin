package admin

import (
    "github.com/gin-gonic/gin"
    "lakego-admin/lakego/config"
    "lakego-admin/lakego/provider"
    "lakego-admin/lakego/http/route"
    "lakego-admin/lakego/http/response"
    "lakego-admin/lakego/http/route/middleware"

    "lakego-admin/admin/support/url"
    "lakego-admin/admin/support/http/code"

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

// 全局中间件
var middlewares []gin.HandlerFunc = []gin.HandlerFunc{}

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
    // 脚本
    s.loadCmd()

    if !s.App.GetRunningInConsole() {
        // 路由
        s.loadRoute()
    }
}

/**
 * 导入脚本
 */
func (s *ServiceProvider) loadCmd() {
    s.AddCommand(cmd.InstallCmd)
}

/**
 * 导入路由
 */
func (s *ServiceProvider) loadRoute() {
    s.AddRoute(func(engine *gin.Engine) {
        // 中间件
        s.loadMiddleware()

        // 分组
        s.loadGroup()

        conf := config.New("admin")

        prefix := "/" + conf.GetString("Route.Prefix") + "/*"

        // 未知路由处理
        engine.NoRoute(func (ctx *gin.Context) {
            if url.MatchPath(ctx, prefix, "") {
                response.Error(ctx, "未知路由", code.StatusInvalid)
            }
        })

        // 未知调用方式
        engine.NoMethod(func (ctx *gin.Context) {
            if url.MatchPath(ctx, prefix, "") {
                response.Error(ctx, "访问错误", code.StatusInvalid)
            }
        })

        // 全局中间件
        engine.Use(middlewares...)

        // 后台路由及设置中间件
        m := route.GetMiddlewares(conf.GetString("Route.Middleware"))

        // 路由
        admin := engine.Group(conf.GetString("Route.Prefix"))
        {
            admin.Use(m...)
            {
                adminRoute.Route(admin)
            }
        }

    })
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

