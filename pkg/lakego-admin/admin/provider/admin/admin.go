package admin

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/lakego/provider"
    "github.com/deatil/lakego-admin/lakego/http/response"
    "github.com/deatil/lakego-admin/lakego/http/route"
    "github.com/deatil/lakego-admin/lakego/facade/config"

    "github.com/deatil/lakego-admin/admin/support/url"
    "github.com/deatil/lakego-admin/admin/support/http/code"

    // 中间件
    "github.com/deatil/lakego-admin/admin/middleware/exception"
    "github.com/deatil/lakego-admin/admin/middleware/authorization"
    "github.com/deatil/lakego-admin/admin/middleware/cors"
    "github.com/deatil/lakego-admin/admin/middleware/permission"
    "github.com/deatil/lakego-admin/admin/middleware/actionlog"
    "github.com/deatil/lakego-admin/admin/middleware/admincheck"

    // 路由
    adminRoute "github.com/deatil/lakego-admin/admin/route"

    // 脚本
    "github.com/deatil/lakego-admin/admin/cmd"
)

// 全局中间件
var middlewares = []gin.HandlerFunc{}

// 路由中间件
var routeMiddlewares = map[string]gin.HandlerFunc{
    // 异常处理
    "lakego.exception": exception.Handler(),

    // 跨域处理
    "lakego.cors": cors.Handler(),

    // token 验证
    "lakego.auth": authorization.Handler(),

    // 权限检测
    "lakego.permission": permission.Handler(),

    // 操作日志
    "lakego.action-log": actionlog.Handler(),

    // 超级管理员检测
    "lakego.admin-check": admincheck.Handler(),
}

// 中间件分组
var middlewareGroups = map[string]interface{}{
    // 常规中间件
    "lakego-admin": []string{
        "lakego.exception",
        "lakego.cors",
        "lakego.auth",
        "lakego.permission",
        "lakego.action-log",
    },
    // 超级管理员检测
    "lakego-admin-check": []string{
        "lakego.admin-check",
    },
}

// 服务提供者
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
    // 安装
    s.AddCommand(cmd.InstallCmd)

    // 重设权限
    s.AddCommand(cmd.ResetPermissionCmd)

    // 导入路由信息
    s.AddCommand(cmd.ImportRouteCmd)

    // 强制将 jwt 的 refreshToken 放入黑名单
    s.AddCommand(cmd.PassportLogoutCmd)

    // 重置密码
    s.AddCommand(cmd.ResetPasswordCmd)
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
        groupMiddlewares := route.GetMiddlewares(conf.GetString("Route.Middleware"))

        // 管理员路由
        adminGroupMiddlewares := route.GetMiddlewares(conf.GetString("Route.AdminMiddleware"))

        // 路由
        admin := engine.Group(conf.GetString("Route.Prefix"))
        {
            admin.Use(groupMiddlewares...)
            {
                // 常规路由
                adminRoute.Route(admin)

                // 需要管理员权限
                admin.Use(adminGroupMiddlewares...)
                {
                    adminRoute.AdminRoute(admin)
                }
            }
        }

    })
}

/**
 * 导入中间件
 */
func (s *ServiceProvider) loadMiddleware() {
    m := route.GetMiddlewareInstance()

    for name, value := range routeMiddlewares {
        m.WithMiddleware(name, value)
    }
}

/**
 * 导入中间件分组
 */
func (s *ServiceProvider) loadGroup() {
    m := route.GetMiddlewareInstance()

    for name, value := range middlewareGroups {
        for _, group := range value.([]string) {
            m.WithGroup(name, group)
        }
    }
}

