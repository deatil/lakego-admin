package admin

import (
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/provider"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    pathTool "github.com/deatil/lakego-doak/lakego/support/path"
    routerFacade "github.com/deatil/lakego-doak/lakego/facade/router"

    "github.com/deatil/lakego-doak/admin/support/url"
    "github.com/deatil/lakego-doak/admin/support/response"
    "github.com/deatil/lakego-doak/admin/support/http/code"

    // 中间件
    "github.com/deatil/lakego-doak/admin/middleware/recovery"
    "github.com/deatil/lakego-doak/admin/middleware/authorization"
    "github.com/deatil/lakego-doak/admin/middleware/cors"
    "github.com/deatil/lakego-doak/admin/middleware/permission"
    "github.com/deatil/lakego-doak/admin/middleware/actionlog"
    "github.com/deatil/lakego-doak/admin/middleware/admincheck"

    // 路由
    adminRoute "github.com/deatil/lakego-doak/admin/route"

    // 脚本
    "github.com/deatil/lakego-doak/admin/cmd"
)

// 全局中间件
var globalMiddlewares = []router.HandlerFunc{
    // 异常处理
    recovery.Handler(),

    // 跨域处理
    cors.Handler(),
}

// 路由中间件
var routeMiddlewares = map[string]router.HandlerFunc{
    // token 验证
    "lakego-admin.auth": authorization.Handler(),

    // 权限检测
    "lakego-admin.permission": permission.Handler(),

    // 操作日志
    "lakego-admin.action-log": actionlog.Handler(),

    // 超级管理员检测
    "lakego-admin.admin-check": admincheck.Handler(),
}

// 中间件分组
var middlewareGroups = map[string][]string{
    // 常规中间件
    "lakego-admin": {
        "lakego-admin.auth",
        "lakego-admin.permission",
        "lakego-admin.action-log",
    },

    // 超级管理员检测
    "lakego-admin-check": {
        "lakego-admin.admin-check",
    },
}

/**
 * 服务提供者
 *
 * @create 2021-9-11
 * @author deatil
 */
type ServiceProvider struct {
    provider.ServiceProvider
}

// 注册
func (this *ServiceProvider) Register() {
    // 脚本
    this.loadCommand()

    // 路由
    this.loadRoute()

    // 推送配置
    this.publishConfig()
}

/**
 * 导入脚本
 */
func (this *ServiceProvider) loadCommand() {
    // 安装
    this.AddCommand(cmd.InstallCmd)

    // 重设权限
    this.AddCommand(cmd.ResetPermissionCmd)

    // 导入路由信息
    this.AddCommand(cmd.ImportRouteCmd)

    // 强制将 jwt 的 refreshToken 放入黑名单
    this.AddCommand(cmd.PassportLogoutCmd)

    // 重置密码
    this.AddCommand(cmd.ResetPasswordCmd)

    // 系统信息
    this.AddCommand(cmd.VersionCmd)
}

/**
 * 导入路由
 */
func (this *ServiceProvider) loadRoute() {
    this.AddRoute(func(engine *router.Engine) {
        // 中间件
        this.loadMiddleware()

        conf := config.New("admin")

        prefix := "/" + conf.GetString("Route.Prefix") + "/*"

        // 未知路由处理
        engine.NoRoute(func (ctx *router.Context) {
            if url.MatchPath(ctx, prefix, "") {
                response.Error(ctx, "未知路由", code.StatusInvalid)
            }
        })

        // 未知调用方式
        engine.NoMethod(func (ctx *router.Context) {
            if url.MatchPath(ctx, prefix, "") {
                response.Error(ctx, "访问错误", code.StatusInvalid)
            }
        })

        // 全局中间件
        engine.Use(globalMiddlewares...)

        // 中间件
        groupMiddlewares := routerFacade.GetMiddlewares(conf.GetString("Route.Middleware"))

        // 管理员中间件
        adminGroupMiddlewares := routerFacade.GetMiddlewares(conf.GetString("Route.AdminMiddleware"))

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
func (this *ServiceProvider) loadMiddleware() {
    m := routerFacade.NewMiddleware()

    // 导入中间件
    for name, value := range routeMiddlewares {
        m.AliasMiddleware(name, value)
    }

    // 导入中间件分组
    for groupName, middlewares := range middlewareGroups {
        for _, middleware := range middlewares {
            m.MiddlewareGroup(groupName, middleware)
        }
    }
}

/**
 * 推送配置
 */
func (this *ServiceProvider) publishConfig() {
    // 配置
    path := pathTool.FormatPath("{root}/pkg/lakego-doak/admin/resources/config/admin.yml")

    // 推送文件
    // > go run main.go lakego:publish --tag=admin-config --force
    toPath := pathTool.ConfigPath("/admin-dev.yml")
    this.Publishes(this, map[string]string{
        path: toPath,
    }, "admin-config")
}
