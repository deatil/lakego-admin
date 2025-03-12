package provider

import (
    "os"
    "fmt"

    "github.com/deatil/go-events/events"
    "github.com/deatil/go-datebin/datebin"
    "github.com/deatil/lakego-filesystem/filesystem"
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/provider"
    "github.com/deatil/lakego-doak/lakego/facade"
    path_tool "github.com/deatil/lakego-doak/lakego/path"

    "github.com/deatil/lakego-doak-admin/admin/support/url"
    "github.com/deatil/lakego-doak-admin/admin/support/time"
    "github.com/deatil/lakego-doak-admin/admin/support/response"
    "github.com/deatil/lakego-doak-admin/admin/support/http/code"

    // 中间件
    "github.com/deatil/lakego-doak-admin/admin/middleware/recovery"
    "github.com/deatil/lakego-doak-admin/admin/middleware/authorization"
    "github.com/deatil/lakego-doak-admin/admin/middleware/cors"
    "github.com/deatil/lakego-doak-admin/admin/middleware/permission"
    "github.com/deatil/lakego-doak-admin/admin/middleware/admincheck"

    // 路由
    admin_route "github.com/deatil/lakego-doak-admin/admin/route"

    // 脚本
    "github.com/deatil/lakego-doak-admin/admin/cmd"

    // 事件
    "github.com/deatil/lakego-doak-admin/admin/listener"
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

    // 超级管理员检测
    "lakego-admin.admin-check": admincheck.Handler(),
}

// 中间件分组
var middlewareGroups = map[string][]string{
    // 常规中间件
    "lakego-admin": {
        "lakego-admin.auth",
        "lakego-admin.permission",
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
type Admin struct {
    provider.ServiceProvider
}

// 引导
func (this *Admin) Boot() {
    // 设置时区
    this.initTimezone()

    // 脚本
    this.loadCommand()

    // 路由
    this.loadRoute()

    // 推送配置
    this.publishConfig()

    // 记录 pid 信息
    this.putSock()

    // 注册事件
    this.loadEvents()
}

// 设置时区
func (this *Admin) initTimezone() {
    tz := facade.Config("admin").GetString("timezone")

    time.SetTimezone(tz)

    // 全局设置时区
    datebin.SetTimezone(tz)
}

// 导入脚本
func (this *Admin) loadCommand() {
    // 安装
    this.AddCommand(cmd.InstallCmd)

    // 重设权限
    this.AddCommand(cmd.ResetPermissionCmd)

    // 导入路由信息
    this.AddCommand(cmd.ImportRouteCmd)

    // 导入 api 路由信息
    this.AddCommand(cmd.ImportApiRouteCmd)

    // 强制将 jwt 的 refreshToken 放入黑名单
    this.AddCommand(cmd.PassportLogoutCmd)

    // 重置密码
    this.AddCommand(cmd.ResetPasswordCmd)

    // 系统信息
    this.AddCommand(cmd.VersionCmd)

    // 停止 admin 系统服务
    this.AddCommand(cmd.StopCmd)
}

// 导入路由
func (this *Admin) loadRoute() {
    this.AddRoute(func(engine *router.Engine) {
        // 中间件
        this.loadMiddleware()

        conf := facade.Config("admin")

        prefix := "/" + conf.GetString("route.prefix") + "/*"

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

        // 路由
        admin := router.Group(engine, conf.GetString("route.prefix"), conf.GetString("route.middleware"))
        {
            // 常规路由
            admin_route.Route(admin)

            // 需要管理员权限
            router.Use(admin, conf.GetString("route.admin-middleware"))
            {
                admin_route.AdminRoute(admin)
            }
        }

    })
}

// 导入中间件
func (this *Admin) loadMiddleware() {
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

// 推送配置
func (this *Admin) publishConfig() {
    // 配置
    path := path_tool.FormatPath("{root}/pkg/lakego-app/doak-admin/resources/config/admin.yml")

    // 推送文件
    // > go run main.go lakego:publish --tag=admin-config --force
    toPath := path_tool.ConfigPath("/admin-dev.yml")
    this.Publishes(this, map[string]string{
        path: toPath,
    }, "admin-config")
}

// 记录 pid 信息
func (this *Admin) putSock() {
    pidPath := facade.Config("admin").GetString("pid-path")
    file := path_tool.FormatPath(pidPath)

    contents := fmt.Sprintf("%d,%d", os.Getppid(), os.Getpid())
    filesystem.New().Put(file, []byte(contents))
}

// 注册事件
func (this *Admin) loadEvents() {
    // 登录相关
    events.AddAction("admin.passport-login.make-accesstoken-fail", &listener.PassportLoginError{}, events.DefaultSort)
    events.AddAction("admin.passport-login.make-refreshtoken-fail", &listener.PassportLoginError{}, events.DefaultSort)
    events.AddAction("admin.passport-refreshtoken.make-accesstoken-fail", &listener.PassportLoginError{}, events.DefaultSort)
}
