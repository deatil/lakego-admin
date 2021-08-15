package admin

import (
    "github.com/gin-gonic/gin"
    "lakego-admin/lakego/lake"
    "lakego-admin/lakego/config"
    "lakego-admin/lakego/http/code"
    "lakego-admin/lakego/http/route"
    "lakego-admin/lakego/http/response"
    "lakego-admin/lakego/http/route/middleware"
    appInterface "lakego-admin/lakego/app/interfaces"

    // 中间件
    "lakego-admin/admin/middleware/exception"
    "lakego-admin/admin/middleware/authorization"
    "lakego-admin/admin/middleware/cors"
    "lakego-admin/admin/middleware/event"
    "lakego-admin/admin/middleware/permission"

    // 路由
    adminRoute "lakego-admin/admin/router"
)

type ServiceProvider struct {
    App appInterface.App
    Engine *gin.Engine
}

// 路由中间件
var routeMiddlewares map[string]gin.HandlerFunc = map[string]gin.HandlerFunc{
    // 异常处理
    "lakego.exception": exception.Handler(),

    // 事件
    "lakego.event": event.Handler(),

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
        "lakego.event",
        "lakego.cors",
        "lakego.auth",
        "lakego.permission",
    },
}

// 注册
func (s *ServiceProvider) WithApp(app interface{}) {
    s.App = app.(appInterface.App)
}

// 注册
func (s *ServiceProvider) WithRoute(engine *gin.Engine) {
    s.Engine = engine
}

// 注册
func (s *ServiceProvider) Register() {
    // 中间件
    s.loadMiddleware()

    // 分组
    s.loadGroup()

    // 路由
    s.loadRoute()
}

// 引导
func (s *ServiceProvider) Boot() {
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
    s.Engine.NoRoute(func (ctx *gin.Context) {
        if lake.MatchPath(ctx, prefix, "") {
            response.Error(ctx, "未知路由", code.StatusInvalid)
        }
    })

    // 未知调用方式
    s.Engine.NoMethod(func (ctx *gin.Context) {
        if lake.MatchPath(ctx, prefix, "") {
            response.Error(ctx, "访问错误", code.StatusInvalid)
        }
    })

    // 后台路由及设置中间件
    m := route.GetMiddlewares(conf.GetString("Route.Middleware"))

    // 路由
    admin := s.Engine.Group(conf.GetString("Route.Group"))
    {
        admin.Use(m...)
        {
            adminRoute.Route(admin)
        }
    }
}

