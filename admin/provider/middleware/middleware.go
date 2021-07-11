package middleware

import (
    "github.com/gin-gonic/gin"
    "lakego-admin/lakego/http/route/middleware"
    "lakego-admin/admin/middleware/authorization"
    "lakego-admin/admin/middleware/cors"
    "lakego-admin/admin/middleware/event"
    "lakego-admin/admin/middleware/permission"
)

type MiddlewareProvider struct {
    Engine *gin.Engine
}

// 路由中间件
var routeMiddleware map[string]gin.HandlerFunc = map[string]gin.HandlerFunc{
    // 事件
    "lakego.event": event.Event(),
    // 跨域处理
    "lakego.cors": cors.Cors(),
    // token 验证
    "lakego.auth": authorization.CheckTokenAuth(),
    // 权限检测
    "lakego.permission": permission.Permission(),
}

// 中间件分组
var middlewareGroups map[string]interface{} = map[string]interface{}{
    "lakego-admin": []string{
        "lakego.event",
        "lakego.cors",
        "lakego.auth",
        "lakego.permission",
    },
}

// 注册
func (mp *MiddlewareProvider) WithRoute(engine *gin.Engine) {
    mp.Engine = engine
}

// 注册
func (mp *MiddlewareProvider) Register() {
    // 中间件
    LoadMiddleware()

    // 分组
    LoadGroup()
}

// 引导
func (mp *MiddlewareProvider) Boot() {
}

/**
 * 导入中间件
 */
func LoadMiddleware() {
    m := middleware.GetInstance()

    for name, value := range routeMiddleware {
        m.WithMiddleware(name, value)
    }
}

/**
 * 导入中间件分组
 */
func LoadGroup() {
    m := middleware.GetInstance()

    for name, value := range middlewareGroups {
        for _, group := range value.([]string) {
            m.WithGroup(name, group)
        }
    }
}
