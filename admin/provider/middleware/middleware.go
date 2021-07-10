package middleware

import (
    "github.com/gin-gonic/gin"
    "lakego-admin/lakego/http/route/middleware"
    "lakego-admin/admin/middleware/authorization"
    "lakego-admin/admin/middleware/cors"
    "lakego-admin/admin/middleware/event"
)

type MiddlewareProvider struct {
    Engine *gin.Engine
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
    
    // 跨域处理
    m.WithMiddleware("lakego.cors", cors.Cors())
    
    // token 验证
    m.WithMiddleware("lakego.auth", authorization.CheckTokenAuth())
    
    // 事件
    m.WithMiddleware("lakego.event", event.Event())
}

/**
 * 导入中间件分组
 */
func LoadGroup() {
    m := middleware.GetInstance()
    
    m.WithGroup("lakego-admin", "lakego.cors")
    m.WithGroup("lakego-admin", "lakego.auth")
    m.WithGroup("lakego-admin", "lakego.event")
}
