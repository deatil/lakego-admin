package route

import (
    "github.com/gin-gonic/gin"
    "lakego-admin/lakego/lake"
    "lakego-admin/lakego/config"
    "lakego-admin/lakego/http/code"
    "lakego-admin/lakego/http/response"
    adminRoute "lakego-admin/admin/router"
)

type RouteProvider struct {
    Engine *gin.Engine
}

// 注册
func (p *RouteProvider) WithRoute(engine *gin.Engine) {
    p.Engine = engine
}

// 注册
func (p *RouteProvider) Register() {
    prefix := "/" + config.New("admin").GetString("Route.Group") + "/*"

    // 未知路由处理
    p.Engine.NoRoute(func (ctx *gin.Context) {
        if lake.MatchPath(ctx, prefix, "") {
            response.Error(ctx, code.StatusInvalid, "未知路由")
        }
    })

    // 未知调用方式
    p.Engine.NoMethod(func (ctx *gin.Context) {
        if lake.MatchPath(ctx, prefix, "") {
            response.Error(ctx, code.StatusInvalid, "访问错误")
        }
    })

    // 路由
    adminRoute.Dispatch(p.Engine)
}

// 引导
func (p *RouteProvider) Boot() {
}

