package route

import (
	"github.com/gin-gonic/gin"
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
	// 未知路由处理
	p.Engine.NoRoute(func (c *gin.Context) {
		response.Error(c, code.StatusInvalid, "未知路由")
	})
	
	// 未知调用方式
	p.Engine.NoMethod(func (c *gin.Context) {
		response.Error(c, code.StatusInvalid, "访问错误")
	})
	
	// 路由
	adminRoute.Dispatch(p.Engine)	
}

// 引导
func (p *RouteProvider) Boot() {
}

