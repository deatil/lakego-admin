package provider

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-doak/lakego/provider"

    // 路由
    index_route "app/index/route"
)

/**
 * 服务提供者
 *
 * @create 2022-9-3
 * @author deatil
 */
type Index struct {
    provider.ServiceProvider
}

// 引导
func (this *Index) Boot() {
    // 路由
    this.loadRoute()
}

/**
 * 导入路由
 */
func (this *Index) loadRoute() {
    // 常规 gin 路由，除 gin 自带外没有任何中间件
    this.AddRoute(func(engine *gin.Engine) {
        index_route.Route(engine)
    })
}

