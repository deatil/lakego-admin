package provider

import (
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/provider"
)

/**
 * 服务提供者
 *
 * @create 2022-4-17
 * @author deatil
 */
type Statics struct {
    provider.ServiceProvider
}

// 引导
func (this *Statics) Boot() {
    // 路由
    this.loadRoute()
}

/**
 * 导入路由
 */
func (this *Statics) loadRoute() {
    // 静态文件代理路由
    this.AddRoute(func(engine *router.Engine) {
        engine.Static("/storage", "./public/storage")
    })
}

