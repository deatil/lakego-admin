package swagger

import (
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/provider"

    swaggerFiles "github.com/swaggo/files"
    ginSwagger "github.com/swaggo/gin-swagger"
)

/**
 * 服务提供者
 *
 * @create 2022-2-21
 * @author deatil
 */
type ServiceProvider struct {
    provider.ServiceProvider
}

// 引导
func (this *ServiceProvider) Boot() {
    // 路由
    this.loadRoute()
}

/**
 * 导入路由
 */
func (this *ServiceProvider) loadRoute() {
    // 常规 gin 路由
    this.AddRoute(func(engine *router.Engine) {
        engine.GET("/swagger/*any", ginSwagger.DisablingWrapHandler(swaggerFiles.Handler, "LAKEGO_ADMIN_SWAGGER_CLOSE"))
    })
}

