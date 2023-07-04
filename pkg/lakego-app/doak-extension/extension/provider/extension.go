package provider

import (
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/provider"

    admin_route "github.com/deatil/lakego-doak-admin/admin/support/route"

    "github.com/deatil/lakego-doak-extension/extension/extension"
    ext_cmd "github.com/deatil/lakego-doak-extension/extension/cmd"
    ext_router "github.com/deatil/lakego-doak-extension/extension/route"
)

/**
 * 服务提供者
 *
 * @create 2023-4-19
 * @author deatil
 */
type Extension struct {
    provider.ServiceProvider
}

// 注册
func (this *Extension) Register() {
    // Register
}

// 引导
func (this *Extension) Boot() {
    // 脚本
    this.loadCommand()

    // 路由
    this.loadRoute()

    // 加载扩展
    this.loadExtension()
}

// 导入脚本
func (this *Extension) loadCommand() {
    // 扩展管理
    this.AddCommand(ext_cmd.ExtensionCmd)
}

// 导入路由
func (this *Extension) loadRoute() {
    // 后台路由
    admin_route.AddRoute(func(engine *router.RouterGroup) {
        ext_router.Route(engine)
    })
}

// 导入扩展
func (this *Extension) loadExtension() {
    m := extension.GetManager()

    m.CallBooting()

    // 加载扩展
    m.BootExtension(this.GetApp())

    m.CallBooted()
}

