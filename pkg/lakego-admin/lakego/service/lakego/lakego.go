package lakego

import (
    "github.com/deatil/lakego-admin/lakego/route"
    "github.com/deatil/lakego-admin/lakego/provider"

    // 脚本
    "github.com/deatil/lakego-admin/lakego/console"

    // 视图
    "github.com/deatil/lakego-admin/lakego/facade/view"
)

/**
 * 服务提供者
 *
 * @create 2022-1-4
 * @author deatil
 */
type ServiceProvider struct {
    provider.ServiceProvider
}

// 注册
func (this *ServiceProvider) Register() {
    // 脚本
    this.loadCommand()
}

/**
 * 导入脚本
 */
func (this *ServiceProvider) loadCommand() {
    // 推送
    this.AddCommand(console.PublishCmd)
}

/**
 * 导入模板渲染
 */
func (this *ServiceProvider) loadRender() {
    route.New().Get().HTMLRender = view.New().GetRender()
}
