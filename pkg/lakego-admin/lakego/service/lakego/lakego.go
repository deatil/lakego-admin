package lakego

import (
    "github.com/deatil/lakego-admin/lakego/route"
    "github.com/deatil/lakego-admin/lakego/provider"

    // 脚本
    publishCmd "github.com/deatil/lakego-admin/lakego/console/publish"
    storageCmd "github.com/deatil/lakego-admin/lakego/console/storage"

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

    // 模板渲染
    this.loadHtmlRender()
}

/**
 * 导入脚本
 */
func (this *ServiceProvider) loadCommand() {
    // 推送
    this.AddCommand(publishCmd.PublishCmd)

    // 创建软连接
    this.AddCommand(storageCmd.StorageLinkCmd)
}

/**
 * 导入模板渲染
 */
func (this *ServiceProvider) loadHtmlRender() {
    route.New().Get().HTMLRender = view.New().GetRender()
}
