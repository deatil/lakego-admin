package service_provider

import (
    "github.com/deatil/lakego-doak/lakego/provider"

    // 脚本
    publishCmd "github.com/deatil/lakego-doak/lakego/console/publish"
    storageCmd "github.com/deatil/lakego-doak/lakego/console/storage"

    // 视图
    "github.com/deatil/lakego-doak/lakego/facade/view"
)

// 构造函数
func NewLakego() *Lakego {
    return &Lakego{}
}

/**
 * 服务提供者
 *
 * @create 2022-1-4
 * @author deatil
 */
type Lakego struct {
    provider.ServiceProvider
}

// 引导
func (this *Lakego) Boot() {
    // 脚本
    this.loadCommand()

    // 模板渲染
    this.loadHtmlRender()
}

/**
 * 导入脚本
 */
func (this *Lakego) loadCommand() {
    // 推送
    this.AddCommand(publishCmd.PublishCmd)

    // 创建软连接
    this.AddCommand(storageCmd.StorageLinkCmd)
}

/**
 * 导入模板渲染
 */
func (this *Lakego) loadHtmlRender() {
    this.GetRoute().HTMLRender = view.New().GetRender()
}
