package lakego

import (
    "github.com/deatil/lakego-admin/lakego/provider"

    // 脚本
    "github.com/deatil/lakego-admin/lakego/console"
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
