package provider

import (
    "github.com/deatil/lakego-doak/lakego/provider"

    // 脚本
    "github.com/deatil/lakego-doak-devtool/devtool/cmd"
)

/**
 * 服务提供者
 *
 * @create 2022-2-14
 * @author deatil
 */
type Devtool struct {
    provider.ServiceProvider
}

// 引导
func (this *Devtool) Boot() {
    // 脚本
    this.loadCommand()
}

/**
 * 导入脚本
 */
func (this *Devtool) loadCommand() {
    // 脚手架
    this.AddCommand(cmd.AppAdminCmd)
}
