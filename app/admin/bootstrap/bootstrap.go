package bootstrap

import (
    "github.com/deatil/lakego-doak/lakego/kernel"

    admin_provider "app/admin/provider"
)

// 添加服务提供者
func init() {
    kernel.AddProvider(func() any {
        return &admin_provider.Index{}
    })
}
