package bootstrap

import (
    "github.com/deatil/lakego-doak/lakego/kernel"

    "github.com/deatil/lakego-doak-admin/admin/provider"
)

// 添加服务提供者
func Boot() {
    kernel.AddProvider(func() any {
        return &provider.Admin{}
    })
}
