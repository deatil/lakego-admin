package bootstrap

import (
    "github.com/deatil/lakego-doak/lakego/kernel"

    "github.com/deatil/lakego-doak-database/database/provider"
)

// 添加服务提供者
func init() {
    kernel.AddProvider(func() any {
        return &provider.Database{}
    })
}
