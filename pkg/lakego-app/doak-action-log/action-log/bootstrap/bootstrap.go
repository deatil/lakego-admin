package bootstrap

import (
    "github.com/deatil/lakego-doak/lakego/kernel"

    "github.com/deatil/lakego-doak-action-log/action-log/provider"
)

// 添加服务提供者
func Boot() {
    kernel.AddProvider(func() any {
        return &provider.ActionLog{}
    })
}
