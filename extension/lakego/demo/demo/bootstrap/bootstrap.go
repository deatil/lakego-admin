package bootstrap

import (
    "github.com/deatil/lakego-doak/lakego/kernel"

    "extension/lakego/demo/demo/provider"
)

// 添加服务提供者
func init() {
    kernel.AddProvider(func() any {
        return &provider.Demo{}
    })
}
