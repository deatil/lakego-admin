package bootstrap

import (
    "github.com/deatil/lakego-doak/lakego/kernel"

    index_provider "app/index/provider"
)

// 添加服务提供者
func Boot() {
    kernel.AddProvider(func() any {
        return &index_provider.Index{}
    })
}
