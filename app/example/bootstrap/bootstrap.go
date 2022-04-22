package bootstrap

import (
    "github.com/deatil/lakego-doak/lakego/kernel"

    "app/example/provider"
)

// 添加服务提供者
func init() {
    kernel.AddProvider(func() interface{} {
        return &provider.ExampleServiceProvider{}
    })
}
