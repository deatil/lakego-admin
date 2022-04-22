package bootstrap

import (
    "github.com/deatil/lakego-doak/lakego/kernel"

    "github.com/deatil/lakego-doak-swagger/swagger/provider"
)

// 添加服务提供者
func init() {
    kernel.AddProvider(func() interface{} {
        return &provider.SwaggerServiceProvider{}
    })
}
