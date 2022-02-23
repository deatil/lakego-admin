package bootstrap

import (
    "github.com/deatil/lakego-doak/lakego/kernel"

    serviceProvider "github.com/deatil/lakego-doak/action-log/provider/app"
)

// 例子
func init() {
    kernel.AddProvider(func() interface{} {
        return &serviceProvider.ServiceProvider{}
    })
}
