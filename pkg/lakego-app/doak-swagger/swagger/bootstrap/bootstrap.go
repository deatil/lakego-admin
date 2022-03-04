package bootstrap

import (
    "github.com/deatil/lakego-doak/lakego/kernel"

    serviceProvider "github.com/deatil/lakego-doak-swagger/swagger/provider/swagger"
)

// 例子
func init() {
    kernel.AddProvider(func() interface{} {
        return &serviceProvider.ServiceProvider{}
    })
}
