package bootstrap

import (
    "github.com/deatil/lakego-admin/lakego/kernel"

    lakegoProvider "github.com/deatil/lakego-admin/lakego/service/lakego"
)

// 后台
func init() {
    kernel.AddProvider(func() interface{} {
        return &lakegoProvider.ServiceProvider{}
    })
}
