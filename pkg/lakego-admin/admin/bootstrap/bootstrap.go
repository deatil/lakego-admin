package bootstrap

import (
    "github.com/deatil/lakego-admin/lakego/kernel"

    adminProvider "github.com/deatil/lakego-admin/admin/provider/admin"
)

// 后台
func init() {
    kernel.AddProvider(func() interface{} {
        return &adminProvider.ServiceProvider{}
    })
}
