package bootstrap

import (
    "github.com/deatil/lakego-doak/lakego/kernel"

    adminProvider "github.com/deatil/lakego-doak-admin/admin/provider/admin"
)

// 后台
func init() {
    kernel.AddProvider(func() interface{} {
        return &adminProvider.ServiceProvider{}
    })
}
