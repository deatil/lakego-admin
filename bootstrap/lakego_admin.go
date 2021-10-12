package bootstrap

import (
    adminProvider "github.com/deatil/lakego-admin/admin/provider/admin"
)

// 后台
func init() {
    AddProvider(func() interface{} {
        return &adminProvider.ServiceProvider{}
    })
}
