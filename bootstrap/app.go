package bootstrap

import (
    "lakego-admin/lakego/app"
    providerInterface "lakego-admin/lakego/provider/interfaces"
    adminProvider "lakego-admin/admin/provider/admin"
)


func Start() {
    app := app.New()

    // admin 后台路由
    adminServiceProvider := &adminProvider.ServiceProvider{}
    app.Register(func() providerInterface.ServiceProvider {
        return adminServiceProvider
    })

    app.Run()
}
