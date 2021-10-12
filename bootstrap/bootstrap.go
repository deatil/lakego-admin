package bootstrap

import (
    "github.com/deatil/lakego-admin/lakego/app"

    providerInterface "github.com/deatil/lakego-admin/lakego/provider/interfaces"
)

// 服务提供者
var providers []func() providerInterface.ServiceProvider

// 添加服务提供者
func AddProvider(f func() interface{}) {
    providers = append(providers, func() providerInterface.ServiceProvider {
        addFunc := f()
        return addFunc.(providerInterface.ServiceProvider)
    })
}

// 执行
func Execute() {
    app.NewBootstrap().
        WithServiceProviders(providers).
        Execute()
}


