package bootstrap

import (
    "github.com/deatil/lakego-admin/lakego/kernel"

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
    kernel.New().
        WithServiceProviders(providers).
        Terminate()
}


