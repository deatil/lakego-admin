package bootstrap

import (
    "github.com/deatil/lakego-admin/lakego/kernel"

    providerInterface "github.com/deatil/lakego-admin/lakego/provider/interfaces"
)

// 服务提供者
var providers []func() providerInterface.ServiceProvider

// 添加服务提供者
func AddProvider(f func() interface{}) {
    addProvider := f()

    // 判断是否为服务提供者
    switch addProvider.(type) {
        case providerInterface.ServiceProvider:
            providers = append(providers, func() providerInterface.ServiceProvider {
                return addProvider.(providerInterface.ServiceProvider)
            })
    }
}

// 执行
func Execute() {
    kernel.New().
        WithServiceProviders(providers).
        Terminate()
}


