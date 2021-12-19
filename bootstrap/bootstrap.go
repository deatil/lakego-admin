package bootstrap

import (
    "github.com/deatil/lakego-admin/lakego/kernel"
    "github.com/deatil/lakego-admin/lakego/provider/interfaces"

    _ "lakego-admin/bootstrap/provider"
)

// 服务提供者
var providers []func() interfaces.ServiceProvider

// 添加服务提供者
func AddProvider(f func() interface{}) {
    addProvider := f()

    // 判断是否为服务提供者
    switch addProvider.(type) {
        case interfaces.ServiceProvider:
            providers = append(providers, func() interfaces.ServiceProvider {
                return addProvider.(interfaces.ServiceProvider)
            })
    }
}

// 执行
func Execute() {
    // 服务提供者文件夹
    userProviders := kernel.NewRegister().GetALL()

    // 运行
    kernel.New().
        WithServiceProviders(userProviders).
        WithServiceProviders(providers).
        Terminate()
}


