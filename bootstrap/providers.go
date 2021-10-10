package bootstrap

import (
    providerInterface "github.com/deatil/lakego-admin/lakego/provider/interfaces"
    adminProvider "lakego-admin/admin/provider/admin"
)

// 服务提供者，设置其他 app 相关服务提供者
var providers = []func() providerInterface.ServiceProvider{
    // admin 后台
    func() providerInterface.ServiceProvider {
        return &adminProvider.ServiceProvider{}
    },
}

