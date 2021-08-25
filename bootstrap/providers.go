package bootstrap

import (
    providerInterface "lakego-admin/lakego/provider/interfaces"
    adminProvider "lakego-admin/admin/provider/admin"
)

// 服务提供者
var providers = []func() providerInterface.ServiceProvider{
    // 后台服务
    func() providerInterface.ServiceProvider {
        return &adminProvider.ServiceProvider{}
    },
}

