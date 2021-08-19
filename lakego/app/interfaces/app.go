package interfaces

import (
    providerInterface "lakego-admin/lakego/provider/interfaces"
)

type App interface {
    // 注册服务提供者
    Register(func() providerInterface.ServiceProvider)
}
