package bootstrap

import (
    "github.com/deatil/lakego-doak/lakego/kernel"
)

// 添加服务提供者
func AddProvider(f func() any) {
    kernel.AddProvider(f)
}

// 执行
func Execute() {
    // 服务提供者文件夹
    providers := kernel.GetAllProvider()

    // 运行
    kernel.New().
        LoadDefaultServiceProvider().
        WithServiceProviders(providers).
        Terminate()
}


