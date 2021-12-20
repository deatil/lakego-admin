package bootstrap

import (
    "github.com/deatil/lakego-admin/lakego/kernel"

    // lakego-admin
    _ "github.com/deatil/lakego-admin/admin/bootstrap"

    // 例子，不用刻意注释该引入
    _ "app/example/bootstrap"
)

// 添加服务提供者
func AddProvider(f func() interface{}) {
    kernel.AddProvider(f)
}

// 执行
func Execute() {
    // 服务提供者文件夹
    providers := kernel.NewRegister().GetAll()

    // 运行
    kernel.New().
        WithServiceProviders(providers).
        Terminate()
}


