package bootstrap

import (
    // 框架服务提供者
    _ "github.com/deatil/lakego-admin/lakego/bootstrap"

    // lakego-admin 后台系统
    _ "github.com/deatil/lakego-admin/admin/bootstrap"

    // 例子，不用时可以注释该引入
    _ "app/example/bootstrap"
)
