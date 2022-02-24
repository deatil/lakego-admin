package bootstrap

import (
    // lakego-admin 后台系统
    _ "github.com/deatil/lakego-doak-admin/admin/bootstrap"

    // 操作日志
    _ "github.com/deatil/lakego-doak-action-log/action-log/bootstrap"

    // 例子，不用时可以注释该引入
    _ "app/example/bootstrap"
)
