package bootstrap

import (
    // lakego-admin 后台系统
    _ "github.com/deatil/lakego-doak-admin/admin/bootstrap"

    // 操作日志
    _ "github.com/deatil/lakego-doak-action-log/action-log/bootstrap"

    // 数据库管理
    _ "github.com/deatil/lakego-doak-database/database/bootstrap"

    // API 文档
    _ "github.com/deatil/lakego-admin/docs/swagger"
    _ "github.com/deatil/lakego-doak-swagger/swagger/bootstrap"

    // 静态文件代理模块
    _ "github.com/deatil/lakego-doak-statics/statics/bootstrap"

    // 例子，不用时可以注释该引入
    _ "app/example/bootstrap"
)
