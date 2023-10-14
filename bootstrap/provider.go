package bootstrap

import (
    // lakego-admin 后台系统
    admin "github.com/deatil/lakego-doak-admin/admin/bootstrap"

    // 扩展管理
    extension "github.com/deatil/lakego-doak-extension/extension/bootstrap"

    // 操作日志
    action_log "github.com/deatil/lakego-doak-action-log/action-log/bootstrap"

    // 数据库管理
    database "github.com/deatil/lakego-doak-database/database/bootstrap"

    // 系统监控
    monitor "github.com/deatil/lakego-doak-monitor/monitor/bootstrap"

    // 开发工具
    devtool "github.com/deatil/lakego-doak-devtool/devtool/bootstrap"

    // 静态文件代理
    statics "github.com/deatil/lakego-doak-statics/statics/bootstrap"

    // API 文档
    _ "github.com/deatil/lakego-admin/swagger"
    swagger "github.com/deatil/lakego-doak-swagger/swagger/bootstrap"

    // admin 模块
    app_admin "app/admin/bootstrap"

    // 默认模块
    app_index "app/index/bootstrap"

    // app 例子
    app_example "app/example/bootstrap"

    // 扩展例子
    extension_demo "extension/lakego/demo/demo/bootstrap"
)

// 引入模块
func init() {
    // admin 系统相关模块
    admin.Boot()
    extension.Boot()
    action_log.Boot()
    database.Boot()
    monitor.Boot()
    devtool.Boot()

    // 其他模块
    statics.Boot()
    swagger.Boot()

    // app 模块
    app_admin.Boot()
    app_index.Boot()

    // app 例子，不用时可以注释该启用
    app_example.Boot()

    // 扩展例子，不用时可以注释该启用
    extension_demo.Boot()
}
