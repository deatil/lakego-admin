package facade

import (
    "github.com/deatil/lakego-doak/lakego/router"

    facade_view "github.com/deatil/lakego-doak/lakego/facade/view"
    facade_cache "github.com/deatil/lakego-doak/lakego/facade/cache"
    facade_logger "github.com/deatil/lakego-doak/lakego/facade/logger"
    facade_upload "github.com/deatil/lakego-doak/lakego/facade/upload"
    facade_storage "github.com/deatil/lakego-doak/lakego/facade/storage"
    facade_config "github.com/deatil/lakego-doak/lakego/facade/config"
    facade_captcha "github.com/deatil/lakego-doak/lakego/facade/captcha"
    facade_database "github.com/deatil/lakego-doak/lakego/facade/database"
    facade_permission "github.com/deatil/lakego-doak/lakego/facade/permission"
)

// 数据库
var DB = facade_database.Default

// 缓存
var Cache = facade_cache.Default

var (
    // 路由
    Route = router.DefaultRoute()

    // 中间件
    Middleware = router.DefaultMiddleware()

    // 别名信息
    RouteName = router.DefaultName()
)

// 日志
var Logger = facade_logger.Default

// 模板渲染
var ViewHtml = facade_view.New()

// 上传
var Upload = facade_upload.Default

var (
    // 文件操作
    Storage = facade_storage.Default

    // 文件操作
    NewStorageWithDisk = facade_storage.NewWithDisk
)

// 配置
var Config = facade_config.New

// 验证码
var Captcha = facade_captcha.Default

// 权限
var Permission = facade_permission.Default
