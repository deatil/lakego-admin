package facade

import (
    "gorm.io/gorm"
    "github.com/deatil/lakego-doak/lakego/cache"
    "github.com/deatil/lakego-doak/lakego/config"
    "github.com/deatil/lakego-doak/lakego/logger"
    "github.com/deatil/lakego-doak/lakego/upload"
    "github.com/deatil/lakego-doak/lakego/storage"
    "github.com/deatil/lakego-doak/lakego/captcha"
    "github.com/deatil/lakego-doak/lakego/permission"

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
var DB *gorm.DB

// 缓存
var Cache *cache.Cache

// 日志
var Logger *logger.Logger

// 上传
var Upload *upload.Upload

// 文件操作
var Storage *storage.Storage

// 配置
var Config func(string) *config.Config

// 验证码
var Captcha *captcha.Captcha

// 权限
var Permission *permission.Permission

// 初始化
func init() {
    // 数据库
    DB = facade_database.Default

    // 缓存
    Cache = facade_cache.Default

    // 日志
    Logger = facade_logger.Default

    // 上传
    Upload = facade_upload.Default

    // 文件操作
    Storage = facade_storage.Default

    // 配置
    Config = facade_config.New

    // 验证码
    Captcha = facade_captcha.Default

    // 权限
    Permission = facade_permission.Default
}
