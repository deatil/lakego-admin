package interfaces

import (
    "gorm.io/gorm"
)

/**
 * 数据库接口
 *
 * @create 2021-9-15
 * @author deatil
 */
type Database interface {
    // 设置配置
    WithConfig(map[string]interface{}) Database

    // 获取配置
    GetConfig(string) interface{}

    // 设置驱动
    WithDriver(Driver) Database

    // 获取驱动
    GetDriver() Driver

    // 连接
    GetConnection() *gorm.DB

    // 使用 debug 连接
    GetConnectionWithDebug() *gorm.DB

    // 关闭
    Close()
}

