package interfaces

import (
    "gorm.io/gorm"
)

/**
 * 驱动接口
 *
 * @create 2021-9-15
 * @author deatil
 */
type Driver interface {
    // 设置配置
    WithConfig(map[string]interface{}) Driver

    // 获取配置
    GetConfig(string) interface{}

    // 连接
    GetConnection() *gorm.DB

    // 带debug连接
    GetConnectionWithDebug() *gorm.DB

    // 关闭
    Close()
}

