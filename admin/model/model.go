package model

import (
    "encoding/json"
    "gorm.io/gorm"

    "lakego-admin/lakego/facade/database"
)

// 创建一个 db 连接
func NewDB() *gorm.DB {
    return database.New()
}

// 获取配置
func GetConfig(key string, typ ...string) interface{} {
    return database.GetConfig(key, typ...)
}

// 格式化获取的数据为 map
func FormatStructToMap(data interface{}) map[string]interface{} {
    // 结构体转map
    tmp, _ := json.Marshal(&data)
    dataMap := make(map[string]interface{})
    json.Unmarshal(tmp, &dataMap)

    return dataMap
}

