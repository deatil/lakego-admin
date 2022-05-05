package model

import (
    "encoding/json"
    "gorm.io/gorm"

    "github.com/deatil/lakego-doak/lakego/facade/database"
)

// 创建一个 db 连接
func NewDB() *gorm.DB {
    return database.New()
}

// 获取配置
func GetConfig(key string, typ ...string) any {
    conf, _ := database.GetConfig(key, typ...)

    return conf
}

// 格式化获取的数据为 map
func FormatStructToMap(data any) map[string]any {
    // 结构体转map
    tmp, _ := json.Marshal(&data)

    dataMap := make(map[string]any)
    json.Unmarshal(tmp, &dataMap)

    return dataMap
}

// 格式化获取的数据为 array_map
func FormatStructToArrayMap(data any) []map[string]any {
    tmp, _ := json.Marshal(&data)

    dataMap := make([]map[string]any, 0)
    json.Unmarshal(tmp, &dataMap)

    return dataMap
}

