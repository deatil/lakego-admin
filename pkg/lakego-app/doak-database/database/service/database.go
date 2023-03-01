package service

import (
    "gorm.io/gorm"
    "github.com/deatil/go-goch/goch"

    "github.com/deatil/lakego-doak/lakego/facade"
)

// 创建一个 db 连接
func NewDB() *gorm.DB {
    return facade.DB
}

// 构造函数
func NewDatabase() Database {
    return Database{}
}

// DbVersion struct
type DbVersion struct {
    DbVersion string
}

// 数据库管理
type Database struct {}

// 获取mysql的版本
func (this Database) GetMysqlVersion() string {
    var dbVersion DbVersion

    err := NewDB().Raw("select VERSION() as db_version").Scan(&dbVersion)
    if err != nil {
        return "not found."
    }

    return dbVersion.DbVersion
}

// 获取所有数据表的状态
func (this Database) GetTableStatus() []map[string]string {
    var maps []map[string]any

    var resultMaps []map[string]string
    NewDB().Raw("SHOW TABLE STATUS").Scan(&maps)

    if len(maps) > 0 {
        for _, item := range maps {
            resultMaps = append(resultMaps, map[string]string{
                "name":        this.toString(item["Name"]),
                "comment":     this.toString(item["Comment"]),
                "engine":      this.toString(item["Engine"]),
                "collation":   this.toString(item["Collation"]),
                "data_length": this.toString(item["Data_length"]),
                "create_time": this.toString(item["Create_time"]),
                "update_time": this.toString(item["Update_time"]),
            })
        }
    }

    return resultMaps
}

// 优化数据表
func (this Database) OptimizeTable(tableName string) bool {
    err := NewDB().Exec("OPTIMIZE TABLE `" + tableName + "`").Error
    if err == nil {
        return true
    }

    return false
}

// 修复数据表
func (this Database) RepairTable(tableName string) bool {
    err := NewDB().Exec("REPAIR TABLE `" + tableName + "`").Error
    if err == nil {
        return true
    }

    return false
}

// 获取数据表的所有字段
func (this Database) GetFullColumnsFromTable(tableName string) []map[string]string {
    var maps []map[string]any

    var resultMaps []map[string]string
    NewDB().Raw("SHOW FULL COLUMNS FROM `" + tableName + "`").Scan(&maps)

    if len(maps) > 0 {
        for _, item := range maps {
            resultMaps = append(resultMaps, map[string]string{
                "name":       this.toString(item["Field"]),
                "type":       this.toString(item["Type"]),
                "collation":  this.toString(item["Collation"]),
                "null":       this.toString(item["Null"]),
                "key":        this.toString(item["Key"]),
                "default":    this.toString(item["Default"]),
                "extra":      this.toString(item["Extra"]),
                "privileges": this.toString(item["Privileges"]),
                "comment":    this.toString(item["Comment"]),
            })
        }
    }

    return resultMaps
}

// any 转换为 string
func (this Database) toString(val any) string {
    return goch.ToString(val)
}
