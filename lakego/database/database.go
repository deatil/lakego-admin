package database

import (
    "gorm.io/gorm"
    "lakego-admin/lakego/database/driver/mysql"
)

type Config struct {
    Default string
    Debug string
    Connections map[string]interface{}
}

type Database struct {
    Config Config
    DB *gorm.DB
}

/**
 * 单例模式
 */
func New() *Database {
    return &Database{}
}

/**
 * 连接
 */
func (db *Database) Connection(config Config) {
    db.Config = config

    defaultType := config.Default
    db.DB = db.ConnectionFromType(defaultType)
}

/**
 * 获取数据库连接对象db
 */
func (db *Database) GetDB() *gorm.DB {
    return db.DB
}

/**
 * 根据 type 创建链接
 */
func (db *Database) ConnectionFromType(typeName string) (dbConnection *gorm.DB) {
    connections := db.Config.Connections

    debug := db.Config.Debug
    conf := connections[typeName].(map[string]interface{})

    driverType := conf["type"].(string)
    if driverType == "mysql" {
        dbConnection = mysql.New(conf).WithDebug(debug).GetConnection()
    } else {
        dbConnection = mysql.New(conf).WithDebug(debug).GetConnection()
    }

    return dbConnection
}
