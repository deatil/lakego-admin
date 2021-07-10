package database

import (
    "sync"
    
    "gorm.io/gorm"

    "lakego-admin/lakego/database/config"
    "lakego-admin/lakego/database/driver"
)

var instance *DatabasePool
var once sync.Once

type DatabasePool struct {
    DB *gorm.DB
}

/**
 * 单例模式
 */
func GetPoolInstance() *DatabasePool {
    once.Do(func() {
        instance = &DatabasePool{}
    })

    return instance
}

/**
 * 初始化
 */
func (pool *DatabasePool) InitPool() {
    typeName := config.GetConnectionType()

    pool.DB = ConnectionFromType(typeName)
}

/**
 * 获取数据库连接对象db
 */
func (pool *DatabasePool) GetPoolDB() *gorm.DB {
    return pool.DB
}

/**
 * 对外获取数据库连接对象 DB
 */
func GetDB() *gorm.DB {
    return GetPoolInstance().GetPoolDB()
}

/**
 * 根据 type 创建链接
 */
func ConnectionFromType(typeName string) (dbConnection *gorm.DB) {
    driverType := config.New(typeName).GetString("Type")
    
    if driverType == "mysql" {
        dbConnection = driver.GetMysqlConnection(typeName)
    } else {
        dbConnection = driver.GetMysqlConnection(typeName)
    }
    
    return dbConnection
}
