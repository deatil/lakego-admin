package database

import (
    "gorm.io/gorm"
    "lakego-admin/lakego/database/interfaces"
)

/**
 * 单例模式
 */
func New(driver interfaces.Driver, conf ...map[string]interface{}) *Database {
    d := &Database{
        driver: driver,
    }

    if len(conf) > 0{
        d.config = conf[0]
    }

    return d
}

type Database struct {
    config map[string]interface{}
    driver interfaces.Driver
}

// 设置配置
func (db *Database) WithConfig(config map[string]interface{}) interfaces.Database {
    db.config = config

    return db
}

// 获取配置
func (db *Database) GetConfig(name string) interface{} {
    if data, ok := db.config[name]; ok {
        return data
    }

    return nil
}

/**
 * 设置驱动
 */
func (db *Database) WithDriver(driver interfaces.Driver) interfaces.Database {
    db.driver = driver

    return db
}

/**
 * 获取驱动
 */
func (db *Database) GetDriver() interfaces.Driver {
    return db.driver
}

/**
 * 获取数据库连接对象db
 */
func (db *Database) GetConnection() *gorm.DB {
    return db.driver.GetConnection()
}

/**
 * 获取数据库连接对象db，带debug
 */
func (db *Database) GetConnectionWithDebug() *gorm.DB {
    return db.driver.GetConnectionWithDebug()
}

/**
 * 关闭连接
 */
func (db *Database) Close() {
    db.driver.Close()
}
