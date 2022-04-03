package database

import (
    "gorm.io/gorm"
    "github.com/deatil/lakego-doak/lakego/database/interfaces"
)

/**
 * 使用
 */
func New(driver interfaces.Driver, conf ...ConfigMap) *Database {
    d := &Database{
        driver: driver,
    }

    if len(conf) > 0{
        d.config = conf[0]
    }

    return d
}

type (
    // 配置 map
    ConfigMap = map[string]interface{}
)

/**
 * 数据库
 *
 * @create 2021-9-15
 * @author deatil
 */
type Database struct {
    // 配置
    config ConfigMap

    // 驱动
    driver interfaces.Driver
}

// 设置配置
func (this *Database) WithConfig(config ConfigMap) interfaces.Database {
    this.config = config

    return this
}

// 获取配置
func (this *Database) GetConfig(name string) interface{} {
    if data, ok := this.config[name]; ok {
        return data
    }

    return nil
}

/**
 * 设置驱动
 */
func (this *Database) WithDriver(driver interfaces.Driver) interfaces.Database {
    this.driver = driver

    return this
}

/**
 * 获取驱动
 */
func (this *Database) GetDriver() interfaces.Driver {
    return this.driver
}

/**
 * 获取数据库连接对象db
 */
func (this *Database) GetConnection() *gorm.DB {
    return this.driver.GetConnection()
}

/**
 * 获取数据库连接对象db，带debug
 */
func (this *Database) GetConnectionWithDebug() *gorm.DB {
    return this.driver.GetConnectionWithDebug()
}

/**
 * 关闭连接
 */
func (this *Database) Close() {
    this.driver.Close()
}
