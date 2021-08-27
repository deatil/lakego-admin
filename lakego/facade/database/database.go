package database

import (
    "sync"
    "gorm.io/gorm"

    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/database"
    "lakego-admin/lakego/database/interfaces"
    "lakego-admin/lakego/database/register"
    mysqlDriver "lakego-admin/lakego/database/driver/mysql"
)

var once sync.Once

/**
 * 数据库
 *
 * @create 2021-7-11
 * @author deatil
 */
func New(once ...bool) *gorm.DB {
    database := GetDefaultDatabase()

    return Database(database, once...)
}

// 实例化
func NewWithType(database string, once ...bool) *gorm.DB {
    return Database(database, once...)
}

// 注册
func Register() {
    once.Do(func() {
        // 注册驱动
        register.RegisterDrivers(map[string]func(map[string]interface{}) interfaces.Driver {
            "mysql": func(conf map[string]interface{}) interfaces.Driver {
                driver := &mysqlDriver.Mysql{}

                driver.WithConfig(conf)

                return driver
            },
        })
    })
}

// 选择数据库
func Database(name string, once ...bool) *gorm.DB {
    // 注册默认
    Register()

    var once2 bool
    if len(once) > 0 {
        once2 = once[0]
    } else {
        once2 = true
    }

    // 连接列表
    connections := config.New("database").GetStringMap("Connections")

    // 获取驱动配置
    driverConfig, ok := connections[name]
    if !ok {
        panic("数据库驱动 " + name + " 配置不存在")
    }

    // 配置
    driverConf := driverConfig.(map[string]interface{})

    driverType := driverConf["type"].(string)
    driver := register.GetDriver(driverType, driverConf, once2)
    if driver == nil {
        panic("数据库驱动 " + driverType + " 没有被注册")
    }

    d := database.New(driver, driverConf)

    debug := config.New("database").GetBool("Debug")
    if debug {
        return d.GetConnectionWithDebug()
    }

    return d.GetConnection()
}

// 默认数据库
func GetDefaultDatabase() string {
    return config.New("database").GetString("Default")
}



