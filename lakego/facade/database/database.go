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
        // 注册可用驱动
        register.RegisterDrivers(map[string]func() interfaces.Driver {
            "mysql": func() interfaces.Driver {
                return &mysqlDriver.Mysql{}
            },
        })

        // 连接列表
        connections := config.New("database").GetStringMap("Connections")

        // mysql
        register.RegisterDatabase("mysql", func() interfaces.Database {
            mysqlConf := connections["mysql"].(map[string]interface{})
            mysqlType := mysqlConf["type"].(string)

            driver := register.GetDriver(mysqlType)
            if driver == nil {
                panic("数据库驱动 " + mysqlType + " 没有被注册")
            }

            driver.WithConfig(mysqlConf)

            d := database.New(driver, mysqlConf)

            return d
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

    // 拿取
    c := register.GetDatabase(name, once2)
    if c == nil {
        panic("数据库类型 " + name + " 没有被注册")
    }

    return c.GetConnection()
}

// 默认数据库
func GetDefaultDatabase() string {
    return config.New("database").GetString("Default")
}



