package database

import (
    "sync"
    "gorm.io/gorm"

    "lakego-admin/lakego/register"
    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/database"
    "lakego-admin/lakego/database/interfaces"
    mysqlDriver "lakego-admin/lakego/database/driver/mysql"
)

var once sync.Once

// 初始化
func init() {
    // 注册默认
    Register()
}

/**
 * 数据库
 *
 * @create 2021-7-11
 * @author deatil
 */
func New(once ...bool) *gorm.DB {
    var once2 bool
    if len(once) > 0 {
        once2 = once[0]
    } else {
        once2 = true
    }

    database := GetDefaultDatabase()

    return Database(database, once2)
}

// 实例化
func NewWithType(database string, once ...bool) *gorm.DB {
    return Database(database, once...)
}

// 选择数据库
func Database(name string, once ...bool) *gorm.DB {
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
    driver := register.NewManagerWithPrefix("database_").GetRegister(driverType, driverConf, once...)
    if driver == nil {
        panic("数据库驱动 " + driverType + " 没有被注册")
    }

    d := database.New(driver.(interfaces.Driver), driverConf)

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

// 获取配置
func GetConfig(key string, typ ...string) interface{} {
    // 连接列表
    connections := config.New("database").GetStringMap("Connections")

    var name string
    if len(typ) > 0 {
        name = typ[0]
    } else {
        name = GetDefaultDatabase()
    }

    // 获取驱动配置
    driverConfig, ok := connections[name]
    if !ok {
        panic("数据库驱动 " + name + " 配置不存在")
    }

    // 配置
    driverConf := driverConfig.(map[string]interface{})

    if value, ok := driverConf[key]; ok {
        return value
    }

    return nil
}

// 注册
func Register() {
    once.Do(func() {
        // 注册驱动
        register.NewManagerWithPrefix("database_").RegisterMany(map[string]func(map[string]interface{}) interface{} {
            "mysql": func(conf map[string]interface{}) interface{} {
                driver := &mysqlDriver.Mysql{}

                driver.WithConfig(conf)
                driver.CreateConnection()

                return driver
            },
        })
    })
}



