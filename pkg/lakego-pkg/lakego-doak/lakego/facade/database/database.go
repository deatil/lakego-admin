package database

import (
    "strings"
    "gorm.io/gorm"

    "github.com/deatil/lakego-doak/lakego/register"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/database"
    "github.com/deatil/lakego-doak/lakego/database/interfaces"
    mysqlDriver "github.com/deatil/lakego-doak/lakego/database/driver/mysql"
)

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
    var o bool
    if len(once) > 0 {
        o = once[0]
    } else {
        o = true
    }

    database := GetDefaultDatabase()

    return Database(database, o)
}

// 实例化
func NewWithType(database string, once ...bool) *gorm.DB {
    return Database(database, once...)
}

// 选择数据库
func Database(name string, once ...bool) *gorm.DB {
    // 使用驱动类型
    driverType, driverConf := GetConfig("type", name)

    newDriverType := driverType.(string)

    // 驱动
    driver := register.
        NewManagerWithPrefix("database").
        GetRegister(newDriverType, driverConf, once...)
    if driver == nil {
        panic("数据库驱动[" + newDriverType + "]没有被注册")
    }

    d := database.New(driver.(interfaces.Driver), driverConf)

    debug := config.New("database").GetBool("debug")
    if debug {
        return d.GetConnectionWithDebug()
    }

    return d.GetConnection()
}

// 默认数据库
func GetDefaultDatabase() string {
    return config.New("database").GetString("default")
}

// 获取配置
func GetConfig(key string, typ ...string) (any, map[string]any) {
    // 连接列表
    connections := config.New("database").GetStringMap("connections")

    var name string
    if len(typ) > 0 {
        name = typ[0]
    } else {
        name = GetDefaultDatabase()
    }

    // 转为小写
    name = strings.ToLower(name)

    // 获取驱动配置
    driverConfig, ok := connections[name]
    if !ok {
        panic("数据库驱动[" + name + "]配置不存在")
    }

    // 配置
    driverConf := driverConfig.(map[string]any)

    if value, ok := driverConf[key]; ok {
        return value, driverConf
    }

    return nil, driverConf
}

// 注册
func Register() {
    // 注册驱动
    register.
        NewManagerWithPrefix("database").
        RegisterMany(map[string]func(map[string]any) any {
            "mysql": func(conf map[string]any) any {
                driver := mysqlDriver.New(conf)

                return driver
            },
        })
}

