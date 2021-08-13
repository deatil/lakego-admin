package register

import(
    "lakego-admin/lakego/register"
    "lakego-admin/lakego/database/interfaces"
)

// 驱动前缀
var driverPrefix = "database_driver_"

// 数据库前缀
var databasePrefix = "database_database_"

/**
 * 注册驱动
 */
func RegisterDriver(name string, f func() interfaces.Driver) {
    name = driverPrefix + name

    register.New().With(name, func() interface{} {
        return f()
    })
}

/**
 * 批量注册驱动
 */
func RegisterDrivers(drivers map[string]func() interfaces.Driver) {
    for name, f := range drivers {
        RegisterDriver(name, f)
    }
}

/**
 * 获取已注册驱动
 */
func GetDriver(name string, once ...bool) interfaces.Driver {
    name = driverPrefix + name

    data := register.New().Get(name, once...)
    if data != nil {
        return data.(interfaces.Driver)
    }

    return nil
}

/**
 * 注册数据库
 */
func RegisterDatabase(name string, f func() interfaces.Database) {
    name = databasePrefix + name

    register.New().With(name, func() interface{} {
        return f()
    })
}

/**
 * 批量注册驱动
 */
func RegisterDatabases(databases map[string]func() interfaces.Database) {
    for name, f := range databases {
        RegisterDatabase(name, f)
    }
}

/**
 * 获取已注册数据库
 */
func GetDatabase(name string, once ...bool) interfaces.Database {
    name = databasePrefix + name

    data := register.New().Get(name, once...)
    if data != nil {
        return data.(interfaces.Database)
    }

    return nil
}
