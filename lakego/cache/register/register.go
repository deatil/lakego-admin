package register

import(
    "lakego-admin/lakego/register"
    "lakego-admin/lakego/cache/interfaces"
)

// 驱动前缀
var driverPrefix = "cache_driver_"

// 缓存前缀
var cachePrefix = "cache_cache_"

/**
 * 注册驱动
 */
func RegisterDriver(name string, f func() interfaces.Driver) {
    name = driverPrefix + name

    register.New().With(name, f)
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
        newData := data.(func() interfaces.Driver)

        return newData()
    }

    return nil
}

/**
 * 注册缓存
 */
func RegisterCache(name string, f func() interfaces.Cache) {
    name = cachePrefix + name

    register.New().With(name, f)
}

/**
 * 批量注册缓存
 */
func RegisterCaches(caches map[string]func() interfaces.Cache) {
    for name, f := range caches {
        RegisterCache(name, f)
    }
}

/**
 * 获取已注册缓存
 */
func GetCache(name string, once ...bool) interfaces.Cache {
    name = cachePrefix + name

    data := register.New().Get(name, once...)
    if data != nil {
        newData := data.(func() interfaces.Cache)

        return newData()
    }

    return nil
}
