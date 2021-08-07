package register

import(
    "lakego-admin/lakego/cache/interfaces"
    driverRegister "lakego-admin/lakego/cache/register/driver"
    cacheRegister "lakego-admin/lakego/cache/register/cache"
)

/**
 * 注册驱动
 */
func RegisterDriver(name string, f func() interfaces.Driver) {
    driverRegister.New().With(name, f)
}

/**
 * 获取已注册驱动
 */
func GetDriver(name string) interfaces.Driver {
    return driverRegister.New().Get(name)
}

/**
 * 注册缓存
 */
func RegisterCache(name string, f func() interfaces.Cache) {
    cacheRegister.New().With(name, f)
}

/**
 * 获取已注册缓存
 */
func GetCache(name string) interfaces.Cache {
    return cacheRegister.New().Get(name)
}
