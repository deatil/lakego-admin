package cache

import (
    "sync"

    "lakego-admin/lakego/register"
    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/cache"
    "lakego-admin/lakego/cache/interfaces"
    redisDriver "lakego-admin/lakego/cache/driver/redis"
)

/**
 * 缓存
 *
 * @create 2021-7-3
 * @author deatil
 */

var once sync.Once

// 实例化
func New(once ...bool) interfaces.Cache {
    cache := GetDefaultCache()

    return Cache(cache, once...)
}

// 实例化
func NewWithType(cache string, once ...bool) interfaces.Cache {
    return Cache(cache, once...)
}

// 注册
func Register() {
    once.Do(func() {
        // 注册缓存驱动
        register.NewManagerWithPrefix("cache_").Register("redis", func(conf map[string]interface{}) interface{} {
            prefix := conf["prefix"].(string)

            driver := &redisDriver.Redis{}

            driver.Init(conf)
            driver.SetPrefix(prefix)

            return driver
        })
    })
}

func Cache(name string, once ...bool) interfaces.Cache {
    // 注册默认缓存
    Register()

    // 缓存列表
    caches := config.New("cache").GetStringMap("Caches")

    // 获取驱动配置
    driverConfig, ok := caches[name]
    if !ok {
        panic("缓存驱动 " + name + " 配置不存在")
    }

    // 配置
    driverConf := driverConfig.(map[string]interface{})

    driverType := driverConf["type"].(string)
    driver := register.NewManagerWithPrefix("cache_").GetRegister(driverType, driverConf, once...)
    if driver == nil {
        panic("缓存驱动 " + driverType + " 没有被注册")
    }

    c := cache.New(driver.(interfaces.Driver), driverConf)

    return c
}

func GetDefaultCache() string {
    return config.New("cache").GetString("Default")
}
