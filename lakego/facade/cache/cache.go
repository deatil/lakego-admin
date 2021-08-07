package cache

import (
    "sync"

    "lakego-admin/lakego/config"
    "lakego-admin/lakego/cache"
    "lakego-admin/lakego/cache/interfaces"
    redisDriver "lakego-admin/lakego/cache/driver/redis"
    driverRegister "lakego-admin/lakego/cache/register/driver"
    cacheRegister "lakego-admin/lakego/cache/register/cache"
)

/**
 * 缓存
 *
 * @create 2021-7-3
 * @author deatil
 */

var once sync.Once

func New() interfaces.Cache {
    cache := GetDefaultCache()

    return Cache(cache)
}

// 注册磁盘
func Register() {
    once.Do(func() {
        // 注册可用缓存驱动
        driverRegister.RegisterDriver("redis", func() interfaces.Driver {
            return &redisDriver.Redis{}
        })

        // 缓存列表
        caches := config.New("cache").GetStringMap("Caches")

        // redis 缓存
        cacheRegister.RegisterCache("redis", func() interfaces.Cache {
            redisConf := caches["redis"].(map[string]interface{})
            redisType := redisConf["type"].(string)
            redisPrefix := redisConf["prefix"].(string)

            driver := driverRegister.GetDriver(redisType)
            if driver == nil {
                panic("缓存驱动 " + redisType + " 没有被注册")
            }

            driver.Init(redisConf)
            driver.SetPrefix(redisPrefix)

            c := cache.New(driver, redisConf)

            return c
        })

    })
}

func Cache(name string) interfaces.Cache {
    // 注册默认缓存
    Register()

    // 拿取缓存
    c := cacheRegister.GetCache(name)
    if c == nil {
        panic("缓存类型 " + name + " 没有被注册")
    }

    return c
}

func GetDefaultCache() string {
    return config.New("cache").GetString("Default")
}
