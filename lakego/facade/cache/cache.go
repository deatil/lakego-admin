package cache

import (
    "sync"

    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/cache"
    "lakego-admin/lakego/cache/interfaces"
    "lakego-admin/lakego/cache/register"
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
        // 注册可用缓存驱动
        register.RegisterDriver("redis", func() interfaces.Driver {
            return &redisDriver.Redis{}
        })

        // 缓存列表
        caches := config.New("cache").GetStringMap("Caches")

        // redis 缓存
        register.RegisterCache("redis", func() interfaces.Cache {
            redisConf := caches["redis"].(map[string]interface{})
            redisType := redisConf["type"].(string)
            redisPrefix := redisConf["prefix"].(string)

            driver := register.GetDriver(redisType)
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

func Cache(name string, once ...bool) interfaces.Cache {
    // 注册默认缓存
    Register()

    var once2 bool
    if len(once) > 0 && once[0] {
        once2 = true
    } else {
        once2 = false
    }

    // 拿取缓存
    c := register.GetCache(name, once2)
    if c == nil {
        panic("缓存类型 " + name + " 没有被注册")
    }

    return c
}

func GetDefaultCache() string {
    return config.New("cache").GetString("Default")
}
