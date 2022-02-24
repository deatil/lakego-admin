package cache

import (
    "sync"
    "strings"

    "github.com/deatil/lakego-doak/lakego/register"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/cache"
    "github.com/deatil/lakego-doak/lakego/cache/interfaces"
    redisDriver "github.com/deatil/lakego-doak/lakego/cache/driver/redis"
)

/**
 * 缓存
 *
 * @create 2021-7-3
 * @author deatil
 */

var once sync.Once

// 初始化
func init() {
    // 注册默认
    Register()
}

// 实例化
func New(once ...bool) interfaces.Cache {
    name := GetDefaultCache()

    return Cache(name, once...)
}

// 实例化
func NewWithType(name string, once ...bool) interfaces.Cache {
    return Cache(name, once...)
}

func Cache(name string, once ...bool) interfaces.Cache {
    // 缓存列表
    caches := config.New("cache").GetStringMap("Caches")

    // 转为小写
    name = strings.ToLower(name)

    // 获取驱动配置
    driverConfig, ok := caches[name]
    if !ok {
        panic("缓存驱动[" + name + "]配置不存在")
    }

    // 配置
    driverConf := driverConfig.(map[string]interface{})

    driverType := driverConf["type"].(string)
    driver := register.
        NewManagerWithPrefix("cache").
        GetRegister(driverType, driverConf, once...)
    if driver == nil {
        panic("缓存驱动[" + driverType + "]没有被注册")
    }

    c := cache.New(driver.(interfaces.Driver), driverConf)

    return c
}

func GetDefaultCache() string {
    return config.New("cache").GetString("Default")
}

// 注册
func Register() {
    once.Do(func() {
        // 注册缓存驱动
        register.
            NewManagerWithPrefix("cache").
            Register("redis", func(conf map[string]interface{}) interface{} {
                prefix := conf["prefix"].(string)

                driver := &redisDriver.Redis{}

                driver.Init(conf)
                driver.SetPrefix(prefix)

                return driver
            })
    })
}

