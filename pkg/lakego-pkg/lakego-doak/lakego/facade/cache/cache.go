package cache

import (
    "sync"
    "strings"

    "github.com/deatil/lakego-doak/lakego/array"
    "github.com/deatil/lakego-doak/lakego/register"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/cache"
    "github.com/deatil/lakego-doak/lakego/cache/interfaces"
    redisDriver "github.com/deatil/lakego-doak/lakego/cache/driver/redis"
)

/**
 * 缓存
 *
 * cache.New().Get("larke-cache", "larke-cache-data", 122222)
 * cacheData, err := cache.New().Get("larke-cache")
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
    driverConf := driverConfig.(map[string]any)

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
            Register("redis", func(conf map[string]any) any {
                addr     := array.ArrGetWithGoch(conf, "addr").ToString()
                password := array.ArrGetWithGoch(conf, "password").ToString()
                db       := array.ArrGetWithGoch(conf, "db").ToInt()

                minIdleConn  := array.ArrGetWithGoch(conf, "minidle-conn").ToInt()
                dialTimeout  := array.ArrGetWithGoch(conf, "dial-timeout").ToDuration()
                readTimeout  := array.ArrGetWithGoch(conf, "read-timeout").ToDuration()
                writeTimeout := array.ArrGetWithGoch(conf, "write-timeout").ToDuration()

                poolSize    := array.ArrGetWithGoch(conf, "pool-size").ToInt()
                poolTimeout := array.ArrGetWithGoch(conf, "pool-timeout").ToDuration()

                enabletrace := array.ArrGetWithGoch(conf, "enabletrace").ToBool()

                keyPrefix   := array.ArrGetWithGoch(conf, "key-prefix").ToString()

                driver := redisDriver.New(redisDriver.Config{
                    DB:       db,
                    Addr:     addr,
                    Password: password,

                    MinIdleConn:  minIdleConn,
                    DialTimeout:  dialTimeout,
                    ReadTimeout:  readTimeout,
                    WriteTimeout: writeTimeout,
                    PoolSize:     poolSize,
                    PoolTimeout:  poolTimeout,

                    EnableTrace:  enabletrace,

                    KeyPrefix:    keyPrefix,
                })

                return driver
            })
    })
}

