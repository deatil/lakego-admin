package redis

import (
    "github.com/deatil/go-goch/goch"

    "github.com/deatil/lakego-doak/lakego/redis"
    "github.com/deatil/lakego-doak/lakego/array"
    "github.com/deatil/lakego-doak/lakego/facade/config"
)

/**
 * 构造函数
 *
 * redis.New().Set("go-redis", "go-redis-data", 60000)
 *
 * @create 2021-6-20
 * @author deatil
 */
func New(defVal ...string) redis.Redis {
    conf := config.New("redis")

    // 默认
    defaultConnect := conf.GetString("default")
    if len(defVal) > 0 {
        defaultConnect = defVal[0]
    }

    // 连接列表
    connects := conf.GetStringMap("connects")

    // 连接使用的配置
    connectConfs, ok := connects[defaultConnect]
    if !ok {
        panic("redis连接配置 [" + defaultConnect + "] 不存在")
    }

    // 格式化转换
    connectConf := goch.ToStringMap(connectConfs)

    addr := goch.ToString(array.ArrGet(connectConf, "addr"))
    password := goch.ToString(array.ArrGet(connectConf, "password"))

    db := goch.ToInt(array.ArrGet(connectConf, "db"))

    minIdleConn := goch.ToInt(array.ArrGet(connectConf, "minidle-conn"))
    dialTimeout := goch.ToDuration(array.ArrGet(connectConf, "dial-timeout"))
    readTimeout := goch.ToDuration(array.ArrGet(connectConf, "read-timeout"))
    writeTimeout := goch.ToDuration(array.ArrGet(connectConf, "write-timeout"))

    poolSize := goch.ToInt(array.ArrGet(connectConf, "pool-size"))
    poolTimeout := goch.ToDuration(array.ArrGet(connectConf, "pool-timeout"))

    enabletrace := goch.ToBool(array.ArrGet(connectConf, "enabletrace"))

    keyPrefix := goch.ToString(array.ArrGet(connectConf, "key-prefix"))

    return redis.New(redis.Config{
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
}

// 连接
func Connect(name string) redis.Redis {
    return New(name)
}
