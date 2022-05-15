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
 * redis.New().Get("go-redis", &redisData)
 *
 * @create 2021-6-20
 * @author deatil
 */
func New(connect ...string) redis.Redis {
    conf := config.New("redis")

    // 默认
    defaultConnect := conf.GetString("default")
    if len(connect) > 0 {
        defaultConnect = connect[0]
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

    addr := array.ArrGetWithGoch(connectConf, "addr").ToString()
    password := array.ArrGetWithGoch(connectConf, "password").ToString()

    db := array.ArrGetWithGoch(connectConf, "db").ToInt()

    minIdleConn := array.ArrGetWithGoch(connectConf, "minidle-conn").ToInt()
    dialTimeout := array.ArrGetWithGoch(connectConf, "dial-timeout").ToDuration()
    readTimeout := array.ArrGetWithGoch(connectConf, "read-timeout").ToDuration()
    writeTimeout := array.ArrGetWithGoch(connectConf, "write-timeout").ToDuration()

    poolSize := array.ArrGetWithGoch(connectConf, "pool-size").ToInt()
    poolTimeout := array.ArrGetWithGoch(connectConf, "pool-timeout").ToDuration()

    enabletrace := array.ArrGetWithGoch(connectConf, "enabletrace").ToBool()

    keyPrefix := array.ArrGetWithGoch(connectConf, "key-prefix").ToString()

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
