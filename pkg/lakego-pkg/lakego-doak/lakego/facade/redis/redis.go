package redis

import (
    "github.com/deatil/lakego-doak/lakego/redis"
    "github.com/deatil/lakego-doak/lakego/array"
    "github.com/deatil/lakego-doak/lakego/facade/config"
)

/**
 * Redis
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
    cfg := array.ArrayFrom(connectConfs)

    return redis.New(redis.Config{
        DB:       cfg.Value("db").ToInt(),
        Addr:     cfg.Value("addr").ToString(),
        Password: cfg.Value("password").ToString(),

        MinIdleConn:  cfg.Value("minidle-conn").ToInt(),
        DialTimeout:  cfg.Value("dial-timeout").ToDuration(),
        ReadTimeout:  cfg.Value("read-timeout").ToDuration(),
        WriteTimeout: cfg.Value("write-timeout").ToDuration(),

        PoolSize:     cfg.Value("pool-size").ToInt(),
        PoolTimeout:  cfg.Value("pool-timeout").ToDuration(),

        EnableTrace:  cfg.Value("enabletrace").ToBool(),

        KeyPrefix:    cfg.Value("key-prefix").ToString(),
    })
}

// 连接
func Connect(name string) redis.Redis {
    return New(name)
}
