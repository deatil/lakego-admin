package redis

import (
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/redis"
)

/**
 * redis
 *
 * @create 2021-6-20
 * @author deatil
 */
func New() redis.Redis {
    conf := config.New("redis")

    keyPrefix := conf.GetString("KeyPrefix")

    addr := conf.GetString("Addr")
    password := conf.GetString("Password")
    db := conf.GetInt("DB")

    minIdleConn := config["minidleconn"].(int)
    dialTimeout, _ := time.ParseDuration(config["dialtimeout"].(string))
    readTimeout, _ := time.ParseDuration(config["readtimeout"].(string))
    writeTimeout, _ := time.ParseDuration(config["writetimeout"].(string))
    poolSize := config["poolsize"].(int)
    poolTimeout, _ := time.ParseDuration(config["pooltimeout"].(string))

    enabletrace := config["enabletrace"].(bool)

    return redis.New(redis.Config{
        KeyPrefix: keyPrefix,

        DB: db,
        Addr: addr,
        Password: password,

        MinIdleConns: minIdleConn,
        DialTimeout:  dialTimeout,
        ReadTimeout:  readTimeout,
        WriteTimeout: writeTimeout,
        PoolSize:     poolSize,
        PoolTimeout:  poolTimeout,

        EnableTrace:  enabletrace,
    })
}

/**
 * redis，带 DB 选择
 *
 * @create 2021-6-20
 * @author deatil
 */
func NewWithDB(mainDB int) redis.Redis {
    conf := config.New("redis")

    addr := conf.GetString("Host")
    password := conf.GetString("Password")
    keyPrefix := conf.GetString("KeyPrefix")

    return redis.New(redis.Config{
        DB: mainDB,
        Host: addr,
        Password: password,
        KeyPrefix: keyPrefix,
    })
}

