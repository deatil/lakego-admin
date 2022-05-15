package redis

import (
    "time"
    "context"

    "github.com/go-redis/cache/v8"
    "github.com/go-redis/redis/v8"
    "github.com/go-redis/redis/extra/redisotel/v8"

    "github.com/deatil/lakego-doak/lakego/facade/logger"
    "github.com/deatil/lakego-doak/lakego/captcha/store"
    "github.com/deatil/lakego-doak/lakego/captcha/interfaces"
)

// 构造函数
func New(config Config) interfaces.Store {
    db        := config.DB
    addr      := config.Addr
    password  := config.Password
    keyPrefix := config.KeyPrefix
    ttl       := config.TTL

    minIdleConn  := config.MinIdleConn
    dialTimeout  := config.DialTimeout
    readTimeout  := config.ReadTimeout
    writeTimeout := config.WriteTimeout
    poolSize     := config.PoolSize
    poolTimeout  := config.PoolTimeout

    enabletrace  := config.EnableTrace

    client := redis.NewClient(&redis.Options{
        Addr:     addr,
        Password: password,
        DB:       db,

        MinIdleConns: minIdleConn,
        DialTimeout:  dialTimeout,
        ReadTimeout:  readTimeout,
        WriteTimeout: writeTimeout,
        PoolSize:     poolSize,
        PoolTimeout:  poolTimeout,
    })

    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()

    if _, err := client.Ping(ctx).Result(); err != nil {
        logger.New().Error(err.Error())
    }

    // 调试
    if enabletrace {
        client.AddHook(redisotel.NewTracingHook())
    }

    return &Redis{
        ttl: ttl,
        prefix: keyPrefix,
        client: client,
        cache: cache.New(&cache.Options{
            Redis:      client,
            LocalCache: cache.NewTinyLFU(1000, time.Minute),
        }),
    }
}

// 缓存配置
type Config struct {
    Addr     string
    Password string
    DB       int

    MinIdleConn  int
    DialTimeout  time.Duration
    ReadTimeout  time.Duration
    WriteTimeout time.Duration
    PoolSize     int
    PoolTimeout  time.Duration

    EnableTrace  bool

    KeyPrefix    string
    TTL          int
}

/**
 * Redis 存储
 *
 * @create 2021-10-18
 * @author deatil
 */
type Redis struct {
    // 继承默认
    store.Store

    // 缓存
    cache *cache.Cache

    // 客户端
    client *redis.Client

    // 前缀
    prefix string

    // 过期时间
    ttl int
}

// 设置
func (this *Redis) Set(id string, value string) error {
    ttl := time.Second * time.Duration(this.ttl)

    this.cache.Set(&cache.Item{
        Ctx:            context.TODO(),
        Key:            this.formatKey(id),
        Value:          value,
        TTL:            ttl,
        SkipLocalCache: true,
    })

    return nil
}

// 获取
func (this *Redis) Get(id string, clear bool) string {
    var (
        key = this.formatKey(id)
        val string
    )

    err := this.cache.Get(context.TODO(), key, &val)
    if err != nil {
        return ""
    }

    if clear {
        this.client.Del(context.TODO(), key)
    }

    return val
}

// 验证
func (this *Redis) Verify(id, answer string, clear bool) bool {
    v := this.Get(id, clear)
    return v == answer
}

// 获取格式化的值
func (this *Redis) formatKey(v string) string {
    return this.prefix + ":" + v
}

