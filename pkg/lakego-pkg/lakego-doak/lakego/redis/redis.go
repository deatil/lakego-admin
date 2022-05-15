package redis

import (
    "fmt"
    "time"
    "errors"
    "context"

    "github.com/go-redis/cache/v8"
    "github.com/go-redis/redis/v8"
    "github.com/go-redis/redis/extra/redisotel/v8"

    "github.com/deatil/lakego-doak/lakego/facade/logger"
)

// 构造函数
func New(config Config) Redis {
    db := config.DB
    addr := config.Addr
    password := config.Password
    keyPrefix := config.KeyPrefix

    minIdleConn := config.MinIdleConn
    dialTimeout := config.DialTimeout
    readTimeout := config.ReadTimeout
    writeTimeout := config.WriteTimeout
    poolSize := config.PoolSize
    poolTimeout := config.PoolTimeout

    enabletrace := config.EnableTrace

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

    return Redis{
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
}

/**
 * redis 缓存
 *
 * @create 2021-9-8
 * @author deatil
 */
type Redis struct {
    // 前缀
    prefix string

    // 缓存
    cache  *cache.Cache

    // 客户端
    client *redis.Client
}

// 设置
func (this Redis) Set(key string, value any, expiration int) error {
    ttl := this.FormatTime(expiration)

    return this.cache.Set(&cache.Item{
        Ctx:            context.TODO(),
        Key:            this.wrapperKey(key),
        Value:          value,
        TTL:            ttl,
        SkipLocalCache: true,
    })
}

// 获取
func (this Redis) Get(key string, value any) error {
    err := this.cache.Get(context.TODO(), this.wrapperKey(key), value)
    if err == cache.ErrCacheMiss {
        err = errors.New("Redis Key No Exist")
    }

    return err
}

func (this Redis) Delete(keys ...string) (bool, error) {
    wrapperKeys := make([]string, len(keys))
    for index, key := range keys {
        wrapperKeys[index] = this.wrapperKey(key)
    }

    cmd := this.client.Del(context.TODO(), wrapperKeys...)
    if err := cmd.Err(); err != nil {
        return false, err
    }

    return cmd.Val() > 0, nil
}

func (this Redis) Check(keys ...string) (bool, error) {
    wrapperKeys := make([]string, len(keys))
    for index, key := range keys {
        wrapperKeys[index] = this.wrapperKey(key)
    }

    cmd := this.client.Exists(context.TODO(), wrapperKeys...)
    if err := cmd.Err(); err != nil {
        return false, err
    }
    return cmd.Val() > 0, nil
}

func (this Redis) Close() error {
    return this.client.Close()
}

func (this Redis) GetClient() *redis.Client {
    return this.client
}

// 包装 key 值
func (this Redis) wrapperKey(key string) string {
    return fmt.Sprintf("%s:%s", this.prefix, key)
}

// int 时间格式化为 Duration 格式
func (this Redis) FormatTime(t int) time.Duration {
    return time.Second * time.Duration(int64(t))
}
