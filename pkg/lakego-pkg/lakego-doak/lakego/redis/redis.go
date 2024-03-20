package redis

import (
    "fmt"
    "time"
    "errors"
    "context"

    "github.com/go-redis/cache/v8"
    "github.com/go-redis/redis/v8"
    "github.com/go-redis/redis/extra/redisotel/v8"

    "github.com/deatil/go-goch/goch"
)

// 日志接口
type iLogger interface {
    Errorf(template string, args ...any)
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

    Logger iLogger
}

/**
 * redis 缓存
 *
 * @create 2021-9-8
 * @author deatil
 */
type Redis struct {
    // 上下文
    ctx context.Context

    // 前缀
    prefix string

    // 缓存
    cache  *cache.Cache

    // 客户端
    client *redis.Client
}

// 构造函数
func New(config Config) Redis {
    client := redis.NewClient(&redis.Options{
        Addr:     config.Addr,
        Password: config.Password,
        DB:       config.DB,

        MinIdleConns: config.MinIdleConn,
        DialTimeout:  config.DialTimeout,
        ReadTimeout:  config.ReadTimeout,
        WriteTimeout: config.WriteTimeout,
        PoolSize:     config.PoolSize,
        PoolTimeout:  config.PoolTimeout,
    })

    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()

    if _, err := client.Ping(ctx).Result(); err != nil {
        if config.Logger != nil {
            config.Logger.Errorf("redis: %s", err.Error())
        }
    }

    // 调试
    if config.EnableTrace {
        client.AddHook(redisotel.NewTracingHook())
    }

    return Redis{
        ctx:    context.TODO(),
        prefix: config.KeyPrefix,
        client: client,
        cache:  cache.New(&cache.Options{
            Redis:      client,
            LocalCache: cache.NewTinyLFU(1000, time.Minute),
        }),
    }
}

// 设置
func (this Redis) Set(key string, value any, expiration any) error {
    ttl := goch.ToDuration(expiration)

    return this.cache.Set(&cache.Item{
        Ctx:            this.ctx,
        Key:            this.wrapperKey(key),
        Value:          value,
        TTL:            ttl,
        SkipLocalCache: true,
    })
}

// 获取
func (this Redis) Get(key string, value any) error {
    err := this.cache.Get(this.ctx, this.wrapperKey(key), value)
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

    cmd := this.client.Del(this.ctx, wrapperKeys...)
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

    cmd := this.client.Exists(this.ctx, wrapperKeys...)
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
    if this.prefix == "" {
        return key
    }

    return fmt.Sprintf("%s:%s", this.prefix, key)
}
