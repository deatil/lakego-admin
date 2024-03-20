package redis

import (
    "time"
    "errors"
    "context"

    "github.com/go-redis/redis/v8"
    "github.com/go-redis/redis/extra/redisotel/v8"
)

// 构造函数
func New(config Config) *Redis {
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
            config.Logger.Errorf("cache-redis: %s", err.Error())
        }
    }

    // 调试
    if config.EnableTrace {
        client.AddHook(redisotel.NewTracingHook())
    }

    return &Redis{
        ctx:    context.Background(),
        client: client,
    }
}

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

    Logger iLogger
}

/**
 * redis 缓存
 *
 * @create 2021-7-15
 * @author deatil
 */
type Redis struct {
    // 上下文
    ctx context.Context

    // 客户端
    client *redis.Client
}

// 判断是否存在
func (this *Redis) Exists(key string) bool {
    n, err := this.client.Exists(this.ctx, key).Result()
    if err != nil {
        return false
    }

    if n > 0 {
        return true
    } else {
        return false
    }
}

// 获取
func (this *Redis) Get(key string) (any, error) {
    var val any
    var err error

    val, err = this.client.Get(this.ctx, key).Result()
    if err == redis.Nil {
        return val, errors.New("获取存储数据失败")
    } else if err != nil {
        return val, errors.New("获取存储数据失败")
    } else {
        return val, nil
    }
}

// 设置
func (this *Redis) Put(key string, value any, ttl time.Duration) error {
    err := this.client.Set(this.ctx, key, value, ttl).Err()
    if err != nil {
        return errors.New("缓存存储失败")
    }

    return nil
}

// 存在永久
func (this *Redis) Forever(key string, value any) error {
    err := this.client.Set(this.ctx, key, value, 0).Err()
    if err != nil {
        return errors.New("缓存存储失败")
    }

    return nil
}

// 增加
func (this *Redis) Increment(key string, value ...int64) error {
    var err error

    if len(value) > 0 {
        _, err = this.client.IncrBy(this.ctx, key, value[0]).Result()
    } else {
        _, err = this.client.Incr(this.ctx, key).Result()
    }

    if err != nil {
        return errors.New("增加数据量失败")
    }

    return nil
}

// 减少
func (this *Redis) Decrement(key string, value ...int64) error {
    var err error

    if len(value) > 0 {
        _, err = this.client.DecrBy(this.ctx, key, value[0]).Result()
    } else {
        _, err = this.client.Decr(this.ctx, key).Result()
    }

    if err != nil {
        return errors.New("减少数据量失败")
    }

    return nil
}

// 删除
func (this *Redis) Forget(key string) (bool, error) {
    _, err := this.client.Del(this.ctx, key).Result()
    if err != nil {
        return false, errors.New("删除数据失败")
    }

    return true, nil
}

// 清空
func (this *Redis) Flush() (bool, error) {
    _, err := this.client.FlushDB(this.ctx).Result()
    if err != nil {
        return false, errors.New("清空数据失败")
    }

    return true, nil
}

// HashSet
func (this *Redis) HashSet(key string, field string, value string) error {
    return this.client.HSet(this.ctx, key, field, value).Err()
}

// HashGet
func (this *Redis) HashGet(key string, field string) (string, error) {
    return this.client.HGet(this.ctx, key, field).Result()
}

// HashDel
func (this *Redis) HashDel(key string) error {
    return this.client.HDel(this.ctx, key).Err()
}

// 过期时间
func (this *Redis) Expire(key string, expiration time.Duration) error {
    return this.client.Expire(this.ctx, key, expiration).Err()
}

// 关闭
func (this *Redis) Close() error {
    return this.client.Close()
}

// 获取客户端
func (this *Redis) GetClient() *redis.Client {
    return this.client
}
