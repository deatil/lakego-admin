package redis

import (
    "fmt"
    "time"
    "errors"
    "reflect"
    "context"

    "github.com/go-redis/redis/v8"

    "lakego-admin/lakego/logger"
)

// 配置
type Config struct {
    DB int
    Host string
    Password string
}

// redis 缓存
type Redis struct {
    config Config
    prefix string
    ctx context.Context
    client *redis.Client
}

// 实例化
func New(config Config) *Redis {
    mainDB := config.DB
    addr := config.Host
    password := config.Password

    client := redis.NewClient(&redis.Options{
        Addr:     addr,
        DB:       mainDB,
        Password: password,
    })

    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()

    if _, err := client.Ping(ctx).Result(); err != nil {
        logger.Error(err.Error())
    }

    return &Redis{
        config: config,
        ctx: context.Background(),
        client: client,
    }
}

// 判断是否存在
func (r *Redis) Exists(key string) bool {
    n, err := r.client.Exists(r.ctx, r.wrapperKey(key)).Result()
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
func (r *Redis) Get(key string) (interface{}, error) {
    var val interface{}
    var err error

    val, err = r.client.Get(r.ctx, r.wrapperKey(key)).Result()
    if err == redis.Nil {
        return val, errors.New("获取存储数据失败")
    } else if err != nil {
        return val, errors.New("获取存储数据失败")
    } else {
        return val, nil
    }
}

// 设置
func (r *Redis) Put(key string, value interface{}, expiration interface{}) error {
    var ttl time.Duration

    if reflect.TypeOf(expiration).String() == "int64" {
        ttl = r.IntTimeToDuration(expiration.(int64))
    } else if reflect.TypeOf(expiration).String() == "int" {
        ttl = r.IntTimeToDuration(int64(expiration.(int)))
    } else {
        ttl = expiration.(time.Duration)
    }

    err := r.client.Set(r.ctx, r.wrapperKey(key), value, ttl).Err()
    if err != nil {
        return errors.New("缓存存储失败")
    }

    return nil
}

// 存在永久
func (r *Redis) Forever(key string, value interface{}) error {
    err := r.client.Set(r.ctx, r.wrapperKey(key), value, 0).Err()
    if err != nil {
        return errors.New("缓存存储失败")
    }

    return nil
}

// 增加
func (r *Redis) Increment(key string, value ...int64) error {
    var err error

    if len(value) > 0 {
        _, err = r.client.IncrBy(r.ctx, r.wrapperKey(key), value[0]).Result()
    } else {
        _, err = r.client.Incr(r.ctx, r.wrapperKey(key)).Result()
    }

    if err != nil {
        return errors.New("增加数据量失败")
    }

    return nil
}

// 减少
func (r *Redis) Decrement(key string, value ...int64) error {
    var err error

    if len(value) > 0 {
        _, err = r.client.DecrBy(r.ctx, r.wrapperKey(key), value[0]).Result()
    } else {
        _, err = r.client.Decr(r.ctx, r.wrapperKey(key)).Result()
    }

    if err != nil {
        return errors.New("减少数据量失败")
    }

    return nil
}

// 删除
func (r *Redis) Forget(key string) (bool, error) {
    _, err := r.client.Del(r.ctx, r.wrapperKey(key)).Result()
    if err != nil {
        return false, errors.New("删除数据失败")
    }

    return true, nil
}

// 清空
func (r *Redis) Flush() (bool, error) {
    _, err := r.client.FlushDB(r.ctx).Result()
    if err != nil {
        return false, errors.New("清空数据失败")
    }

    return true, nil
}

// 设置前缀
func (r *Redis) SetPrefix(prefix string) error {
    r.prefix = prefix
    return nil
}

// 获取前缀
func (r *Redis) GetPrefix() string {
    return r.prefix
}

// 关闭
func (r *Redis) Close() error {
    return r.client.Close()
}

// 获取客户端
func (r *Redis) GetClient() *redis.Client {
    return r.client
}

// 包装字段
func (r *Redis) wrapperKey(key string) string {
    return fmt.Sprintf("%s:%s", r.prefix, key)
}

// int64 时间格式化为 Duration 格式
func (r *Redis) IntTimeToDuration(t int64) time.Duration {
    return time.Second * time.Duration(t)
}
