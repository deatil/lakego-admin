package redis

import (
    "log"
    "fmt"
    "time"
    "errors"
    "context"

    "github.com/go-redis/redis/v8"

    "github.com/deatil/lakego-admin/lakego/cache/interfaces"
)

/**
 * redis 缓存
 *
 * @create 2021-7-15
 * @author deatil
 */
type Redis struct {
    // 配置
    config map[string]interface{}

    // 前缀
    prefix string

    // 上下文
    ctx context.Context

    // 客户端
    client *redis.Client
}

// 实例化
func (this *Redis) Init(config map[string]interface{}) interfaces.Driver {
    mainDB := config["db"].(int)
    addr := config["host"].(string)
    password := config["password"].(string)

    client := redis.NewClient(&redis.Options{
        Addr:     addr,
        DB:       mainDB,
        Password: password,
    })

    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()

    if _, err := client.Ping(ctx).Result(); err != nil {
        log.Print(err.Error())
    }

    this.config = config
    this.ctx = context.Background()
    this.client = client

    return this
}

// 判断是否存在
func (this *Redis) Exists(key string) bool {
    n, err := this.client.Exists(this.ctx, this.WrapperKey(key)).Result()
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
func (this *Redis) Get(key string) (interface{}, error) {
    var val interface{}
    var err error

    val, err = this.client.Get(this.ctx, this.WrapperKey(key)).Result()
    if err == redis.Nil {
        return val, errors.New("获取存储数据失败")
    } else if err != nil {
        return val, errors.New("获取存储数据失败")
    } else {
        return val, nil
    }
}

// 设置
func (this *Redis) Put(key string, value interface{}, ttl int64) error {
    expiration := this.IntTimeToDuration(ttl)

    err := this.client.Set(this.ctx, this.WrapperKey(key), value, expiration).Err()
    if err != nil {
        return errors.New("缓存存储失败")
    }

    return nil
}

// 存在永久
func (this *Redis) Forever(key string, value interface{}) error {
    err := this.client.Set(this.ctx, this.WrapperKey(key), value, 0).Err()
    if err != nil {
        return errors.New("缓存存储失败")
    }

    return nil
}

// 增加
func (this *Redis) Increment(key string, value ...int64) error {
    var err error

    if len(value) > 0 {
        _, err = this.client.IncrBy(this.ctx, this.WrapperKey(key), value[0]).Result()
    } else {
        _, err = this.client.Incr(this.ctx, this.WrapperKey(key)).Result()
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
        _, err = this.client.DecrBy(this.ctx, this.WrapperKey(key), value[0]).Result()
    } else {
        _, err = this.client.Decr(this.ctx, this.WrapperKey(key)).Result()
    }

    if err != nil {
        return errors.New("减少数据量失败")
    }

    return nil
}

// 删除
func (this *Redis) Forget(key string) (bool, error) {
    _, err := this.client.Del(this.ctx, this.WrapperKey(key)).Result()
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
    return this.client.HSet(this.ctx, this.WrapperKey(key), field, value).Err()
}

// HashGet
func (this *Redis) HashGet(key string, field string) (string, error) {
    return this.client.HGet(this.ctx, this.WrapperKey(key), field).Result()
}

// HashDel
func (this *Redis) HashDel(key string) error {
    return this.client.HDel(this.ctx, this.WrapperKey(key)).Err()
}

// 过期时间
func (this *Redis) Expire(key string, expiration time.Duration) error {
    return this.client.Expire(this.ctx, key, expiration).Err()
}

// 设置前缀
func (this *Redis) SetPrefix(prefix string) {
    this.prefix = prefix
}

// 获取前缀
func (this *Redis) GetPrefix() string {
    return this.prefix
}

// 关闭
func (this *Redis) Close() error {
    return this.client.Close()
}

// 获取客户端
func (this *Redis) GetClient() *redis.Client {
    return this.client
}

// 包装字段
func (this *Redis) WrapperKey(key string) string {
    return fmt.Sprintf("%s:%s", this.prefix, key)
}

// int64 时间格式化为 Duration 格式
func (this *Redis) IntTimeToDuration(t int64) time.Duration {
    return time.Second * time.Duration(t)
}
