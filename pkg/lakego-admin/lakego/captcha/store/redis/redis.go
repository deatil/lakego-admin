package redis

import (
    "time"
    "context"

    "github.com/go-redis/cache/v8"
    "github.com/go-redis/redis/v8"

    "github.com/deatil/lakego-admin/lakego/captcha/store"
)

/**
 * Redis 存储
 *
 * @create 2021-10-18
 * @author deatil
 */
type Redis struct {
    // 继承默认
    store.Store

    // 配置
    config map[string]interface{}

    // 缓存
    cache *cache.Cache

    // 客户端
    client *redis.Client
}

// 设置配置
func (this *Redis) WithConfig(config map[string]interface{}) *Redis {
    this.config = config

    return this
}

// 初始化
func (this *Redis) Init() {
    DB := this.config["db"].(int)
    addr := this.config["addr"].(string)
    password := this.config["password"].(string)

    client := redis.NewClient(&redis.Options{
        Addr:     addr,
        DB:       DB,
        Password: password,
    })

    ctx, cancel := context.WithTimeout(context.Background(), 3 * time.Second)
    defer cancel()

    if _, err := client.Ping(ctx).Result(); err != nil {
        panic("验证码 redis 连接失败")
    }

    rcache := cache.New(&cache.Options{
        Redis:      client,
        LocalCache: cache.NewTinyLFU(1000, time.Minute),
    })

    // 保存缓存句柄
    this.cache = rcache

    // 保存客户端
    this.client = client
}

// 设置
func (this *Redis) Set(id string, value string) error {
    ttl := time.Second * time.Duration(this.config["ttl"].(int))

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
    return this.config["prefix"].(string) + ":" + v
}

