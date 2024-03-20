package cache

import (
    "strings"
)

// 缓存接口
type iCache interface {
    Put(key string, value any, ttl any) error
    Get(key string) (any, error)
    Forget(key string) (bool, error)
}

// 缓存配置
type Config struct {
    Cache iCache
    Expir string
}

/**
 * Cache 存储
 *
 * @create 2021-10-18
 * @author deatil
 */
type Cache struct {
    // 缓存
    cache iCache

    // 过期时间
    expir string
}

// 构造函数
func New(config Config) *Cache {
    return &Cache{
        expir: config.Expir,
        cache: config.Cache,
    }
}

// 设置
func (this *Cache) Set(id string, value string) (err error) {
    err = this.cache.Put(id, value, this.expir)

    return
}

// 获取
func (this *Cache) Get(id string, clear bool) string {
    val, err := this.cache.Get(id)
    if err != nil {
        return ""
    }

    v, ok := val.(string)
    if !ok {
        return ""
    }

    if clear {
        this.cache.Forget(id)
    }

    return v
}

// 验证
func (this *Cache) Verify(id, answer string, clear bool) bool {
    v := this.Get(id, clear)
    return strings.ToLower(v) == strings.ToLower(answer)
}
