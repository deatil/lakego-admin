package cache

import (
    "fmt"
    "time"

    "github.com/deatil/go-goch/goch"

    "github.com/deatil/lakego-doak/lakego/array"
    "github.com/deatil/lakego-doak/lakego/cache/interfaces"
)

// 创建
func New(driver interfaces.Driver, conf ...Config) *Cache {
    cache := &Cache{
        driver: driver,
    }

    if len(conf) > 0{
        cache.config = conf[0]
    }

    return cache
}

type (
    // 配置
    Config = map[string]any
)

/**
 * 缓存
 *
 * @create 2021-7-15
 * @author deatil
 */
type Cache struct {
    // 配置
    config Config

    // 前缀
    prefix string

    // 驱动
    driver interfaces.Driver
}

// 设置驱动
func (this *Cache) WithDriver(driver interfaces.Driver) *Cache {
    this.driver = driver

    return this
}

// 获取驱动
func (this *Cache) GetDriver() interfaces.Driver {
    return this.driver
}

// 设置配置
func (this *Cache) WithConfig(config Config) *Cache {
    this.config = config

    return this
}

// 获取配置
func (this *Cache) GetConfig(name string) goch.Goch {
    return array.ArrGetWithGoch(this.config, name)
}

// 设置前缀
func (this *Cache) WithPrefix(prefix string) *Cache {
    this.prefix = prefix

    return this
}

// 获取前缀
func (this *Cache) GetPrefix() string {
    return this.prefix
}

// 获取
func (this *Cache) Has(key string) bool {
    key = this.wrapperKey(key)

    return this.driver.Exists(key)
}

// 获取
func (this *Cache) Get(key string) (any, error) {
    key = this.wrapperKey(key)

    return this.driver.Get(key)
}

// 设置
func (this *Cache) Put(key string, value any, ttl any) error {
    key = this.wrapperKey(key)

    expiration := this.formatTime(ttl)

    return this.driver.Put(key, value, expiration)
}

// 永久设置
func (this *Cache) Forever(key string, value any) error {
    key = this.wrapperKey(key)

    return this.driver.Forever(key, value)
}

// 获取后删除
func (this *Cache) Pull(key string) (any, error) {
    var val any
    var err error

    key = this.wrapperKey(key)

    val, err = this.driver.Get(key)
    if err != nil {
        return val, err
    }

    this.driver.Forget(key)

    return val, nil
}

// 增加一
func (this *Cache) Increment(key string, value ...int64) error {
    key = this.wrapperKey(key)

    return this.driver.Increment(key, value...)
}

// 减去一
func (this *Cache) Decrement(key string, value ...int64) error {
    key = this.wrapperKey(key)

    return this.driver.Decrement(key, value...)
}

// 删除
func (this *Cache) Forget(key string) (bool, error) {
    key = this.wrapperKey(key)

    return this.driver.Forget(key)
}

// 清空
func (this *Cache) Flush() (bool, error) {
    return this.driver.Flush()
}

// 包装字段
func (this *Cache) wrapperKey(key string) string {
    if this.prefix == "" {
        return key
    }

    return fmt.Sprintf("%s:%s", this.prefix, key)
}

// 时间格式化
func (this *Cache) formatTime(t any) time.Duration {
    return time.Second * goch.ToDuration(t)
}
