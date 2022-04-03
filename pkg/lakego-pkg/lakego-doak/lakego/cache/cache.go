package cache

import (
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
    Config = map[string]interface{}
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

    // 驱动
    driver interfaces.Driver
}

// 设置驱动
func (this *Cache) WithDriver(driver interfaces.Driver) interfaces.Cache {
    this.driver = driver

    return this
}

// 获取驱动
func (this *Cache) GetDriver() interfaces.Driver {
    return this.driver
}

// 设置配置
func (this *Cache) WithConfig(config Config) interfaces.Cache {
    this.config = config

    return this
}

// 获取配置
func (this *Cache) GetConfig(name string) interface{} {
    if data, ok := this.config[name]; ok {
        return data
    }

    return nil
}

// 获取
func (this *Cache) Has(key string) bool {
    return this.driver.Exists(key)
}

// 获取
func (this *Cache) Get(key string) (interface{}, error) {
    return this.driver.Get(key)
}

// 设置
func (this *Cache) Put(key string, value interface{}, ttl int64) error {
    return this.driver.Put(key, value, ttl)
}

// 永久设置
func (this *Cache) Forever(key string, value interface{}) error {
    return this.driver.Forever(key, value)
}

// 获取后删除
func (this *Cache) Pull(key string) (interface{}, error) {
    var val interface{}
    var err error

    val, err = this.driver.Get(key)
    if err != nil {
        return val, err
    }

    this.driver.Forget(key)

    return val, nil
}

// 增加一
func (this *Cache) Increment(key string, value ...int64) error {
    return this.driver.Increment(key, value...)
}

// 减去一
func (this *Cache) Decrement(key string, value ...int64) error {
    return this.driver.Decrement(key, value...)
}

// 删除
func (this *Cache) Forget(key string) (bool, error) {
    return this.driver.Forget(key)
}

// 清空
func (this *Cache) Flush() (bool, error) {
    return this.driver.Flush()
}

// 获取前缀
func (this *Cache) GetPrefix() string {
    return this.driver.GetPrefix()
}

