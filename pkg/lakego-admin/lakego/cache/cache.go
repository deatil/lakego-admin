package cache

import (
    "time"
    "reflect"

    "github.com/deatil/lakego-admin/lakego/cache/interfaces"
)

// 创建
func New(driver interfaces.Driver, conf ...map[string]interface{}) *Cache {
    cache := &Cache{
        driver: driver,
    }

    if len(conf) > 0{
        cache.config = conf[0]
    }

    return cache
}

/**
 * 缓存
 *
 * @create 2021-7-15
 * @author deatil
 */
type Cache struct {
    // 配置
    config map[string]interface{}

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
func (this *Cache) WithConfig(config map[string]interface{}) interfaces.Cache {
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
func (this *Cache) Put(key string, value interface{}, seconds interface{}) error {
    ttl := this.FormatTime(seconds)

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

// 格式化时间
func (this *Cache) FormatTime(expiration interface{}) time.Duration {
    var ttl time.Duration

    if reflect.TypeOf(expiration).String() == "int64" {
        ttl = this.IntTimeToDuration(expiration.(int64))
    } else if reflect.TypeOf(expiration).String() == "int" {
        ttl = this.IntTimeToDuration(int64(expiration.(int)))
    } else {
        ttl = expiration.(time.Duration)
    }

    return ttl
}

// int64 时间格式化为 Duration 格式
func (this *Cache) IntTimeToDuration(t int64) time.Duration {
    return time.Duration(t) * time.Second
}

