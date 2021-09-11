package cache

import (
    "time"
    "reflect"

    "lakego-admin/lakego/cache/interfaces"
)

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

// 创建
func New(driver interfaces.Driver, conf ...map[string]interface{}) *Cache {
    c := &Cache{
        driver: driver,
    }

    if len(conf) > 0{
        c.config = conf[0]
    }

    return c
}

// 设置驱动
func (c *Cache) WithDriver(driver interfaces.Driver) interfaces.Cache {
    c.driver = driver

    return c
}

// 获取驱动
func (c *Cache) GetDriver() interfaces.Driver {
    return c.driver
}

// 设置配置
func (c *Cache) WithConfig(config map[string]interface{}) interfaces.Cache {
    c.config = config

    return c
}

// 获取配置
func (c *Cache) GetConfig(name string) interface{} {
    if data, ok := c.config[name]; ok {
        return data
    }

    return nil
}

// 获取
func (c *Cache) Has(key string) bool {
    return c.driver.Exists(key)
}

// 获取
func (c *Cache) Get(key string) (interface{}, error) {
    return c.driver.Get(key)
}

// 设置
func (c *Cache) Put(key string, value interface{}, seconds interface{}) error {
    ttl := c.FormatTime(seconds)

    return c.driver.Put(key, value, ttl)
}

// 永久设置
func (c *Cache) Forever(key string, value interface{}) error {
    return c.driver.Forever(key, value)
}

// 获取后删除
func (c *Cache) Pull(key string) (interface{}, error) {
    var val interface{}
    var err error

    val, err = c.driver.Get(key)
    if err != nil {
        return val, err
    }

    c.driver.Forget(key)

    return val, nil
}

// 增加一
func (c *Cache) Increment(key string, value ...int64) error {
    return c.driver.Increment(key, value...)
}

// 减去一
func (c *Cache) Decrement(key string, value ...int64) error {
    return c.driver.Decrement(key, value...)
}

// 删除
func (c *Cache) Forget(key string) (bool, error) {
    return c.driver.Forget(key)
}

// 清空
func (c *Cache) Flush() (bool, error) {
    return c.driver.Flush()
}

// 获取前缀
func (c *Cache) GetPrefix() string {
    return c.driver.GetPrefix()
}

// 格式化时间
func (c *Cache) FormatTime(expiration interface{}) time.Duration {
    var ttl time.Duration

    if reflect.TypeOf(expiration).String() == "int64" {
        ttl = c.IntTimeToDuration(expiration.(int64))
    } else if reflect.TypeOf(expiration).String() == "int" {
        ttl = c.IntTimeToDuration(int64(expiration.(int)))
    } else {
        ttl = expiration.(time.Duration)
    }

    return ttl
}

// int64 时间格式化为 Duration 格式
func (c *Cache) IntTimeToDuration(t int64) time.Duration {
    return time.Duration(t) * time.Second
}

