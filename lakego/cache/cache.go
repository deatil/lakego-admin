package cache

import (
    "lakego-admin/lakego/cache/interfaces"
)

/**
 * 缓存
 *
 * @create 2021-7-15
 * @author deatil
 */
type Cache struct {
    config map[string]interface{}
    driver interfaces.Driver
}

// 创建
func New(idriver interfaces.Driver, conf ...map[string]interface{}) *Cache {
    c := &Cache{
        driver: idriver,
    }

    if len(conf) > 0{
        c.config = conf[0]
    }

    return c
}

// 获取
func (c *Cache) Get(key string) (interface{}, error) {
    return c.driver.Get(key)
}

// 设置
func (c *Cache) Put(key string, value interface{}, seconds interface{}) error {
    return c.driver.Put(key, value, seconds)
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
