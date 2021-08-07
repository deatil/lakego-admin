package cache

import(
    "sync"
    "lakego-admin/lakego/cache/interfaces"
)

// 锁
var cacheLock = new(sync.RWMutex)

var instance *Cache
var once sync.Once

/**
 * 注册缓存
 */
func RegisterCache(name string, f func() interfaces.Cache) {
    New().With(name, f)
}

/**
 * 获取已注册缓存
 */
func GetCache(name string) interfaces.Cache {
    return New().Get(name)
}

/**
 * 单例模式
 */
func New() *Cache {
    once.Do(func() {
        register := make(map[string]func() interfaces.Cache)
        instance = &Cache{
            registers: register,
        }
    })

    return instance
}

/**
 * 磁盘
 */
type Cache struct {
    // 已注册数据
    registers map[string]func() interfaces.Cache
}

// 注册
func (c *Cache) With(name string, f func() interfaces.Cache) {
    cacheLock.Lock()
    defer cacheLock.Unlock()

    if exists := c.Exists(name); exists {
        c.Delete(name)
    }

    c.registers[name] = f
}

/**
 * 获取
 */
func (c *Cache) Get(name string) interfaces.Cache {
    if value, exists := c.registers[name]; exists {
        return value()
    }

    return nil
}

/**
 * 判断
 */
func (c *Cache) Exists(name string) bool {
    if _, exists := c.registers[name]; exists {
        return true
    }

    return false
}

/**
 * 删除
 */
func (c *Cache) Delete(name string) {
    delete(c.registers, name)
}

