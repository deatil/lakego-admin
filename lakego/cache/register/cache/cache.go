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
 * 单例模式
 */
func New() *Cache {
    once.Do(func() {
        register := make(map[string]func() interfaces.Cache)
        used := make(map[string]interfaces.Cache)

        instance = &Cache{
            registers: register,
            used: used,
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

    // 已使用
    used map[string]interfaces.Cache
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
func (c *Cache) Get(name string, once ...bool) interfaces.Cache {
    if len(once) > 0 && once[0] {
        if used, is := c.used[name]; is {
            return used
        }
    }

    if value, exists := c.registers[name]; exists {
        c.used[name] = value()

        return c.used[name]
    }

    return nil
}

/**
 * 获取单列
 */
func (c *Cache) GetOnce(name string) interfaces.Cache {
    return c.Get(name, true)
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

