package database

import(
    "sync"
    "lakego-admin/lakego/database/interfaces"
)

// 锁
var lock = new(sync.RWMutex)

var instance *Database
var once sync.Once

/**
 * 单例模式
 */
func New() *Database {
    once.Do(func() {
        register := make(map[string]func() interfaces.Database)
        used := make(map[string]interfaces.Database)

        instance = &Database{
            registers: register,
            used: used,
        }
    })

    return instance
}

/**
 * 磁盘
 */
type Database struct {
    // 已注册数据
    registers map[string]func() interfaces.Database

    // 已使用
    used map[string]interfaces.Database
}

// 注册
func (d *Database) With(name string, f func() interfaces.Database) {
    lock.Lock()
    defer lock.Unlock()

    if exists := d.Exists(name); exists {
        d.Delete(name)
    }

    d.registers[name] = f
}

/**
 * 获取
 */
func (d *Database) Get(name string, once ...bool) interfaces.Database {
    if len(once) > 0 && once[0] {
        if used, is := d.used[name]; is {
            return used
        }
    }

    if value, exists := d.registers[name]; exists {
        d.used[name] = value()

        return d.used[name]
    }

    return nil
}

/**
 * 获取单列
 */
func (d *Database) GetOnce(name string) interfaces.Database {
    return d.Get(name, true)
}

/**
 * 判断
 */
func (d *Database) Exists(name string) bool {
    if _, exists := d.registers[name]; exists {
        return true
    }

    return false
}

/**
 * 删除
 */
func (d *Database) Delete(name string) {
    delete(d.registers, name)
}

