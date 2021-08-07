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
        instance = &Database{
            registers: register,
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
func (d *Database) Get(name string) interfaces.Database {
    if value, exists := d.registers[name]; exists {
        return value()
    }

    return nil
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

