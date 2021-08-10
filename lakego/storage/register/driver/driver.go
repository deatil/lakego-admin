package driver

import(
    "sync"
    "lakego-admin/lakego/fllesystem/interfaces"
)

// 锁
var driverLock = new(sync.RWMutex)

var instance *Driver
var once sync.Once

/**
 * 单例模式
 */
func New() *Driver {
    once.Do(func() {
        register := make(map[string]func() interfaces.Adapter)
        used := make(map[string]interfaces.Adapter)

        instance = &Driver{
            registers: register,
            used: used,
        }
    })

    return instance
}

/**
 * 适配器
 */
type Driver struct {
    // 已注册数据
    registers map[string]func() interfaces.Adapter

    // 已使用
    used map[string]interfaces.Adapter
}

// 注册
func (d *Driver) With(name string, f func() interfaces.Adapter) {
    driverLock.Lock()
    defer driverLock.Unlock()

    if exists := d.Exists(name); exists {
        d.Delete(name)
    }

    d.registers[name] = f
}

/**
 * 获取
 */
func (d *Driver) Get(name string, once ...bool) interfaces.Adapter {
    if len(once) > 0 && once[0] {
        if useDriver, existsDriver := d.used[name]; existsDriver {
            return useDriver
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
func (d *Driver) GetOnce(name string) interfaces.Adapter {
    return d.Get(name, true)
}

/**
 * 判断
 */
func (d *Driver) Exists(name string) bool {
    if _, exists := d.registers[name]; exists {
        return true
    }

    return false
}

/**
 * 删除
 */
func (d *Driver) Delete(name string) {
    delete(d.registers, name)
}

