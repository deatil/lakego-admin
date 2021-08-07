package driver

import(
    "sync"
    "lakego-admin/lakego/cache/interfaces"
)

// 锁
var driverLock = new(sync.RWMutex)

var instance *Driver
var once sync.Once

/**
 * 注册驱动
 */
func RegisterDriver(name string, f func() interfaces.Driver) {
    New().With(name, f)
}

/**
 * 获取已注册驱动
 */
func GetDriver(name string) interfaces.Driver {
    return New().Get(name)
}

/**
 * 单例模式
 */
func New() *Driver {
    once.Do(func() {
        register := make(map[string]func() interfaces.Driver)
        instance = &Driver{
            registers: register,
        }
    })

    return instance
}

/**
 * 驱动
 */
type Driver struct {
    // 已注册数据
    registers map[string]func() interfaces.Driver
}

// 注册
func (d *Driver) With(name string, f func() interfaces.Driver) {
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
func (d *Driver) Get(name string) interfaces.Driver {
    if value, exists := d.registers[name]; exists {
        return value()
    }

    return nil
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

