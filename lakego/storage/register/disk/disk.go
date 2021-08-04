package disk

import(
    "sync"
    "lakego-admin/lakego/fllesystem/interfaces"
)

// 锁
var diskLock = new(sync.RWMutex)

var instance *Disk
var once sync.Once

/**
 * 注册磁盘
 */
func RegisterDisk(name string, f func() interfaces.Fllesystem) {
    New().With(name, f)
}

/**
 * 获取已注册磁盘
 */
func GetDisk(name string) interfaces.Fllesystem {
    return New().Get(name)
}

/**
 * 单例模式
 */
func New() *Disk {
    once.Do(func() {
        register := make(map[string]func() interfaces.Fllesystem)
        instance = &Disk{
            registers: register,
        }
    })

    return instance
}

/**
 * 磁盘
 */
type Disk struct {
    // 已注册数据
    registers map[string]func() interfaces.Fllesystem
}

// 注册
func (d *Disk) With(name string, f func() interfaces.Fllesystem) {
    diskLock.Lock()
    defer diskLock.Unlock()

    if exists := d.Exists(name); exists {
        d.Delete(name)
    }

    d.registers[name] = f
}

/**
 * 获取
 */
func (d *Disk) Get(name string) interfaces.Fllesystem {
    if value, exists := d.registers[name]; exists {
        return value()
    }

    return nil
}

/**
 * 判断
 */
func (d *Disk) Exists(name string) bool {
    if _, exists := d.registers[name]; exists {
        return true
    }

    return false
}

/**
 * 删除
 */
func (d *Disk) Delete(name string) {
    delete(d.registers, name)
}

