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
 * 单例模式
 */
func New() *Disk {
    once.Do(func() {
        register := make(map[string]func() interfaces.Fllesystem)
        used := make(map[string]interfaces.Fllesystem)

        instance = &Disk{
            registers: register,
            used: used,
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

    // 已使用
    used map[string]interfaces.Fllesystem
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
func (d *Disk) Get(name string, once ...bool) interfaces.Fllesystem {
    if len(once) > 0 && once[0] {
        if useDisk, existsDisk := d.used[name]; existsDisk {
            return useDisk
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
func (d *Disk) GetOnce(name string) interfaces.Fllesystem {
    return d.Get(name, true)
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

