package register

import(
    "sync"
    "lakego-admin/lakego/fllesystem/interfaces"
)

// 锁
var registerLock = new(sync.RWMutex)

var instance *Register
var once sync.Once

/**
 * 注册适配器
 */
func RegisterFllesystem(driver string, f func() interfaces.Fllesystem) {
    New().With(driver, f)
}

/**
 * 获取已注册适配器
 */
func GetFllesystem(driver string) interfaces.Fllesystem {
    return New().Get(driver)
}

/**
 * 单例模式
 */
func New() *Register {
    once.Do(func() {
        instance = &Register{}
    })

    return instance
}

/**
 * 文件管理器适配器注册器
 */
type Register struct {
    // 已注册数据
    registers sync.Map
}

/ 注册服务提供者
func (reg *Register) With(name string, f func() interfaces.Fllesystem) {
    registerLock.Lock()
    defer registerLock.Unlock()

    if exists := reg.Exists(name); exists {
        reg.Delete(name)
    }

    reg.registers.Store(name, f)
}

/**
 * 获取中间件
 */
func (reg *Register) Get(name string) interfaces.Fllesystem {
    if value, exists := reg.registers.Load(name); exists {
        return value()
    }

    return nil
}

/**
 * 判断
 */
func (reg *Register) Exists(name string) bool {
    if _, exists := reg.registers.Load(name); exists {
        return true
    }

    return false
}

/**
 * 删除
 */
func (reg *Register) Delete(name string) {
    reg.registers.Delete(name)
}

