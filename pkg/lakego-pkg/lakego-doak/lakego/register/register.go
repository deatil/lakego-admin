package register

import(
    "sync"
)

var instance *Register
var once sync.Once

/**
 * 单例模式
 */
func New() *Register {
    once.Do(func() {
        instance = &Register{
            registers: make(RegistersMap),
            used:      make(UsedMap),
        }
    })

    return instance
}

type (
    // 配置 Map
    ConfigMap = map[string]any

    // 注册的方法
    RegisterFunc = func(ConfigMap) any

    // 已注册 Map
    RegistersMap = map[string]RegisterFunc

    // 已使用 Map
    UsedMap = map[string]any
)

/**
 * 注册器
 *
 * @create 2021-9-6
 * @author deatil
 */
type Register struct {
    // 锁定
    mu sync.RWMutex

    // 已注册数据
    registers RegistersMap

    // 已使用
    used UsedMap
}

// 注册
func (this *Register) With(name string, f RegisterFunc) {
    this.mu.Lock()
    defer this.mu.Unlock()

    if _, exists := this.registers[name]; exists {
        delete(this.registers, name)
    }

    this.registers[name] = f
}

// 获取
func (this *Register) Get(name string, conf ConfigMap) any {
    this.mu.RLock()
    defer this.mu.RUnlock()

    value, exists := this.registers[name]
    if exists {
        return value(conf)
    }

    return nil
}

// 获取单例
func (this *Register) GetOnce(name string, conf ConfigMap) any {
    this.mu.RLock()
    defer this.mu.RUnlock()

    // 存在
    value, exists := this.used[name]
    if exists {
        return value
    }

    // 不存在
    value2, exists2 := this.registers[name]
    if exists2 {
        this.used[name] = value2(conf)

        return this.used[name]
    }

    return nil
}

// 判断
func (this *Register) Exists(name string) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    _, exists := this.registers[name]

    return exists
}

// 删除
func (this *Register) Delete(name string) {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.registers, name)
}
