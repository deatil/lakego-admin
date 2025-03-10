package register

import (
    "sync"
)

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

// 默认
var defaultRegister = New()

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

// 构造函数
func New() *Register {
    reg := &Register{
        registers: make(RegistersMap),
        used:      make(UsedMap),
    }

    return reg
}

// 注册
func (this *Register) With(name string, fn RegisterFunc) {
    this.mu.Lock()
    defer this.mu.Unlock()

    if _, exists := this.registers[name]; exists {
        delete(this.registers, name)
    }

    this.registers[name] = fn
}

func With(name string, fn RegisterFunc) {
    defaultRegister.With(name, fn)
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

func Get(name string, conf ConfigMap) any {
    return defaultRegister.Get(name, conf)
}

// 获取单例
func (this *Register) GetOnce(name string, conf ConfigMap) any {
    // 存在
    this.mu.RLock()
    value, exists := this.used[name]
    this.mu.RUnlock()

    if exists {
        return value
    }

    // 不存在
    this.mu.RLock()
    fn, ok := this.registers[name]
    this.mu.RUnlock()

    if !ok {
        return nil
    }

    newFn := fn(conf)

    this.mu.Lock()
    this.used[name] = newFn
    this.mu.Unlock()

    return newFn
}

func GetOnce(name string, conf ConfigMap) any {
    return defaultRegister.GetOnce(name, conf)
}

// 判断
func (this *Register) Exists(name string) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    _, exists := this.registers[name]

    return exists
}

func Exists(name string) bool {
    return defaultRegister.Exists(name)
}

// 删除
func (this *Register) Delete(name string) {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.registers, name)
}

func Delete(name string) {
    defaultRegister.Delete(name)
}
