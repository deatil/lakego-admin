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
        register := make(map[string]func(map[string]interface{}) interface{})
        used := make(map[string]interface{})

        instance = &Register{
            registers: register,
            used: used,
        }
    })

    return instance
}

type (
    // 注册的方法
    RegisterFunc = func(map[string]interface{}) interface{}

    // 配置 Map
    ConfigMap = map[string]interface{}

    // 已注册 Map
    RegistersMap = map[string]RegisterFunc

    // 已使用 Map
    UsedMap = map[string]interface{}
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

    if exists := this.Exists(name); exists {
        this.Delete(name)
    }

    this.registers[name] = f
}

/**
 * 获取
 */
func (this *Register) Get(name string, conf ConfigMap) interface{} {
    var value RegisterFunc
    var exists bool

    this.WithRLock(func() {
        value, exists = this.registers[name]
    })

    if exists {
        return value(conf)
    }

    return nil
}

/**
 * 获取单例
 */
func (this *Register) GetOnce(name string, conf ConfigMap) interface{} {
    var value interface{}
    var exists bool

    this.WithRLock(func() {
        value, exists = this.used[name]
    })

    if exists {
        return value
    }

    this.used[name] = this.Get(name, conf)

    return this.used[name]
}

/**
 * 判断
 */
func (this *Register) Exists(name string) bool {
    _, exists := this.registers[name]

    return exists
}

/**
 * 删除
 */
func (this *Register) Delete(name string) {
    delete(this.registers, name)
}

func (this *Register) WithLock(f func()) {
    this.mu.Lock()
    f()
    this.mu.Unlock()
}

func (this *Register) WithRLock(f func()) {
    this.mu.RLock()
    f()
    this.mu.RUnlock()
}

