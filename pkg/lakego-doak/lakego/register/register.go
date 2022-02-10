package register

import(
    "sync"
)

// 锁
var lock = new(sync.RWMutex)

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

/**
 * 注册器
 *
 * @create 2021-9-6
 * @author deatil
 */
type Register struct {
    // 已注册数据
    registers map[string]func(map[string]interface{}) interface{}

    // 已使用
    used map[string]interface{}
}

// 注册
func (this *Register) With(name string, f func(map[string]interface{}) interface{}) {
    lock.Lock()
    defer lock.Unlock()

    if exists := this.Exists(name); exists {
        this.Delete(name)
    }

    this.registers[name] = f
}

/**
 * 获取
 */
func (this *Register) Get(name string, conf map[string]interface{}) interface{} {
    if value, exists := this.registers[name]; exists {
        return value(conf)
    }

    return nil
}

/**
 * 获取单例
 */
func (this *Register) GetOnce(name string, conf map[string]interface{}) interface{} {
    if usedValue, usedExists := this.used[name]; usedExists {
        return usedValue
    }

    this.used[name] = this.Get(name, conf)

    return this.used[name]
}

/**
 * 判断
 */
func (this *Register) Exists(name string) bool {
    if _, exists := this.registers[name]; exists {
        return true
    }

    return false
}

/**
 * 删除
 */
func (this *Register) Delete(name string) {
    delete(this.registers, name)
}

