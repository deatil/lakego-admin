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
func (r *Register) With(name string, f func(map[string]interface{}) interface{}) {
    lock.Lock()
    defer lock.Unlock()

    if exists := r.Exists(name); exists {
        r.Delete(name)
    }

    r.registers[name] = f
}

/**
 * 获取
 */
func (r *Register) Get(name string, conf map[string]interface{}) interface{} {
    if value, exists := r.registers[name]; exists {
        return value(conf)
    }

    return nil
}

/**
 * 获取单例
 */
func (r *Register) GetOnce(name string, conf map[string]interface{}) interface{} {
    if usedValue, usedExists := r.used[name]; usedExists {
        return usedValue
    }

    r.used[name] = r.Get(name, conf)

    return r.used[name]
}

/**
 * 判断
 */
func (r *Register) Exists(name string) bool {
    if _, exists := r.registers[name]; exists {
        return true
    }

    return false
}

/**
 * 删除
 */
func (r *Register) Delete(name string) {
    delete(r.registers, name)
}

