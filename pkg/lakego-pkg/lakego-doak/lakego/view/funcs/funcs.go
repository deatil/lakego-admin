package funcs

import(
    "sync"
)

var instance *Funcs
var once sync.Once

// 单例
func Instance() *Funcs {
    once.Do(func() {
        instance = New()
    })

    return instance
}

// 构造函数
func New() *Funcs {
    return &Funcs{
        fns: make(FuncMap),
    }
}

type (
    // 方法列表
    FuncMap = map[string]any
)

/**
 * 函数
 *
 * @create 2022-7-11
 * @author deatil
 */
type Funcs struct {
    // 锁定
    mu  sync.RWMutex

    // 已注册函数
    fns FuncMap
}

// 添加函数
func (this *Funcs) AddFunc(name string, fn any) *Funcs {
    this.mu.Lock()
    defer this.mu.Unlock()

    if _, exists := this.fns[name]; exists {
        delete(this.fns, name)
    }

    this.fns[name] = fn

    return this
}

// 批量添加函数
func (this *Funcs) AddFuncs(data FuncMap) *Funcs {
    if len(data) > 0 {
        for name, fn := range data {
            this.AddFunc(name, fn)
        }
    }

    return this
}

// 是否存在
func (this *Funcs) HasFunc(name string) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    _, exists := this.fns[name]

    return exists
}

// 移除已注册函数
func (this *Funcs) RemoveFunc(name string) {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.fns, name)
}

// 获取全部注册函数
func (this *Funcs) GetAllFuncs() FuncMap {
    this.mu.Lock()
    defer this.mu.Unlock()

    return this.fns
}
