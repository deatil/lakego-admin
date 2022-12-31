package funcs

import(
    "sync"
)

// 默认
var defaultFns *Funcs

// 初始化
func init() {
    defaultFns = New()
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

// 添加函数
func AddFunc(name string, fn any) *Funcs {
    return defaultFns.AddFunc(name, fn)
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

// 批量添加函数
func AddFuncs(data FuncMap) *Funcs {
    return defaultFns.AddFuncs(data)
}

// 是否存在
func (this *Funcs) HasFunc(name string) bool {
    this.mu.RLock()
    defer this.mu.RUnlock()

    _, exists := this.fns[name]

    return exists
}

// 是否存在
func HasFunc(name string) bool {
    return defaultFns.HasFunc(name)
}

// 移除已注册函数
func (this *Funcs) RemoveFunc(name string) {
    this.mu.Lock()
    defer this.mu.Unlock()

    delete(this.fns, name)
}

// 移除已注册函数
func RemoveFunc(name string) {
    defaultFns.RemoveFunc(name)
}

// 获取全部注册函数
func (this *Funcs) GetAllFunc() FuncMap {
    this.mu.Lock()
    defer this.mu.Unlock()

    return this.fns
}

// 获取全部注册函数
func GetAllFunc() FuncMap {
    return defaultFns.GetAllFunc()
}
