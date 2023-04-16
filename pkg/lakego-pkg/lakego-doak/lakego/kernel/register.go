package kernel

import(
    "sync"

    "github.com/deatil/lakego-doak/lakego/provider/interfaces"
)

type (
    // 服务提供者接口
    IServiceProvider = interfaces.ServiceProvider

    // 服务提供者函数
    Provider = func() IServiceProvider
)

// 默认
var defaultRegister = NewRegister()

// 构造函数
func NewRegister() *Register {
    return &Register{
        providers: make([]Provider, 0),
    }
}

/**
 * 注册器
 *
 * @create 2021-12-19
 * @author deatil
 */
type Register struct {
    // 锁定
    mu sync.RWMutex

    // 服务提供者
    providers []Provider
}

// 添加服务提供者
func (this *Register) AddProvider(fn func() any) *Register {
    this.mu.Lock()
    defer this.mu.Unlock()

    provider := fn()

    // 判断是否为服务提供者
    switch p := provider.(type) {
        case IServiceProvider:
            this.providers = append(this.providers, func() IServiceProvider {
                return p
            })
    }

    return this
}

// 添加服务提供者
func AddProvider(f func() any) *Register {
    return defaultRegister.AddProvider(f)
}

// 获取全部服务提供者
func (this *Register) GetAllProvider() []Provider {
    return this.providers
}

// 获取全部服务提供者
func GetAllProvider() []Provider {
    return defaultRegister.GetAllProvider()
}
