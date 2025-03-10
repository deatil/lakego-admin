package provider

import(
    "sync"

    iprovider "github.com/deatil/lakego-doak/lakego/provider/interfaces"
)

// 添加服务提供者
func AppendProvider(f func() iprovider.ServiceProvider) {
    defaultRegister.Append(f)
}

// 获取全部添加的服务提供者
func GetAllProvider() []func() iprovider.ServiceProvider {
    return defaultRegister.GetAll()
}

// 默认
var defaultRegister = NewRegister()

/**
 * 注册器
 *
 * @create 2021-9-8
 * @author deatil
 */
type Register struct {
    // 读写锁
    mu sync.RWMutex

    // 服务提供者
    providers []func() iprovider.ServiceProvider
}

// 构造函数
func NewRegister() *Register {
    reg := new(Register)
    reg.providers = make([]func() iprovider.ServiceProvider, 0)

    return reg
}

// 注册
func (this *Register) Append(f func() iprovider.ServiceProvider) {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.providers = append(this.providers, f)
}

// 获取全部
func (this *Register) GetAll() []func() iprovider.ServiceProvider {
    return this.providers
}

