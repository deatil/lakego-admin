package provider

import(
    "sync"

    providerInterface "lakego-admin/lakego/provider/interfaces"
)

// 锁
var lock = new(sync.RWMutex)

var instance *Register
var once sync.Once

// 添加服务提供者
func AppendProvider(f func() providerInterface.ServiceProvider) {
    NewRegister().Append(f)
}

// 获取全部添加的服务提供者
func GetAllProvider() []func() providerInterface.ServiceProvider {
    return NewRegister().GetAll()
}

/**
 * 单例模式
 */
func NewRegister() *Register {
    once.Do(func() {
        providers := make([]func() providerInterface.ServiceProvider, 0)

        instance = &Register{
            providers: providers,
        }
    })

    return instance
}

/**
 * 注册器
 *
 * @create 2021-9-8
 * @author deatil
 */
type Register struct {
    providers []func() providerInterface.ServiceProvider
}

// 注册
func (r *Register) Append(f func() providerInterface.ServiceProvider) {
    lock.Lock()
    defer lock.Unlock()

    r.providers = append(r.providers, f)
}

/**
 * 获取全部
 */
func (r *Register) GetAll() []func() providerInterface.ServiceProvider {
    return r.providers
}

