package kernel

import(
    "sync"

    providerInterface "github.com/deatil/lakego-admin/lakego/provider/interfaces"
)

// 锁
var lock = new(sync.RWMutex)

var instance *Register
var once sync.Once

/**
 * 单例模式
 */
func NewRegister() *Register {
    once.Do(func() {
        instance = &Register{
            providers: make([]Provider, 0),
        }
    })

    return instance
}

// 添加服务提供者
func AddProvider(f func() interface{}) {
    NewRegister().With(f)
}

type (
    // 服务提供者
    Provider = func() providerInterface.ServiceProvider
)

/**
 * 注册器
 *
 * @create 2021-12-19
 * @author deatil
 */
type Register struct {
    // 服务提供者
    providers []Provider
}

// 注册
func (this *Register) With(f func() interface{}) *Register {
    lock.Lock()
    defer lock.Unlock()

    addProvider := f()

    // 判断是否为服务提供者
    switch addProvider.(type) {
        case providerInterface.ServiceProvider:
            this.providers = append(this.providers, func() providerInterface.ServiceProvider {
                return addProvider.(providerInterface.ServiceProvider)
            })
    }

    return this
}

/**
 * 获取全部
 */
func (this *Register) GetALL() []Provider {
    return this.providers
}
