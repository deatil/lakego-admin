package di

import (
    "sync"
    "go.uber.org/dig"
)

var instance *DI
var once sync.Once

/**
 * 单例模式
 */
func New() *DI {
    once.Do(func() {
        instance = &DI{
            container: dig.New(),
        }
    })

    return instance
}

/**
 * 容器
 *
 * @create 2021-10-20
 * @author deatil
 */
type DI struct {
    // 容器
    container *dig.Container
}

// 设置容器
func (this *DI) WithContainer(container *dig.Container) error {
    this.container = container

    return nil
}

// 获取容器
func (this *DI) GetContainer() *dig.Container {
    return this.container
}

// 绑定
// dig.Group("ro")
// dig.LocationForPC("ro")
// DI.Provide(newFile, dig.As(new(io.Reader)), dig.Name("temp"))
func (this *DI) Provide(constructor interface{}, opts ...dig.ProvideOption) error {
    return this.Container.Provide(constructor, opts...)
}

// 使用
func (this *DI) Invoke(function interface{}, opts ...dig.InvokeOption) error {
    return this.Container.Invoke(function, opts...)
}
