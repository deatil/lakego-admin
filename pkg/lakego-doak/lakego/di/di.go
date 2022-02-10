package di

import (
    "io"
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

type (
    // 选项
    Option = dig.Option

    // 设置选项
    ProvideOption = dig.ProvideOption

    // 使用选项
    InvokeOption = dig.InvokeOption

    // VisualizeOption
    VisualizeOption = dig.VisualizeOption

    // 唯一ID
    ID = dig.ID

    // 结构体的信息
    ProvideInfo = dig.ProvideInfo

    // 输入
    Input = dig.Input

    // 输出
    Output = dig.Output

    // 核心容器
    Container = dig.Container

    // 结构体导入
    In = dig.In

    // 结构体导出
    Out = dig.Out
)

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
// c.Provide(newFile, dig.As(new(io.Reader)), dig.Name("temp"))
func (this *DI) Provide(constructor interface{}, opts ...dig.ProvideOption) error {
    return this.container.Provide(constructor, opts...)
}

// 使用
func (this *DI) Invoke(function interface{}, opts ...dig.InvokeOption) error {
    return this.container.Invoke(function, opts...)
}

// 命名
// c.Provide(NewReadOnlyConnection, dig.Name("ro"))
func Name(name string) dig.ProvideOption {
    return dig.Name(name)
}

// 分组
func Group(group string) dig.ProvideOption {
    return dig.Group(group)
}

// 填充信息
func FillProvideInfo(info *dig.ProvideInfo) dig.ProvideOption {
    return dig.FillProvideInfo(info)
}

// c.Provide(newFile, dig.As(new(io.Reader)), dig.Name("temp"))
func As(i ...interface{}) dig.ProvideOption {
    return dig.As(i...)
}

// dig.LocationForPC("ro")
func LocationForPC(pc uintptr) dig.ProvideOption {
    return dig.LocationForPC(pc)
}

func DeferAcyclicVerification() dig.Option {
    return dig.DeferAcyclicVerification()
}

// 创建一个没有设置的容器
func DryRun(dry bool) dig.Option {
    return dig.DryRun(dry)
}

// 是否导入
func IsIn(o interface{}) bool {
    return dig.IsIn(o)
}

// 是否导出
func IsOut(o interface{}) bool {
    return dig.IsOut(o)
}

func VisualizeError(err error) dig.VisualizeOption {
    return dig.VisualizeError(err)
}

func RootCause(err error) error {
    return dig.RootCause(err)
}

func Visualize(c *dig.Container, w io.Writer, opts ...dig.VisualizeOption) error {
    return dig.Visualize(c, w, opts...)
}

func CanVisualizeError(err error) bool {
    return dig.CanVisualizeError(err)
}
