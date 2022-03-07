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

// 命名
// c.Provide(NewReadOnlyConnection, dig.Name("ro"))
// dig.Name(name string) dig.ProvideOption
var Name = dig.Name

// 分组
// dig.Group(group string) dig.ProvideOption
var Group = dig.Group

// 填充信息
// dig.FillProvideInfo(info *dig.ProvideInfo) dig.ProvideOption
var FillProvideInfo = dig.FillProvideInfo

// c.Provide(newFile, dig.As(new(io.Reader)), dig.Name("temp"))
// dig.As(i ...interface{}) dig.ProvideOption
var As = dig.As

// dig.LocationForPC(pc uintptr) dig.ProvideOption
var LocationForPC = dig.LocationForPC

// dig.DeferAcyclicVerification() dig.Option
var DeferAcyclicVerification = dig.DeferAcyclicVerification

// 创建一个没有设置的容器
// dig.DryRun(dry bool) dig.Option
var DryRun = dig.DryRun

// 是否导入
// dig.IsIn(o interface{}) bool
var IsIn = dig.IsIn

// 是否导出
// dig.IsOut(o interface{}) bool
var IsOut = dig.IsOut

// dig.VisualizeError(err error) dig.VisualizeOption
var VisualizeError = dig.VisualizeError

// dig.RootCause(err error) error
var RootCause = dig.RootCause

// dig.Visualize(c *dig.Container, w io.Writer, opts ...dig.VisualizeOption) error
var Visualize = dig.Visualize

// dig.CanVisualizeError(err error) bool
var CanVisualizeError = dig.CanVisualizeError

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
