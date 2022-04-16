package di

import (
    "go.uber.org/dig"
)

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
