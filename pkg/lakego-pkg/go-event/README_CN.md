## go 事件及事件订阅

<p align="center">
<a href="https://pkg.go.dev/github.com/deatil/go-event" target="_blank"><img src="https://pkg.go.dev/badge/deatil/go-event.svg" alt="Go Reference" /></a>
<a href="https://app.codecov.io/gh/deatil/go-event" target="_blank"><img src="https://codecov.io/gh/deatil/go-event/graph/badge.svg?token=SS2Z1IY0XL" /></a>
<img src="https://goreportcard.com/badge/github.com/deatil/go-event" />
</p>


### 项目介绍

*  go 实现的事件及事件订阅

中文 | [English](README.md)


### 下载安装

~~~go
go get -u github.com/deatil/go-event
~~~


### 使用

~~~go
package main

import (
    "fmt"
    "github.com/deatil/go-event/event"
)

type TestEvent struct {}

func (this *TestEvent) OnTestEvent(data any) {
    fmt.Println("TestEvent: ")
    fmt.Println(data)
}

func (this *TestEvent) OnTestEventName(data any, name string) {
    fmt.Println("TestEventName: ")
    fmt.Println(data)
    fmt.Println(name)
}

type TestEventPrefix struct {}

func (this TestEventPrefix) EventPrefix() string {
    return "ABC"
}

func (this TestEventPrefix) OnTestEvent(data any) {
    fmt.Println("TestEventPrefix: ")
    fmt.Println(data)
}

type TestEventSubscribe struct {}

func (this *TestEventSubscribe) Subscribe(e *event.Events) {
    e.Listen("TestEventSubscribe", this.OnTestEvent)
}

func (this *TestEventSubscribe) OnTestEvent(data any) {
    fmt.Println("TestEventSubscribe: ")
    fmt.Println(data)
}

type TestEventStructData struct {
    Data string
}

func TestEventStruct(data TestEventStructData, name any) {
    fmt.Println("TestEventStruct: ")
    fmt.Println(data.Data)
    fmt.Println(name)
}

type TestEventStructHandle struct {}

func (this *TestEventStructHandle) Handle(data any) {
    fmt.Println("TestEventStructHandle: ")
    fmt.Println(data)
}

func main() {
    // 事件注册
    event.Listen("data.error", func(data any) any {
        fmt.Println(data)
        return nil
    })

    // 事件触发
    eventData := "index data"
    event.Dispatch("data.error", eventData)

    // 触发 `data.` 为前缀的全部事件
    event.Dispatch("data.*", eventData)

    // ==================

    // 事件订阅
    event.Subscribe(&TestEvent{})
    event.Subscribe(TestEventPrefix{})
    event.Subscribe(&TestEventSubscribe{})

    // 事件订阅触发
    event.Dispatch("TestEvent", eventData)
    event.Dispatch("TestEventName", eventData)
    event.Dispatch("ABCTestEvent", eventData)
    event.Dispatch("TestEventSubscribe", eventData)

    // ==================

    // 事件注册
    event.Listen(TestEventStructData{}, TestEventStruct)

    // 事件触发
    eventData2 := "index data"
    event.Dispatch(TestEventStructData{
        Data: eventData2,
    })

    // ==================

    // 事件注册
    event.Listen("TestEventStructHandle", &TestEventStructHandle{})

    // 事件触发
    event.Dispatch("TestEventStructHandle", eventData)
}

~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
