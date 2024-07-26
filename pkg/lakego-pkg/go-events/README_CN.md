## go-events

<p align="center">
<a href="https://pkg.go.dev/github.com/deatil/go-events" target="_blank"><img src="https://pkg.go.dev/badge/deatil/go-events.svg" alt="Go Reference" /></a>
<a href="https://app.codecov.io/gh/deatil/go-events" target="_blank"><img src="https://codecov.io/gh/deatil/go-events/graph/badge.svg?token=SS2Z1IY0XL" /></a>
<img src="https://goreportcard.com/badge/github.com/deatil/go-events" />
</p>


### 项目介绍

*  go 实现的事件及事件订阅, 帮助函数逻辑类似于 wordpress 插件 hook 函数

中文 | [English](README.md)


### 下载安装

~~~go
go get -u github.com/deatil/go-events
~~~


### 使用

~~~go
package main

import (
    "fmt"
    "github.com/deatil/go-events/events"
)

func main() {
    // 注册动作事件
    events.AddAction("test1", func() {
        fmt.Println("test1")
    }, events.DefaultSort)
    
    events.DoAction("test1")
    
    // 注册过滤器事件
    events.AddFilter("test1", func(val string) string {
        return "run test1 => " + val
    }, events.DefaultSort)

    data1 := "init1"
    test := events.ApplyFilters("test1", data1)
    
    fmt.Println(test)
    // 输出: run test1 => init1 
}
~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
