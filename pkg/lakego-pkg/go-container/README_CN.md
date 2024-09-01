## go-container

<p align="center">
<a href="https://pkg.go.dev/github.com/deatil/go-container" target="_blank"><img src="https://pkg.go.dev/badge/deatil/go-container.svg" alt="Go Reference" /></a>
<a href="https://app.codecov.io/gh/deatil/go-container" target="_blank"><img src="https://codecov.io/gh/deatil/go-container/graph/badge.svg?token=SS2Z1IY0XL" /></a>
<img src="https://goreportcard.com/badge/github.com/deatil/go-container" />
</p>


### 项目介绍

*  go 实现的容器管理库

中文 | [English](README.md)


### 下载安装

~~~go
go get -u github.com/deatil/go-container
~~~


### 使用

全局注册使用
~~~go
di := container.DI()
~~~

自定义使用
~~~go
di := container.New()
~~~

~~~go
package main

import (
    "fmt"
    "github.com/deatil/go-container/container"
)

type testBind struct {}

func (t *testBind) Data() string {
    return "testBind data"
}

func main() {
    // 绑定函数
    di := container.DI()
    di.Bind("testBind", func() *testBind {
        return &testBind{}
    })
    tb := di.Get("testBind")

    tb2, _ := tb.(*testBind)
    
    fmt.Printf("output: %s", tb2.Data())
    // output: testBind data
}

func useProvide() {
    // 使用 Provide
    di := container.DI()
    di.Provide(func() *testBind {
        return &testBind{}
    })
    di.Invoke(func(tb *testBind) {
        fmt.Printf("output: %s", tb.Data())
        // output: testBind data
    })
}
~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
