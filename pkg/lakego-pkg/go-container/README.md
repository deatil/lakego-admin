## go-container

<p align="center">
<a href="https://pkg.go.dev/github.com/deatil/go-container" target="_blank"><img src="https://pkg.go.dev/badge/deatil/go-container.svg" alt="Go Reference"></a>
<a href="https://app.codecov.io/gh/deatil/go-container" target="_blank"><img src="https://codecov.io/gh/deatil/go-container/graph/badge.svg?token=SS2Z1IY0XL"/></a>
<img src="https://goreportcard.com/badge/github.com/deatil/go-container" />
</p>


### Desc

*  go-container is a container pkg for go.

[中文](README_CN.md) | English


### Download

~~~go
go get -u github.com/deatil/go-container
~~~


### Get Starting

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
    // Bind func
    di := container.DI()
    di.Bind("testBind", func() *testBind {
        return &testBind{}
    })
    tb := di.Get("testBind")

    tb2, _ := tb.(*testBind)
    
    fmt.Printf("output: %s", tb2.Data())
    // output: testBind data
}

~~~


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
