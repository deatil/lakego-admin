## go-events

<p align="center">
<a href="https://pkg.go.dev/github.com/deatil/go-events" target="_blank"><img src="https://pkg.go.dev/badge/deatil/go-events.svg" alt="Go Reference"></a>
<a href="https://app.codecov.io/gh/deatil/go-events" target="_blank"><img src="https://codecov.io/gh/deatil/go-events/graph/badge.svg?token=SS2Z1IY0XL"/></a>
<a href="https://goreportcard.com/report/github.com/deatil/go-events" target="_blank"><img src="https://goreportcard.com/badge/github.com/deatil/go-events" /></a>
</p>


### Desc

*  go-events is a go event and event'subscribe pkg, like wordpress hook functions.

[中文](README_CN.md) | English


### Download

~~~go
go get -u github.com/deatil/go-events
~~~


### Get Starting

~~~go
package main

import (
    "fmt"
    "github.com/deatil/go-events/events"
)

func main() {
    // use action
    events.AddAction("test1", func() {
        fmt.Println("test1")
    }, events.DefaultSort)

    events.DoAction("test1")

    // use Filter
    events.AddFilter("test1", func(val string) string {
        return "run test1 => " + val
    }, events.DefaultSort)

    data1 := "init1"
    test := events.ApplyFilters("test1", data1)

    fmt.Println(test)
    // output: run test1 => init1
}

~~~


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
