## go-datebin

<p align="center">
<a href="https://pkg.go.dev/github.com/deatil/go-datebin"><img src="https://pkg.go.dev/badge/deatil/go-datebin.svg" alt="Go Reference"></a>
<a href="https://codecov.io/gh/deatil/go-datebin" >
 <img src="https://codecov.io/gh/deatil/go-datebin/graph/badge.svg?token=SS2Z1IY0XL"/>
</a>
<img src="https://goreportcard.com/badge/github.com/deatil/go-datebin" />
<a href="https://github.com/avelino/awesome-go"><img src="https://awesome.re/mentioned-badge.svg" alt="Mentioned in Awesome Go"></a>
</p>


### Desc

*  go-datebin is a simple datetime parse pkg.

[中文](README_CN.md) | English


### Download

~~~go
go get -u github.com/deatil/go-datebin
~~~


### Get Starting

~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-datebin/datebin"
)

func main() {
    // now time
    date := datebin.
        Now().
        ToDatetimeString()
    // output: 2024-01-06 12:06:12

    // Parse date and have no timezone
    date2 := datebin.
        Parse("2032-03-15 12:06:17").
        ToDatetimeString(datebin.UTC)
    // output: 2032-03-15 12:06:17

    // Parse date and have timezone
    date2 := datebin.
        ParseWithLayout("2032-03-15 12:06:17", datebin.DatetimeFormat, datebin.GMT).
        ToDatetimeString()
    // output: 2032-03-15 12:06:17

    // set time and format output
    date3 := datebin.
        FromDatetime(2032, 3, 15, 12, 56, 5).
        ToFormatString("Y/m/d H:i:s")
    // output: 2032/03/15 12:56:05
}

~~~


### Examples

~~~go
// format timestamp
var datetimeString string = datebin.FromTimestamp(1705329727, datebin.Shanghai).ToDatetimeString()
// output: 2024-01-15 22:42:07

// format timestamp with timezone
var datetimeString string = datebin.FromTimestamp(1705329727).ToDatetimeString(datebin.Shanghai)
// output: 2024-01-15 22:42:07
~~~

~~~go
// get now timestamp
var timestamp int64 = datebin.Now().Timestamp()
// output: 1705329727
~~~

~~~go
// get now time
var timestamp int64 = datebin.Now(datebin.Iran).ToRFC1123String()
// output: Sun, 21 Jan 2024 07:48:22 +0330
~~~

~~~go
// get now stdtime
var stdTime time.Time = datebin.Now().ToStdTime()
// fmt.Sprintf("%s", stdTime) output: 2024-01-15 23:55:03.0770405 +0800 CST

// get now stdtime with timezone
var stdTime time.Time = datebin.Now(datebin.UTC).ToStdTime()
// fmt.Sprintf("%s", stdTime) output: 2024-01-19 01:59:11.8134897 +0000 UTC
~~~

~~~go
// format stdtime
var datetimeString string = datebin.FromStdTime(stdTime).ToDatetimeString()
// output: 2024-01-15 23:55:03
~~~

~~~go
// format datetime
var datetimeString string = datebin.FromDatetime(2024, 01, 15, 23, 35, 01).ToDatetimeString()
// output: 2024-01-15 23:35:01
~~~

more docs and see [docs](docs.md)


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
