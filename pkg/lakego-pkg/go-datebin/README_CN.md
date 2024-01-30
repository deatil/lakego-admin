## go-datebin

<p align="center">
<a href="https://pkg.go.dev/github.com/deatil/go-datebin"><img src="https://pkg.go.dev/badge/deatil/go-datebin.svg" alt="Go Reference"></a>
<a href="https://codecov.io/gh/deatil/go-datebin" >
 <img src="https://codecov.io/gh/deatil/go-datebin/graph/badge.svg?token=SS2Z1IY0XL"/>
</a>
<img src="https://goreportcard.com/badge/github.com/deatil/go-datebin" />
<a href="https://github.com/avelino/awesome-go"><img src="https://awesome.re/mentioned-badge.svg" alt="Mentioned in Awesome Go"></a>
</p>


### 项目介绍

*  go-datebin 是一个简单易用的 go 时间处理库

中文 | [English](README.md)


### 下载安装

~~~go
go get -u github.com/deatil/go-datebin
~~~


### 开始使用

~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-datebin/datebin"
)

func main() {
    // 当前时间
    date := datebin.
        Now().
        ToDatetimeString()
    // 输出: 2024-01-06 12:06:12

    // 解析时间，不带时区
    date2 := datebin.
        Parse("2032-03-15 12:06:17").
        ToDatetimeString(datebin.UTC)
    // 输出: 2032-03-15 12:06:17

    // 解析时间，带时区
    date2 := datebin.
        ParseWithLayout("2032-03-15 12:06:17", datebin.DatetimeFormat, datebin.GMT).
        ToDatetimeString()
    // 输出: 2032-03-15 12:06:17

    // 设置时间并输出格式化时间
    date3 := datebin.
        FromDatetime(2032, 3, 15, 12, 56, 5).
        ToFormatString("Y/m/d H:i:s")
    // 输出: 2032/03/15 12:56:05
}

~~~


### 常用示例

~~~go
// 格式化时间戳
var datetimeString string = datebin.FromTimestamp(1705329727, datebin.Shanghai).ToDatetimeString()
// 输出: 2024-01-15 22:42:07

// 格式化时间戳带时区
var datetimeString string = datebin.FromTimestamp(1705329727).ToDatetimeString(datebin.Shanghai)
// 输出: 2024-01-15 22:42:07
~~~

~~~go
// 获取当前时间戳
var timestamp int64 = datebin.Now().Timestamp()
// 输出: 1705329727
~~~

~~~go
// 获取当前时间
var timestamp int64 = datebin.Now(datebin.Iran).ToRFC1123String()
// 输出: Sun, 21 Jan 2024 07:48:22 +0330
~~~

~~~go
// 获取当前时间的标准时间
var stdTime time.Time = datebin.Now().ToStdTime()
// fmt.Sprintf("%s", stdTime) 输出: 2024-01-15 23:55:03.0770405 +0800 CST

// 获取当前时间的标准时间带时区
var stdTime time.Time = datebin.Now(datebin.UTC).ToStdTime()
// fmt.Sprintf("%s", stdTime) 输出: 2024-01-19 01:59:11.8134897 +0000 UTC
~~~

~~~go
// 格式化标准时间
var datetimeString string = datebin.FromStdTime(stdTime).ToDatetimeString()
// 输出: 2024-01-15 23:55:03
~~~

~~~go
// 格式化日期时间
var datetimeString string = datebin.FromDatetime(2024, 01, 15, 23, 35, 01).ToDatetimeString()
// 输出: 2024-01-15 23:35:01
~~~

更多示例可点击查看 [使用文档](example.md)


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
