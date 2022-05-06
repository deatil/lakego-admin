## 时间使用


### 项目介绍

*  时间各种简单的使用


### 下载安装

~~~go
go get -u github.com/deatil/go-datebin
~~~


### 使用

~~~go
package main

import (
    "fmt"

    "github.com/deatil/go-datebin/datebin"
)

func main() {
    // 时间
    date := datebin.
        Now().
        ToDatetimeString()
    date2 := datebin.
        Parse("2032-03-15 12:06:17").
        ToDatetimeString()
    date3 := datebin.
        FromDatetime(2032, 3, 15, 12, 56, 5).
        ToDatetimeString()

    fmt.Println("当前的时间：", date)
    fmt.Println("解析的时间：", date2)
    fmt.Println("设置的时间：", date3)
}

~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
