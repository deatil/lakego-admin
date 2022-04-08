## 时间使用


### 项目介绍

*  时间各种简单的使用


### 使用方法

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

    fmt.Println("当前的时间：", date)
    fmt.Println("解析的时间：", date2)
}

~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
