## 时间使用


### 项目介绍

*  时间各种简单的使用


### 使用方法

~~~go
package main

import (
    "fmt"
    "github.com/deatil/lakego-doak/lakego/support/datebin"
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
