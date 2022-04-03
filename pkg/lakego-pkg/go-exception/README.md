### 使用方法

~~~go
package main

import "github.com/deatil/go-exception/exception"

exception.
    Try(func() {
        panic("exception error")
    }).
    Catch(func(e exception.Exception) {
        fmt.Println(e.GetMessage())
    })

~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
