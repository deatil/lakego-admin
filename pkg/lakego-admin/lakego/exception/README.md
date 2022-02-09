### 使用方法

~~~go
package main

import "github.com/deatil/lakego-admin/lakego/exception"

exception.
    Try(func() {
        panic("exception error")
    }).
    Catch(func(e exception.Exception) {
        fmt.Println(e.GetMessage())
    })

~~~
