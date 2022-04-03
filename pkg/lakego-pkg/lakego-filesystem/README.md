## 本地文件管理


### 项目介绍

*  本地文件管理


### 使用方法

~~~go
package main

import (
    "fmt"
    "github.com/deatil/lakego-filesystem/filesystem"
)

func main() {
    fs := filesystem.New()

    img := "./runtime/test/13123/123321.txt"
    // img2 := "./runtime/test/13123"
    // txt := "./runtime/test/1/data.txt"
    fsInfo := fs.IsWritable(img)

    fmt.Println("结果：", fsInfo)
}

~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
