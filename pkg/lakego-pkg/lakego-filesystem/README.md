## 本地文件管理


### 项目介绍

*  lakego-filesystem 是一个 go 版本的本地文件管理器


### 下载安装

~~~go
go get -u github.com/deatil/lakego-filesystem
~~~


### 使用

~~~go
package main

import (
    "fmt"
    "github.com/deatil/lakego-filesystem/filesystem"
)

func main() {
    fs := filesystem.New()

    file := "./runtime/test/13123/123321.txt"
    fileInfo, err := fs.Get(file)
    if err != nil {
        fmt.Println("打开文件错误，原因为：", err.Error())
    }

    fmt.Println("结果：", fileInfo)
}

~~~


### 开源协议

*  本软件包遵循 `Apache2` 开源协议发布，在保留本软件包版权的情况下提供个人及商业免费使用。


### 版权

*  本软件包所属版权归 deatil(https://github.com/deatil) 所有。
