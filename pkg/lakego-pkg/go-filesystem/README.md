## 文件管理器


### 项目介绍

*  go 版本实现的文件管理器


### 适配器

*  `local`: 本地存储


### 下载安装

~~~go
go get -u github.com/deatil/go-filesystem
~~~


### 示例

~~~go
import (
    "github.com/deatil/go-filesystem/filesystem"
    localAdapter "github.com/deatil/go-filesystem/filesystem/adapter/local"
)

func goFilesystem() {
    // 根目录
    root := "/storage"
    adapter := localAdapter.New(root)

    // 磁盘
    fs := filesystem.New(adapter)

    // 使用
    fs.Write(path string, contents string) bool
}
~~~


### 常用方法

~~~go
// 写入
fs.Write(path, contents string) bool

// 写入数据流
fs.WriteStream(path string, resource io.Reader) bool

// 添加数据
fs.Put(path, contents string) bool

// 添加数据流
fs.PutStream(path string, resource io.Reader) bool

// 读取后删除
fs.ReadAndDelete(path string) (any, error)

// 更新
fs.Update(path, contents string) bool

// 读取
fs.Read(path string) any

// 重命名
fs.Rename(path, newpath string) bool

// 复制
fs.Copy(path, newpath string) bool

// 删除
fs.Delete(path string) bool

// 删除文件夹
fs.DeleteDir(dirname string) bool

// 创建文件夹
fs.CreateDir(dirname string) bool

// 列出内容
fs.ListContents(dirname string) bool
~~~


### 开源协议

*  `go-filesystem` 文件管理器 遵循 `Apache2` 开源协议发布，在保留本软件版权的情况下提供个人及商业免费使用。


### 版权

*  该系统所属版权归 deatil(https://github.com/deatil) 所有。
