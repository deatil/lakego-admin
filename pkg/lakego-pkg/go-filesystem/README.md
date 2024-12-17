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
    "fmt"

    "github.com/deatil/go-filesystem/filesystem"
    local_adapter "github.com/deatil/go-filesystem/filesystem/adapter/local"
)

func main() {
    // 根目录
    root := "/storage"
    adapter := local_adapter.New(root)

    // 磁盘
    fs := filesystem.New(adapter)

    // 写入数据
    path := "/path.txt"
    contents := []byte("")

    ok, err := fs.Write(path, contents)
    if err != nil {
        fmt.Println(err.Error())
    }
}
~~~


### 常用方法

~~~go
// 写入
fs.Write(path, contents string) (bool, error)

// 写入数据流
fs.WriteStream(path string, resource io.Reader) (bool, error)

// 添加数据
fs.Put(path, contents string) (bool, error)

// 添加数据流
fs.PutStream(path string, resource io.Reader) (bool, error)

// 读取后删除
fs.ReadAndDelete(path string) (any, error)

// 更新
fs.Update(path, contents string) (bool, error)

// 读取
fs.Read(path string) (string, error)

// 重命名
fs.Rename(path, newpath string) (bool, error)

// 复制
fs.Copy(path, newpath string) (bool, error)

// 删除
fs.Delete(path string) (bool, error)

// 删除文件夹
fs.DeleteDir(dirname string) (bool, error)

// 创建文件夹
fs.CreateDir(dirname string) (bool, error)

// 列出内容
fs.ListContents(dirname string) ([]map[string]any, error)
~~~


### 开源协议

*  `go-filesystem` 文件管理器 遵循 `Apache2` 开源协议发布，在保留本软件版权的情况下提供个人及商业免费使用。


### 版权

*  该系统所属版权归 deatil(https://github.com/deatil) 所有。
