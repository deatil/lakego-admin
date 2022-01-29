## 文件管理器


### 项目介绍

*  go 版本实现的文件管理器


### 驱动

*  `local`: 本地存储


### 示例

~~~go
import (
    "github.com/deatil/go-filesystem/filesystem"
    localAdapter "github.com/deatil/go-filesystem/filesystem/adapter/local"
)

func init() {
    // 根目录
    root := "/storage"
    driver := localAdapter.New(root)
    
    // 格式为 map[string]interface{}
    diskConf := ...
    
    // 磁盘
    disk := filesystem.New(driver, diskConf)

    // 使用
    disk.Write(path string, contents string) bool
}
~~~


### 常用方法

~~~go
// 写入
disk.Write(path, contents string) bool
// 添加数据
disk.Put(path, contents string) bool
// 读取后删除
disk.ReadAndDelete(path string) (interface{}, error)
// 更新
disk.Update(path, contents string) bool
// 读取
disk.Read(path string) interface{}
// 重命名
disk.Rename(path, newpath string) bool
// 复制
disk.Copy(path, newpath string) bool
// 删除
disk.Delete(path string) bool
// 删除文件夹
disk.DeleteDir(dirname string) bool
// 创建文件夹
disk.CreateDir(dirname string) bool
// 列出内容
disk.ListContents(dirname string) bool
~~~


### 开源协议

*  `go-filesystem` 文件管理器 遵循 `Apache2` 开源协议发布，在保留本软件版权的情况下提供个人及商业免费使用。


### 版权

*  该系统所属版权归 deatil(https://github.com/deatil) 所有。
