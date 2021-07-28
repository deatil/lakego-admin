package interfaces

import(
    "os"

    "lakego-admin/lakego/fllesystem/config"
    "lakego-admin/lakego/fllesystem/interfaces/adapter"
)

type Fllesystem interface {
    // 设置配置
    SetConfig(config.Config)

    // 获取配置
    GetConfig() config.Config

    // 提前设置配置
    PrepareConfig(map[string]interface{}) config.Config

    // 设置适配器
    WithAdapter(adapter.Adapter) Fllesystem

    // 获取适配器
    GetAdapter() adapter.Adapter

    // 判断
    Has(path string) bool

    // 上传
    Write(path string, contents string, conf map[string]interface{}) bool

    // 上传
    WriteStream(path string, resource *os.File, conf map[string]interface{}) bool

    // 上传
    Put(path string, contents string, conf map[string]interface{}) bool

    // 上传
    PutStream(path string, resource *os.File, conf map[string]interface{}) bool

    // 读取并删除
    ReadAndDelete(path string) (interface{}, error)

    // 更新
    Update(path string, contents string, conf map[string]interface{}) bool

    // 更新
    UpdateStream(path string, resource *os.File, conf map[string]interface{}) bool

    // 读取
    Read(path string) interface{}

    // 读取
    ReadStream(path string) interface{}

    // 重命名
    Rename(path string, newpath string) bool

    // 复制
    Copy(path string, newpath string) bool

    // 删除
    Delete(path string) bool

    // 删除文件夹
    DeleteDir(dirname string) bool

    // 创建文件夹
    CreateDir(dirname string, conf map[string]interface{}) bool

    // 列出数据
    ListContents(directory string, recursive ...bool) []map[string]interface{}

    // 文件 mime-type
    GetMimetype(path string) string

    // 文件时间
    GetTimestamp(path string) int64

    // 权限
    GetVisibility(path string) string

    // 大小
    GetSize(path string) int64

    // 设置权限
    SetVisibility(path string, visibility string) bool

    // 信息数据
    GetMetadata(path string) map[string]interface{}

    // 获取
    Get(path string) interface{}
}
