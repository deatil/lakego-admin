package interfaces

import(
    "os"

    "lakego-admin/lakego/fllesystem/config"
)

type Fllesystem interface {
    // 设置配置
    SetConfig(*config.Config)

    // 获取配置
    GetConfig() *config.Config

    // 提前设置配置
    PrepareConfig(map[string]interface{}) *config.Config

    // 设置适配器
    WithAdapter(Adapter) Fllesystem

    // 获取适配器
    GetAdapter() Adapter

    // 判断
    Has(string) bool

    // 上传
    Write(string, string, ...map[string]interface{}) bool

    // 上传
    WriteStream(string, *os.File, ...map[string]interface{}) bool

    // 上传
    Put(string, string, ...map[string]interface{}) bool

    // 上传
    PutStream(string, *os.File, ...map[string]interface{}) bool

    // 读取并删除
    ReadAndDelete(string) (interface{}, error)

    // 更新
    Update(string, string, ...map[string]interface{}) bool

    // 更新
    UpdateStream(string, *os.File, ...map[string]interface{}) bool

    // 读取
    Read(string) interface{}

    // 读取
    ReadStream(string) interface{}

    // 重命名
    Rename(string, string) bool

    // 复制
    Copy(string, string) bool

    // 删除
    Delete(string) bool

    // 删除文件夹
    DeleteDir(string) bool

    // 创建文件夹
    CreateDir(string, ...map[string]interface{}) bool

    // 列出数据
    ListContents(string, ...bool) []map[string]interface{}

    // 文件 mime-type
    GetMimetype(string) string

    // 文件时间
    GetTimestamp(string) int64

    // 权限
    GetVisibility(string) string

    // 大小
    GetSize(string) int64

    // 设置权限
    SetVisibility(string, string) bool

    // 信息数据
    GetMetadata(string) map[string]interface{}

    // 获取
    Get(string) interface{}
}
