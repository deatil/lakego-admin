package interfaces

import(
    "os"

    "lakego-admin/lakego/fllesystem/config"
    "lakego-admin/lakego/fllesystem/interfaces/adapter"
)

type Adapter interface {
    // 判断
    Has(string) bool

    // 上传
    Write(string, string, config.Config) (map[string]interface{}, error)

    // 上传 Stream 文件类型
    WriteStream(string, *os.File, config.Config) (map[string]interface{}, error)

    // 更新
    Update(string, string, config.Config) (map[string]interface{}, error)

    // 更新
    UpdateStream(string, *os.File, config.Config) (map[string]interface{}, error)

    //
    Read(string) (map[string]interface{}, error)

    //
    ReadStream(string) (map[string]interface{}, error)

    // 重命名
    Rename(string, string) error

    // 复制
    Copy(string, string) error

    // 删除
    Delete(string) error

    // 删除文件夹
    DeleteDir(string) error

    // 创建文件夹
    CreateDir(string, config.Config) (map[string]string, error)

    // 列出内容
    ListContents(string, ...bool) ([]map[string]interface{}, error)

    //
    GetMetadata(string) (map[string]interface{}, error)

    //
    GetSize(string) (map[string]interface{}, error)

    //
    GetMimetype(string) (map[string]interface{}, error)

    //
    GetTimestamp(string) (map[string]interface{}, error)

    // 获取文件的权限
    GetVisibility(string) (map[string]string, error)

    // 设置文件的权限
    SetVisibility(string, string) (map[string]string, error)

    // 设置前缀
    SetPathPrefix(string) error

    // 获取前缀
    GetPathPrefix() string

    // 添加前缀
    ApplyPathPrefix(string) string

    // 移除前缀
    RemovePathPrefix(string) string
}
