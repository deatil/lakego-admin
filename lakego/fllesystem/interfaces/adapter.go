package interfaces

import(
    "os"

    "lakego-admin/lakego/fllesystem/config"
    "lakego-admin/lakego/fllesystem/interfaces/adapter"
)

type Adapter interface {
    // 判断
    Has(path string) bool

    // 上传
    Write(path string, contents string, conf config.Config) (map[string]interface{}, error)

    // 上传 Stream 文件类型
    WriteStream(path string, stream *os.File, config config.Config) (map[string]interface{}, error)

    // 更新
    Update(path string, contents string, config config.Config) (map[string]interface{}, error)

    // 更新
    UpdateStream(path string, stream *os.File, config config.Config) (map[string]interface{}, error)

    //
    Read(path string) (map[string]interface{}, error)

    //
    ReadStream(path string) (map[string]interface{}, error)

    // 重命名
    Rename(path string, newpath string) error

    // 复制
    Copy(path string, newpath string) error

    // 删除
    Delete(path string) error

    // 删除文件夹
    DeleteDir(dirname string) error

    // 创建文件夹
    CreateDir(dirname string, config config.Config) (map[string]string, error)

    // 列出内容
    ListContents(directory string, recursive ...bool) ([]map[string]interface{}, error)

    //
    GetMetadata(path string) (map[string]interface{}, error)

    //
    GetSize(path string) (map[string]interface{}, error)

    //
    GetMimetype(path string) (map[string]interface{}, error)

    //
    GetTimestamp(path string) (map[string]interface{}, error)

    // 获取文件的权限
    GetVisibility(path string) (map[string]string, error)

    // 设置文件的权限
    SetVisibility(path string, visibility string) (map[string]string, error)

    // 设置前缀
    SetPathPrefix(prefix string) error

    // 获取前缀
    GetPathPrefix() string

    // 添加前缀
    ApplyPathPrefix(path string) string

    // 移除前缀
    RemovePathPrefix(path string) string
}
