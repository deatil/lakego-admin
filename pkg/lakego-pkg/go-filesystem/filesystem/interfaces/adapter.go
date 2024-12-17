package interfaces

import(
    "io"
)

/**
 * 适配器接口
 *
 * @create 2021-8-1
 * @author deatil
 */
type Adapter interface {
    // 设置前缀
    SetPathPrefix(string)

    // 获取前缀
    GetPathPrefix() string

    // 添加前缀
    ApplyPathPrefix(string) string

    // 移除前缀
    RemovePathPrefix(string) string

    // 判断
    Has(string) bool

    // 上传
    Write(string, []byte, Config) (map[string]any, error)

    // 上传 Stream 文件类型
    WriteStream(string, io.Reader, Config) (map[string]any, error)

    // 更新
    Update(string, []byte, Config) (map[string]any, error)

    // 更新
    UpdateStream(string, io.Reader, Config) (map[string]any, error)

    // 读取
    Read(string) (map[string]any, error)

    // 读取文件为数据流
    ReadStream(string) (map[string]any, error)

    // 重命名
    Rename(string, string) error

    // 复制
    Copy(string, string) error

    // 删除
    Delete(string) error

    // 删除文件夹
    DeleteDir(string) error

    // 创建文件夹
    CreateDir(string, Config) (map[string]string, error)

    // 列出内容
    ListContents(string, ...bool) ([]map[string]any, error)

    // 文件信息
    GetMetadata(string) (map[string]any, error)

    // 文件大小
    GetSize(string) (map[string]any, error)

    // 类型
    GetMimetype(string) (map[string]any, error)

    // 获取时间戳
    GetTimestamp(string) (map[string]any, error)

    // 获取文件的权限
    GetVisibility(string) (map[string]string, error)

    // 设置文件的权限
    SetVisibility(string, string) (map[string]string, error)
}
