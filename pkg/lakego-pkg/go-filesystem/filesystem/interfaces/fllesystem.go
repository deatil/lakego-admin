package interfaces

import(
    "io"
    "os"
)

/**
 * 文件管理器接口
 *
 * @create 2021-8-1
 * @author deatil
 */
type Fllesystem interface {
    // 设置配置
    SetConfig(Config)

    // 获取配置
    GetConfig() Config

    // 提前设置配置
    PrepareConfig(map[string]any) Config

    // 设置适配器
    WithAdapter(Adapter) Fllesystem

    // 获取适配器
    GetAdapter() Adapter

    // 获取
    GetFllesystem() Fllesystem

    // 判断
    Has(string) bool

    // 上传
    Write(string, string, ...map[string]any) (bool, error)

    // 上传
    WriteStream(string, io.Reader, ...map[string]any) (bool, error)

    // 上传
    Put(string, string, ...map[string]any) (bool, error)

    // 上传
    PutStream(string, io.Reader, ...map[string]any) (bool, error)

    // 更新
    Update(string, string, ...map[string]any) (bool, error)

    // 更新
    UpdateStream(string, io.Reader, ...map[string]any) (bool, error)

    // 读取
    Read(string) (string, error)

    // 读取
    ReadStream(string) (*os.File, error)

    // 重命名
    Rename(string, string) (bool, error)

    // 复制
    Copy(string, string) (bool, error)

    // 删除
    Delete(string) (bool, error)

    // 读取并删除
    ReadAndDelete(string) (any, error)

    // 删除文件夹
    DeleteDir(string) (bool, error)

    // 创建文件夹
    CreateDir(string, ...map[string]any) (bool, error)

    // 列出数据
    ListContents(string, ...bool) ([]map[string]any, error)

    // 文件 mime-type
    GetMimetype(string) (string, error)

    // 文件时间
    GetTimestamp(string) (int64, error)

    // 权限
    GetVisibility(string) (string, error)

    // 大小
    GetSize(string) (int64, error)

    // 设置权限
    SetVisibility(string, string) (bool, error)

    // 信息数据
    GetMetadata(string) (map[string]any, error)

    // 获取
    Get(string, ...func(Fllesystem, string) any) any
}
