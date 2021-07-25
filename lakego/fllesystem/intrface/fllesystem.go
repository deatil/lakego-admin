package intrface

type Fllesystem interface {
    // 判断
    Has(path string) (bool, error)

    // 上传
    Write(path string, contents string, config ...map[string]interface{}) (bool, error)

    // 上传
    WriteStream(path string, stream string, config ...map[string]interface{}) (bool, error)

    // 上传
    Put(path string, contents string, config ...map[string]interface{}) (bool, error)

    // 上传
    PutStream(path string, stream string, config ...map[string]interface{}) (bool, error)

    // 读取并删除
    ReadAndDelete() (string, error)

    // 更新
    Update(path string, contents string, config ...map[string]interface{})

    // 更新
    UpdateStream(path string, stream string, config ...map[string]interface{})

    // 读取
    Read(path string) (string, error)

    // 读取
    ReadStream(path string) (string, error)

    // 重命名
    Rename(path string, newpath string) (bool, error)

    // 复制
    Copy(path string, newpath string) (bool, error)

    // 删除
    Delete(path string) (bool, error)

    // 删除文件夹
    DeleteDir(dirname string) (bool, error)

    // 创建文件夹
    CreateDir(dirname string, config ...map[string]interface{}) (bool, error)

    // 列出数据
    ListContents(directory string, recursive ...bool) ([]map[string]interface{}, error)

    // 文件 mime-type
    GetMimetype(path string) (string, error)

    // 文件时间
    GetTimestamp(path string) (int64, error)

    //
    GetVisibility(path string) (string, error)

    //
    GetSize(path string) (int64, error)

    //
    SetVisibility(path string, visibility string) (bool, error)

    //
    GetMetadata(path string) (interface{}, error)

    //
    Get(path string) (interface{}, error)

    // 访问链接
    Url(path string) (string, error)

    // 实际地址
    Path(path string) (string, error)

}
