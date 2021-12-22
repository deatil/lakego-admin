package filesystem

import(
    "os"
    "errors"

    "github.com/deatil/go-filesystem/filesystem/util"
    "github.com/deatil/go-filesystem/filesystem/config"
    "github.com/deatil/go-filesystem/filesystem/interfaces"
)

// new 文件管理器
func New(adapters interfaces.Adapter, conf ...map[string]interface{}) interfaces.Fllesystem {
    fs := &Fllesystem{
        adapter: adapters,
    }

    if len(conf) > 0{
        fs.config = fs.PrepareConfig(conf[0])
    }

    return fs
}

/**
 * 文件管理器
 *
 * @create 2021-8-1
 * @author deatil
 */
type Fllesystem struct {
    adapter interfaces.Adapter
    config interfaces.Config
}

// 设置配置
func (this *Fllesystem) SetConfig(conf interfaces.Config) {
    this.config = conf
}

// 获取配置
func (this *Fllesystem) GetConfig() interfaces.Config {
    return this.config
}

// 提前设置配置
func (this *Fllesystem) PrepareConfig(settings map[string]interface{}) interfaces.Config {
    conf := config.New(settings)
    conf.SetFallback(this.GetConfig())

    return conf
}

// 设置适配器
func (this *Fllesystem) WithAdapter(adapters interfaces.Adapter) interfaces.Fllesystem {
    this.adapter = adapters
    return this
}

// 获取适配器
func (this *Fllesystem) GetAdapter() interfaces.Adapter {
    return this.adapter
}

// 获取文件系统
func (this *Fllesystem) GetFllesystem() interfaces.Fllesystem {
    return this
}

// 判断
func (this *Fllesystem) Has(path string) bool {
    path = util.NormalizePath(path)

    if len(path) == 0 {
        return false
    }

    return this.GetAdapter().Has(path)
}

// 写入文件
func (this *Fllesystem) Write(path string, contents string, conf ...map[string]interface{}) bool {
    path = util.NormalizePath(path)

    var newConf map[string]interface{}
    if len(conf) > 0 {
        newConf = conf[0]
    }

    configs := this.PrepareConfig(newConf)

    if _, err := this.GetAdapter().Write(path, contents, configs); err == nil {
        return true
    }

    return false
}

// 写入数据流
func (this *Fllesystem) WriteStream(path string, resource *os.File, conf ...map[string]interface{}) bool {
    path = util.NormalizePath(path)

    var newConf map[string]interface{}
    if len(conf) > 0 {
        newConf = conf[0]
    }

    configs := this.PrepareConfig(newConf)

    if _, err := this.GetAdapter().WriteStream(path, resource, configs); err != nil {
        return false
    }

    return true
}

// 更新
func (this *Fllesystem) Put(path string, contents string, conf ...map[string]interface{}) bool {
    path = util.NormalizePath(path)

    var newConf map[string]interface{}
    if len(conf) > 0 {
        newConf = conf[0]
    }

    configs := this.PrepareConfig(newConf)

    if this.Has(path) {
        if _, err := this.GetAdapter().Update(path, contents, configs); err == nil {
            return true
        }

        return false
    }

    if _, err := this.GetAdapter().Write(path, contents, configs); err == nil {
        return true
    }

    return false
}

// 更新数据流
func (this *Fllesystem) PutStream(path string, resource *os.File, conf ...map[string]interface{}) bool {
    path = util.NormalizePath(path)

    var newConf map[string]interface{}
    if len(conf) > 0 {
        newConf = conf[0]
    }

    configs := this.PrepareConfig(newConf)

    if this.Has(path) {
        if _, err := this.GetAdapter().UpdateStream(path, resource, configs); err == nil {
            return true
        }

        return false
    }

    if _, err := this.GetAdapter().WriteStream(path, resource, configs); err == nil {
        return true
    }

    return false
}

// 读取并删除
func (this *Fllesystem) ReadAndDelete(path string) (interface{}, error) {
    path = util.NormalizePath(path)
    contents := this.Read(path)

    if contents == nil {
        return nil, errors.New("读取失败")
    }

    this.Delete(path)

    return contents, nil
}

// 更新字符
func (this *Fllesystem) Update(path string, contents string, conf ...map[string]interface{}) bool {
    path = util.NormalizePath(path)

    var newConf map[string]interface{}
    if len(conf) > 0 {
        newConf = conf[0]
    }

    configs := this.PrepareConfig(newConf)

    if _, err := this.GetAdapter().Update(path, contents, configs); err == nil {
        return true
    }

    return false
}

// 更新数据流
func (this *Fllesystem) UpdateStream(path string, resource *os.File, conf ...map[string]interface{}) bool {
    path = util.NormalizePath(path)

    var newConf map[string]interface{}
    if len(conf) > 0 {
        newConf = conf[0]
    }

    configs := this.PrepareConfig(newConf)

    if _, err := this.GetAdapter().WriteStream(path, resource, configs); err == nil {
        return true
    }

    return false
}

// 文件到字符
func (this *Fllesystem) Read(path string) interface{} {
    path = util.NormalizePath(path)
    object, err := this.GetAdapter().Read(path)

    if err != nil {
        return nil
    }

    return object["contents"]
}

// 读取成数据流
func (this *Fllesystem) ReadStream(path string) *os.File {
    path = util.NormalizePath(path)
    object, err := this.GetAdapter().ReadStream(path)

    if err != nil {
        return nil
    }

    return object["stream"].(*os.File)
}

// 重命名
func (this *Fllesystem) Rename(path string, newpath string) bool {
    path = util.NormalizePath(path)
    newpath = util.NormalizePath(newpath)

    if err := this.GetAdapter().Rename(path, newpath); err == nil {
        return true
    }

    return false
}

// 复制
func (this *Fllesystem) Copy(path string, newpath string) bool {
    path = util.NormalizePath(path)
    newpath = util.NormalizePath(newpath)

    if err := this.GetAdapter().Copy(path, newpath); err != nil {
        return false
    }

    return true
}

// 删除
func (this *Fllesystem) Delete(path string) bool {
    path = util.NormalizePath(path)

    if err := this.GetAdapter().Delete(path); err == nil {
        return true
    }

    return false
}

// 删除文件夹
func (this *Fllesystem) DeleteDir(dirname string) bool {
    dirname = util.NormalizePath(dirname)
    if dirname == "" {
        return false
    }

    if err := this.GetAdapter().DeleteDir(dirname); err == nil {
        return true
    }

    return false
}

// 创建文件夹
func (this *Fllesystem) CreateDir(dirname string, conf ...map[string]interface{}) bool {
    dirname = util.NormalizePath(dirname)

    var newConf map[string]interface{}
    if len(conf) > 0 {
        newConf = conf[0]
    }

    configs := this.PrepareConfig(newConf)

    if _, err := this.GetAdapter().CreateDir(dirname, configs); err == nil {
        return true
    }

    return false
}

// 列表
func (this *Fllesystem) ListContents(dirname string, recursive ...bool) []map[string]interface{} {
    dirname = util.NormalizePath(dirname)

    result, _ := this.GetAdapter().ListContents(dirname, recursive...)

    return result
}

// 类型
func (this *Fllesystem) GetMimetype(path string) string {
    path = util.NormalizePath(path)
    object, err := this.GetAdapter().GetMimetype(path)

    if err != nil {
        return ""
    }

    return object["mimetype"].(string)
}

// 时间戳
func (this *Fllesystem) GetTimestamp(path string) int64 {
    path = util.NormalizePath(path)
    object, err := this.GetAdapter().GetTimestamp(path)

    if err != nil {
        return 0
    }

    return object["timestamp"].(int64)
}

// 权限
func (this *Fllesystem) GetVisibility(path string) string {
    path = util.NormalizePath(path)
    object, err := this.GetAdapter().GetVisibility(path)

    if err != nil {
        return ""
    }

    return object["visibility"]
}

// 大小
func (this *Fllesystem) GetSize(path string) int64 {
    path = util.NormalizePath(path)
    object, err := this.GetAdapter().GetSize(path)

    if err != nil {
        return 0
    }

    return object["size"].(int64)
}

// 设置权限
func (this *Fllesystem) SetVisibility(path string, visibility string) bool {
    path = util.NormalizePath(path)

    if _, err := this.GetAdapter().SetVisibility(path, visibility); err == nil {
        return true
    }

    return false
}

// 信息数据
func (this *Fllesystem) GetMetadata(path string) map[string]interface{} {
    path = util.NormalizePath(path)

    if info, err := this.GetAdapter().GetMetadata(path); err == nil {
        return info
    }

    return nil
}

// 获取
// Get("file.txt").(*fllesystem.File).Read()
// Get("/file").(*fllesystem.Directory).Read()
func (this *Fllesystem) Get(path string, handler ...func(interfaces.Fllesystem, string) interface{}) interface{} {
    path = util.NormalizePath(path)

    if len(handler) > 0 {
        return handler[0](this, path)
    }

    data := this.GetMetadata(path)

    if data != nil && data["type"] == "file" {
        file := &File{}
        file.SetFilesystem(this)
        file.SetPath(path)

        return file
    } else {
        dir := &Directory{}
        dir.SetFilesystem(this)
        dir.SetPath(path)

        return dir
    }
}
