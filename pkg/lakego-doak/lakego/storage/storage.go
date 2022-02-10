package storage

import(
    "io"
    "strings"

    "github.com/deatil/go-filesystem/filesystem"
    "github.com/deatil/go-filesystem/filesystem/interfaces"
)

// new 文件管理器
func New(adapters interfaces.Adapter, conf ...map[string]interface{}) *Storage {
    fs := &filesystem.Fllesystem{}

    fs.WithAdapter(adapters)

    if len(conf) > 0{
        fs.SetConfig(fs.PrepareConfig(conf[0]))
    }

    return NewWithFllesystem(fs)
}

// new 文件管理器
func NewWithFllesystem(fs *filesystem.Fllesystem) *Storage {
    return &Storage{fs}
}

/**
 * 文件管理器
 *
 * @create 2021-9-8
 * @author deatil
 */
type Storage struct {
    *filesystem.Fllesystem
}

// 判断
func (this *Storage) Exists(path string) bool {
    return this.Has(path)
}

// 判断
func (this *Storage) Missing(path string) bool {
    return ! this.Exists(path)
}

// 路径
func (this *Storage) Path(path string) string {
    adapter := this.GetAdapter()

    return adapter.ApplyPathPrefix(path)
}

// 保存数据流
func (this *Storage) PutFileAs(path string, resource io.Reader, name string, config ...map[string]interface{}) string {
    path = strings.TrimSuffix(path, "/") + "/" + strings.TrimPrefix(name, "/")
    path = strings.TrimPrefix(path, "/")
    path = strings.TrimSuffix(path, "/")

    result := this.PutStream(path, resource, config...)

    if result {
        return path
    }

    return ""
}

// 保存文本数据
func (this *Storage) PutContentsAs(path string, contents string, name string, config ...map[string]interface{}) string {
    path = strings.TrimSuffix(path, "/") + "/" + strings.TrimPrefix(name, "/")
    path = strings.TrimPrefix(path, "/")
    path = strings.TrimSuffix(path, "/")

    result := this.Put(path, contents, config...)

    if result {
        return path
    }

    return ""
}

// 头部添加
func (this *Storage) Prepend(path string, data string, separator string) bool {
    if this.Exists(path) {
        return this.Put(path, data + separator + this.Read(path).(string))
    }

    return this.Put(path, data)
}

// 尾部添加
func (this *Storage) Append(path string, data string, separator string) bool {
    if this.Exists(path) {
        return this.Put(path, this.Read(path).(string) + separator + data)
    }

    return this.Put(path, data)
}

// 时间戳
func (this *Storage) LastModified(path string) int64 {
    return this.GetTimestamp(path)
}

// 链接
func (this *Storage) Url(url string) string {
    conf := this.GetConfig()

    uri := conf.Get("url").(string)

    return this.ConcatPathToUrl(uri, url)
}

// 路径
func (this *Storage) ConcatPathToUrl(url string, path string) string {
    return strings.TrimSuffix(url, "/") + "/" + strings.TrimPrefix(path, "/")
}
