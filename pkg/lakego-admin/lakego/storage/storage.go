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

    fs2 := &Storage{fs}

    return fs2
}

// new 文件管理器
func NewWithFllesystem(ifs *filesystem.Fllesystem) *Storage {
    fs := &Storage{ifs}

    return fs
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

// 链接
func (this *Storage) Url(url string) string {
    conf := this.GetConfig()

    uri := conf.Get("url").(string)

    return uri + "/" + strings.TrimPrefix(url, "/")
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
