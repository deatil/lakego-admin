package storage

import(
    "os"
    "strings"

    "lakego-admin/lakego/fllesystem"
    "lakego-admin/lakego/fllesystem/interfaces"
)

// 文件管理器
type Storage struct {
    *fllesystem.Fllesystem
}

// new 文件管理器
func New(adapters interfaces.Adapter, conf ...map[string]interface{}) *Storage {
    fs := &fllesystem.Fllesystem{}

    fs.WithAdapter(adapters)

    if len(conf) > 0{
        fs.SetConfig(fs.PrepareConfig(conf[0]))
    }

    fs2 := &Storage{fs}

    return fs2
}

// new 文件管理器
func NewWithFllesystem(ifs *fllesystem.Fllesystem) *Storage {
    fs := &Storage{ifs}

    return fs
}

// 获取配置
func (s *Storage) Url(url string) string {
    conf := s.GetConfig()

    uri := conf.Get("url").(string)

    return uri + "/" + strings.TrimPrefix(url, "/")
}

// 获取配置
func (s *Storage) Path(path string) string {
    adapter := s.GetAdapter()

    return adapter.ApplyPathPrefix(path)
}

// 保存数据流
func (s *Storage) PutFileAs(path string, resource *os.File, name string, config ...map[string]interface{}) string {
    path = strings.TrimSuffix(path, "/") + "/" + strings.TrimPrefix(name, "/")
    path = strings.TrimPrefix(path, "/")
    path = strings.TrimSuffix(path, "/")

    result := s.PutStream(path, resource, config...)

    if result {
        return path
    }

    return ""
}

// 保存文本数据
func (s *Storage) PutContentsAs(path string, contents string, name string, config ...map[string]interface{}) string {
    path = strings.TrimSuffix(path, "/") + "/" + strings.TrimPrefix(name, "/")
    path = strings.TrimPrefix(path, "/")
    path = strings.TrimSuffix(path, "/")

    result := s.Put(path, contents, config...)

    if result {
        return path
    }

    return ""
}
