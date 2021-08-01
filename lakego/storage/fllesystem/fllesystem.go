package fllesystem

import(
    "os"
    "strings"

    "lakego-admin/lakego/fllesystem"
    "lakego-admin/lakego/fllesystem/interfaces"
)

// 文件管理器
type Fllesystem struct {
    fllesystem.Fllesystem
}

// new 文件管理器
func New(adapters interfaces.Adapter, conf ...map[string]interface{}) *Fllesystem {
    fs := &Fllesystem{}

    fs.WithAdapter(adapters)

    if len(conf) > 0{
        fs.SetConfig(fs.PrepareConfig(conf[0]))
    }

    return fs
}

// 获取配置
func (fs *Fllesystem) Url(url string) string {
    conf := fs.GetConfig()

    uri := conf.Get("url").(string)

    return uri + strings.TrimPrefix(url, "/") + "/" + url
}

// 获取配置
func (fs *Fllesystem) Path(path string) string {
    adapter := fs.GetAdapter()

    return adapter.ApplyPathPrefix(path)
}

// 保存数据
func (fs *Fllesystem) PutFileAs(path string, resource *os.File, name string, conf ...map[string]interface{}) string {
    var config map[string]interface{}
    if len(conf) > 0 {
        config = conf[0]
    } else {
        config = nil
    }

    path = path + "/" + name
    path = strings.TrimPrefix(path, "/")
    path = strings.TrimSuffix(path, "/")

    result := fs.PutStream(path, resource, config)

    if result {
        return path
    }

    return ""
}
