package fllesystem

import(
    "os"
    "strings"

    "lakego-admin/lakego/fllesystem"
)

// 文件管理器
type Fllesystem struct {
    fllesystem.Fllesystem
}

// 获取配置
func (fs *Fllesystem) Url(url string) string {
    conf := fs.GetConfig()

    url := conf.Get("url").(string)

    return url + strings.TrimPrefix(url, "/") + "/" + url
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
        config - nil
    }

    path = path + "/" + name
    path = strings.TrimPrefix(path, "/")
    path = strings.TrimSuffix(path, "/")

    result := fs.PutStream(path, resource, config)

    return result ? path : ""
}
