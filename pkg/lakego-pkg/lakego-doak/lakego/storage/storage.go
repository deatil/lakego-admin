package storage

import(
    "io"
    "strings"

    "github.com/deatil/go-filesystem/filesystem"
    "github.com/deatil/go-filesystem/filesystem/interfaces"
)

/**
 * 文件管理器
 *
 * @create 2021-9-8
 * @author deatil
 */
type Storage struct {
    *filesystem.Filesystem
}

// new 文件管理器
func New(adapters interfaces.Adapter, conf ...map[string]any) *Storage {
    fs := &filesystem.Filesystem{}

    fs.WithAdapter(adapters)

    if len(conf) > 0{
        fs.WithConfig(fs.PrepareConfig(conf[0]))
    }

    return NewWithFilesystem(fs)
}

// new 文件管理器
func NewWithFilesystem(fs *filesystem.Filesystem) *Storage {
    return &Storage{fs}
}

// 判断
func (this *Storage) Exists(path string) bool {
    return this.Has(path)
}

// 判断
func (this *Storage) Missing(path string) bool {
    return !this.Exists(path)
}

// 路径
func (this *Storage) Path(path string) string {
    adapter := this.GetAdapter()

    return adapter.ApplyPathPrefix(path)
}

// 保存数据流
func (this *Storage) PutFileAs(path string, resource io.Reader, name string, config ...map[string]any) (string, error) {
    path = strings.TrimSuffix(path, "/") + "/" + strings.TrimPrefix(name, "/")
    path = strings.TrimPrefix(path, "/")
    path = strings.TrimSuffix(path, "/")

    result, err := this.PutStream(path, resource, config...)
    if result {
        return path, nil
    }

    return "", err
}

// 保存文本数据
func (this *Storage) PutContentsAs(path string, contents string, name string, config ...map[string]any) (string, error) {
    path = strings.TrimSuffix(path, "/") + "/" + strings.TrimPrefix(name, "/")
    path = strings.TrimPrefix(path, "/")
    path = strings.TrimSuffix(path, "/")

    result, err := this.Put(path, []byte(contents), config...)

    if result {
        return path, nil
    }

    return "", err
}

// 头部添加
func (this *Storage) Prepend(path string, data string, separator string) (bool, error) {
    if this.Exists(path) {
        readData, err := this.Read(path)
        if err != nil {
            return false, err
        }

        return this.Put(path, append([]byte(data + separator), readData...))
    }

    return this.Put(path, []byte(data))
}

// 尾部添加
func (this *Storage) Append(path string, data string, separator string) (bool, error) {
    if this.Exists(path) {
        readData, err := this.Read(path)
        if err != nil {
            return false, err
        }

        return this.Put(path, append(readData, []byte(separator + data)...))
    }

    return this.Put(path, []byte(data))
}

// 时间戳
func (this *Storage) LastModified(path string) (int64, error) {
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
