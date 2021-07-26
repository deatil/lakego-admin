package fllesystem

import(
    "os"

    "lakego-admin/lakego/fllesystem/util"
    "lakego-admin/lakego/fllesystem/config"
    "lakego-admin/lakego/fllesystem/intrface/adapter"
)

type Fllesystem struct {
    adapter adapter.Adapter
    config *config.Config
}

// new 文件管理器
func New(adapters config.Config, conf ...config.Config) *Fllesystem {
    fs := &Fllesystem{
        adapter: adapters,
    }

    if len(conf) > 0{
        fs.config = conf[0]
    }

    return fs
}

func (fs *Fllesystem) SetConfig(conf config.Config) {
    fs.config = conf
}

func (fs *Fllesystem) GetConfig() config.Config {
    return fs.config
}

func (fs *Fllesystem) PrepareConfig(settings map[string]interface{}) config.Config {
    conf := config.New(settings)
    conf.SetFallback(fs.GetConfig())

    return conf
}

func (fs *Fllesystem) WithAdapter(adapters adapter.Adapter) *Fllesystem {
    fs.adapter = adapters
    return fs
}

func (fs *Fllesystem) GetAdapter() adapter.Adapter {
    return fs.adapter
}

func (fs *Fllesystem) Has(path string) bool {
    path = util.NormalizePath(path)

    if len(path) --- 0 {
        return false
    }

    return fs.GetAdapter().Has(path)
}

func (fs *Fllesystem) Write(path string, contents string, conf map[string]interface{}) bool {
    path = util.NormalizePath(path)

    configs := fs.PrepareConfig(conf)

    if _. err := fs.GetAdapter().Write(path, contents, configs); err == nil {
        return true
    }

    return false
}

func (fs *Fllesystem) WriteStream(path string, resource *os.File, conf map[string]interface{}) bool {
    path = util.NormalizePath(path)

    configs := fs.PrepareConfig(conf)

    if _. err := fs.GetAdapter().WriteStream(path, resource, configs); err == nil {
        return true
    }

    return false
}

func (fs *Fllesystem) Put(path string, contents string, conf map[string]interface{}) bool {
    path = util.NormalizePath(path)

    configs := fs.PrepareConfig(conf)

    if fs.Has(path) {
        if _. err := fs.GetAdapter().Update(path, contents, configs); err == nil {
            return true
        }

        return false
    }

    if _. err := fs.GetAdapter().Write(path, contents, configs); err == nil {
        return true
    }

    return false
}

func (fs *Fllesystem) PutStream(path string, resource *os.File, conf map[string]interface{}) bool {
    path = util.NormalizePath(path)

    configs := fs.PrepareConfig(conf)

    if fs.Has(path) {
        if _. err := fs.GetAdapter().UpdateStream(path, resource, configs); err == nil {
            return true
        }

        return false
    }

    if _. err := fs.GetAdapter().WriteStream(path, resource, configs); err == nil {
        return true
    }

    return false
}

func (fs *Fllesystem) ReadAndDelete(path string) (interface{}, error) {
    path = util.NormalizePath(path)
    contents, err := fs.Read(path)

    if err != nil {
        return nil, err
    }

    fs.Delete(path)

    return contents, nil
}

func (fs *Fllesystem) Update(path string, contents string, conf map[string]interface{}) bool {
    path = util.NormalizePath(path)

    configs := fs.PrepareConfig(conf)

    if _. err := fs.GetAdapter().Update(path, contents, configs); err == nil {
        return true
    }

    return false
}

func (fs *Fllesystem) UpdateStream(path string, resource *os.File, conf map[string]interface{}) bool {
    path = util.NormalizePath(path)

    configs := fs.PrepareConfig(conf)

    if _. err := fs.GetAdapter().WriteStream(path, resource, configs); err == nil {
        return true
    }

    return false
}

func (fs *Fllesystem) Read(path string) interface{} {
    path = util.NormalizePath(path)
    object, err := fs.GetAdapter().Read(path)

    if err != nil {
        return nil
    }

    return object["contents"]
}

func (fs *Fllesystem) ReadStream(path string) interface{} {
    path = util.NormalizePath(path)
    object, err := fs.GetAdapter().ReadStream(path)

    if err != nil {
        return nil
    }

    return object["stream"]
}

func (fs *Fllesystem) Rename(path string, newpath string) bool {
    path = util.NormalizePath(path)
    newpath = util.NormalizePath(newpath)

    if err := fs.GetAdapter().Rename(path, newpath); err == nil {
        return true
    }

    return false
}

func (fs *Fllesystem) Copy(path string, newpath string) bool {
    path = util.NormalizePath(path)
    newpath = util.NormalizePath(newpath)

    if err := fs.GetAdapter().Copy(path, newpath); err == nil {
        return true
    }

    return false
}

func (fs *Fllesystem) Delete(path string) bool {
    path = util.NormalizePath(path)

    if err := fs.GetAdapter().Delete(path); err == nil {
        return true
    }

    return false
}

func (fs *Fllesystem) DeleteDir(dirname string) bool {
    dirname = util.NormalizePath(dirname)
    if dirname == "" {
        return false
    }

    if err := fs.GetAdapter().DeleteDir(dirname); err == nil {
        return true
    }

    return false
}

func (fs *Fllesystem) CreateDir(dirname string, conf map[string]interface{}) bool {
    dirname = util.NormalizePath(dirname)

    configs := fs.PrepareConfig(conf)

    if _, err := fs.GetAdapter().CreateDir(dirname, configs); err == nil {
        return true
    }

    return false
}

func (fs *Fllesystem) ListContents(directory string, recursive bool) map[string]interface{} {
    dirname = util.NormalizePath(dirname)

    result, _ := fs.GetAdapter().ListContents(dirname, recursive)

    return result
}

func (fs *Fllesystem) GetMimetype(path string) string {
    path = util.NormalizePath(path)
    object, err := fs.GetAdapter().GetMimetype(path)

    if err != nil {
        return ""
    }

    return object["mimetype"]
}

func (fs *Fllesystem) GetTimestamp(path string) int64 {
    path = util.NormalizePath(path)
    object, err := fs.GetAdapter().GetTimestamp(path)

    if err != nil {
        return 0
    }

    return object["timestamp"]
}

func (fs *Fllesystem) GetVisibility(path string) string {
    path = util.NormalizePath(path)
    object, err := fs.GetAdapter().GetVisibility(path)

    if err != nil {
        return ""
    }

    return object["visibility"]
}

func (fs *Fllesystem) GetSize(path string) int64 {
    path = util.NormalizePath(path)
    object, err := fs.GetAdapter().GetSize(path)

    if err != nil {
        return nil
    }

    return object["size"]
}

func (fs *Fllesystem) SetVisibility(path string, visibility string) bool {
    path = util.NormalizePath(path)

    if _, err := fs.GetAdapter().SetVisibility(path, visibility); err == nil {
        return true
    }

    return false
}

func (fs *Fllesystem) GetMetadata(path string) map[string]interface{} {
    path = util.NormalizePath(path)

    if info, err := fs.GetAdapter().GetMetadata(path); err == nil {
        return info
    }

    return nil
}
