package storage

import(
    "os"
    "sync"
    "strings"

    "lakego-admin/lakego/support/path"
    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/storage/fllesystem"
    "lakego-admin/lakego/fllesystem/interfaces"
    localAdapter "lakego-admin/lakego/fllesystem/adapter/local"
    driverRegister "lakego-admin/lakego/storage/register/driver"
    diskRegister "lakego-admin/lakego/storage/register/disk"
)

var once sync.Once

func New() interfaces.Fllesystem {
    disk := GetDefaultDisk()

    return Disk(disk)
}

// 注册磁盘
func Register() {
    once.Do(func() {
        // 注册可用驱动
        driverRegister.RegisterDriver("local", func() interfaces.Adapter {
            return &localAdapter.Local{}
        })

        // 磁盘列表
        disks := config.New("filesystem").GetStringMap("Disks")

        // 程序根目录
        basePath := path.GetBasePath()

        // 本地磁盘
        diskRegister.RegisterDisk("local", func() interfaces.Fllesystem {
            localConf := disks["local"].(map[string]interface{})
            localRoot := localConf["root"].(string)
            localType := localConf["type"].(string)

            driver := driverRegister.GetDriver(localType)
            if driver == nil {
                panic("文件管理器驱动 " + localType + " 没有被注册")
            }

            localRoot = basePath + "/" + strings.TrimPrefix(localRoot, "/")

            driver.EnsureDirectory(localRoot)
            driver.SetPathPrefix(localRoot)

            fs := fllesystem.New(driver, localConf)

            return fs
        })

        // 公共磁盘
        diskRegister.RegisterDisk("public", func() interfaces.Fllesystem {
            publicConf := disks["public"].(map[string]interface{})
            publicRoot := publicConf["root"].(string)
            publicType := publicConf["type"].(string)

            driver := driverRegister.GetDriver(publicType)
            if driver == nil {
                panic("文件管理器驱动 " + publicType + " 没有被注册")
            }

            publicRoot = basePath + "/" + strings.TrimPrefix(publicRoot, "/")

            driver.EnsureDirectory(publicRoot)
            driver.SetPathPrefix(publicRoot)

            fs := fllesystem.New(driver, publicConf)

            return fs
        })
    })
}

func Disk(name string) interfaces.Fllesystem {
    // 注册默认磁盘
    Register()

    // 拿取磁盘
    disk := diskRegister.GetDisk(name)
    if disk == nil {
        panic("文件管理器磁盘 " + name + " 没有被注册")
    }

    return disk
}

func GetDefaultDisk() string {
    return config.New("filesystem").GetString("Default")
}


// 获取配置
func Url(fs interfaces.Fllesystem, url string) string {
    conf := fs.GetConfig()

    uri := conf.Get("url").(string)

    return uri + "/" + strings.TrimPrefix(url, "/")
}

// 获取配置
func Path(fs interfaces.Fllesystem, path string) string {
    adapter := fs.GetAdapter()

    return adapter.ApplyPathPrefix(path)
}

// 保存数据
func PutFileAs(fs interfaces.Fllesystem, path string, resource *os.File, name string, conf ...map[string]interface{}) string {
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
