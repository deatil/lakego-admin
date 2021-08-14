package storage

import(
    "sync"
    "strings"

    "lakego-admin/lakego/support/path"
    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/fllesystem"
    "lakego-admin/lakego/fllesystem/interfaces"
    localAdapter "lakego-admin/lakego/fllesystem/adapter/local"
    "lakego-admin/lakego/storage"
    "lakego-admin/lakego/storage/register"
)

var once sync.Once

// 对外定义一个type
type Storage storage.Storage

// 实例化
func New(once ...bool) *storage.Storage {
    disk := GetDefaultDisk()

    return Disk(disk, once...)
}

// 实例化
func NewWithDisk(disk string, once ...bool) *storage.Storage {
    return Disk(disk, once...)
}

// 批量操作
func MountManager(filesystems ...map[string]interface{}) *fllesystem.MountManager {
    return fllesystem.NewMountManager(filesystems...)
}

// 注册磁盘
func Register() {
    once.Do(func() {
        // 注册可用驱动
        register.RegisterDriver("local", func() interfaces.Adapter {
            return &localAdapter.Local{}
        })

        // 磁盘列表
        disks := config.New("filesystem").GetStringMap("Disks")

        // 程序根目录
        basePath := path.GetBasePath()

        // 本地磁盘
        register.RegisterDisk("local", func() interfaces.Fllesystem {
            localConf := disks["local"].(map[string]interface{})
            localRoot := localConf["root"].(string)
            localType := localConf["type"].(string)

            driver := register.GetDriver(localType)
            if driver == nil {
                panic("文件管理器驱动 " + localType + " 没有被注册")
            }

            if strings.HasPrefix(localRoot, "{root}") {
                localRoot = strings.TrimPrefix(localRoot, "{root}")
                localRoot = basePath + "/" + strings.TrimPrefix(localRoot, "/")
            }

            driver.EnsureDirectory(localRoot)
            driver.SetPathPrefix(localRoot)

            fs := fllesystem.New(driver, localConf)

            return fs
        })

        // 公共磁盘
        register.RegisterDisk("public", func() interfaces.Fllesystem {
            publicConf := disks["public"].(map[string]interface{})
            publicRoot := publicConf["root"].(string)
            publicType := publicConf["type"].(string)

            driver := register.GetDriver(publicType)
            if driver == nil {
                panic("文件管理器驱动 " + publicType + " 没有被注册")
            }

            if strings.HasPrefix(publicRoot, "{root}") {
                publicRoot = strings.TrimPrefix(publicRoot, "{root}")
                publicRoot = basePath + "/" + strings.TrimPrefix(publicRoot, "/")
            }

            driver.EnsureDirectory(publicRoot)
            driver.SetPathPrefix(publicRoot)

            fs := fllesystem.New(driver, publicConf)

            return fs
        })
    })
}

func Disk(name string, once ...bool) *storage.Storage {
    // 注册默认磁盘
    Register()

    var once2 bool
    if len(once) > 0 {
        once2 = once[0]
    } else {
        once2 = true
    }

    // 拿取磁盘
    disk := register.GetDisk(name, once2)
    if disk == nil {
        panic("文件管理器磁盘 " + name + " 没有被注册")
    }

    disk2 := storage.NewWithFllesystem(disk.(*fllesystem.Fllesystem))

    return disk2
}

func GetDefaultDisk() string {
    return config.New("filesystem").GetString("Default")
}
