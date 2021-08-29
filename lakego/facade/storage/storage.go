package storage

import(
    "sync"
    "strings"

    "lakego-admin/lakego/register"
    "lakego-admin/lakego/support/path"
    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/fllesystem"
    "lakego-admin/lakego/fllesystem/interfaces"
    localAdapter "lakego-admin/lakego/fllesystem/adapter/local"
    "lakego-admin/lakego/storage"
)

var once sync.Once

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
        // 程序根目录
        basePath := path.GetBasePath()

        // 注册可用驱动
        register.NewManagerWithPrefix("database_").Register("local", func(conf map[string]interface{}) interface{} {
            driver := &localAdapter.Local{}

            root := conf["root"].(string)

            if strings.HasPrefix(root, "{root}") {
                root = strings.TrimPrefix(root, "{root}")
                root = basePath + "/" + strings.TrimPrefix(root, "/")
            }

            driver.EnsureDirectory(root)
            driver.SetPathPrefix(root)

            return driver
        })
    })
}

func Disk(name string, once ...bool) *storage.Storage {
    // 注册默认磁盘
    Register()

    // 磁盘列表
    disks := config.New("filesystem").GetStringMap("Disks")

    // 获取驱动配置
    diskConfig, ok := disks[name]
    if !ok {
        panic("文件管理器 " + name + " 配置不存在")
    }

    // 配置
    diskConf := diskConfig.(map[string]interface{})

    // 获取驱动磁盘
    diskType := diskConf["type"].(string)
    driver := register.NewManagerWithPrefix("database_").GetRegister(diskType, diskConf, once...)
    if driver == nil {
        panic("文件管理器驱动 " + diskType + " 没有被注册")
    }

    // 磁盘
    disk := fllesystem.New(driver.(interfaces.Adapter), diskConf)

    // 使用自定义文件管理器
    disk2 := storage.NewWithFllesystem(disk.(*fllesystem.Fllesystem))

    return disk2
}

func GetDefaultDisk() string {
    return config.New("filesystem").GetString("Default")
}
