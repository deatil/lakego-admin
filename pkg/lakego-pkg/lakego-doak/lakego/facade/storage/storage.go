package storage

import(
    "strings"

    "github.com/deatil/lakego-doak/lakego/path"
    "github.com/deatil/lakego-doak/lakego/array"
    "github.com/deatil/lakego-doak/lakego/storage"
    "github.com/deatil/lakego-doak/lakego/register"
    "github.com/deatil/lakego-doak/lakego/facade/config"

    "github.com/deatil/go-filesystem/filesystem"
    "github.com/deatil/go-filesystem/filesystem/interfaces"
    localAdapter "github.com/deatil/go-filesystem/filesystem/adapter/local"
)

// 默认
var Default *storage.Storage

// 初始化
func init() {
    // 注册默认磁盘
    registerStorage()

    // 默认
    Default = New()
}

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
func MountManager(filesystems ...map[string]any) *filesystem.MountManager {
    return filesystem.NewMountManager(filesystems...)
}

func Disk(name string, once ...bool) *storage.Storage {
    // 磁盘列表
    disks := config.New("filesystem").GetStringMap("disks")

    cfg := array.ArrayFrom(disks)

    // 转为小写
    name = strings.ToLower(name)

    // 获取驱动配置
    if !cfg.Has(name) {
        panic("文件管理器[" + name + "]配置不存在")
    }

    // 配置
    diskConf := cfg.Value(name).ToStringMap()
    diskType := cfg.Value(name + ".type").ToString()

    // 获取驱动磁盘
    driver := register.
        NewManagerWithPrefix("database").
        GetRegister(diskType, diskConf, once...)
    if driver == nil {
        panic("文件管理器驱动[" + diskType + "]没有被注册")
    }

    // 磁盘
    disk := filesystem.New(driver.(interfaces.Adapter), diskConf)

    // 使用自定义文件管理器
    disk2 := storage.NewWithFilesystem(disk)

    return disk2
}

func GetDefaultDisk() string {
    return config.New("filesystem").GetString("default")
}

// 注册磁盘
func registerStorage() {
    // 注册可用驱动
    register.
        NewManagerWithPrefix("database").
        Register("local", func(conf map[string]any) any {
            root := conf["root"].(string)

            // 根目录
            root = path.FormatPath(root)

            driver := localAdapter.New(root)

            return driver
        })
}
