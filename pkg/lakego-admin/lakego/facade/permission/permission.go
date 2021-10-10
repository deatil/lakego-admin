package permission

import (
    "sync"

    "github.com/deatil/lakego-admin/lakego/register"
    "github.com/deatil/lakego-admin/lakego/support/path"
    "github.com/deatil/lakego-admin/lakego/facade/database"
    "github.com/deatil/lakego-admin/lakego/facade/config"

    "github.com/deatil/lakego-admin/lakego/permission"
    "github.com/deatil/lakego-admin/lakego/permission/interfaces"
    gormAdapter "github.com/deatil/lakego-admin/lakego/permission/adapter/gorm"
)

/**
 * 权限
 *
 * @create 2021-9-30
 * @author deatil
 */
var once sync.Once

// 初始化
func init() {
    // 注册默认适配器
    Register()
}

// 实例化
func New(once ...bool) *permission.Permission {
    disk := GetDefaultAdapter()

    return Permission(disk, once...)
}

// 实例化
func NewWithDisk(disk string, once ...bool) *permission.Permission {
    return Permission(disk, once...)
}

// 注册
func Register() {
    once.Do(func() {
        // 注册可用驱动
        register.
            NewManagerWithPrefix("permission").
            Register("gorm", func(conf map[string]interface{}) interface{} {
                newDb := database.New()

                a, _ := gormAdapter.NewAdapterByDB(newDb)

                return a
            })
    })
}

func Permission(name string, once ...bool) *permission.Permission {
    // 列表
    adapters := config.New("permission").GetStringMap("Adapters")

    // 获取驱动配置
    adapterConfig, ok := adapters[name]
    if !ok {
        panic("权限适配器[ " + name + " ]配置不存在")
    }

    // 配置
    permissionConfig := adapterConfig.(map[string]interface{})

    // 获取驱动
    permissionType := permissionConfig["type"].(string)
    adapter := register.
        NewManagerWithPrefix("permission").
        GetRegister(permissionType, permissionConfig, once...)
    if adapter == nil {
        panic("权限适配器驱动[ " + permissionType + " ]没有被注册")
    }

    // 配置文件路径
    configfile := permissionConfig["rbacmodel"].(string)
    modelConf := path.FormatPath(configfile)

    // permission 使用
    c := &permission.Permission{}

    c.WithAdapter(adapter.(interfaces.Adapter))
    c.WithModelConf(modelConf)

    return c
}

func GetDefaultAdapter() string {
    return config.New("permission").GetString("Default")
}
