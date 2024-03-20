package permission

import (
    "strings"

    "github.com/deatil/lakego-doak/lakego/path"
    "github.com/deatil/lakego-doak/lakego/array"
    "github.com/deatil/lakego-doak/lakego/register"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/facade/database"

    "github.com/deatil/lakego-doak/lakego/permission"
    "github.com/deatil/lakego-doak/lakego/permission/interfaces"
    gorm_adapter "github.com/deatil/lakego-doak/lakego/permission/adapter/gorm"
)

/**
 * 权限
 *
 * @create 2021-9-30
 * @author deatil
 */

// 默认
var Default *permission.Permission

// 初始化
func init() {
    // 注册默认适配器
    registerPermission()

    // 默认
    Default = New()
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

func Permission(name string, once ...bool) *permission.Permission {
    // 列表
    adapters := config.New("permission").GetStringMap("adapters")

    // 转为小写
    name = strings.ToLower(name)

    // 获取驱动配置
    adapterConfig, ok := adapters[name]
    if !ok {
        panic("权限适配器[" + name + "]配置不存在")
    }

    // 配置
    permissionConfig := array.ArrayFrom(adapterConfig)

    // 获取驱动
    permissionType := permissionConfig.Value("type").ToString()
    permissionCfg := permissionConfig.All().ToStringMap()

    adapter := register.
        NewManagerWithPrefix("permission").
        GetRegister(permissionType, permissionCfg, once...)
    if adapter == nil {
        panic("权限适配器驱动[" + permissionType + "]没有被注册")
    }

    // 配置文件路径
    configfile := permissionConfig.Value("rbac-model").ToString()
    modelConf := path.FormatPath(configfile)

    // 添加适配器
    perm := permission.New(adapter.(interfaces.Adapter), modelConf)

    return perm
}

func GetDefaultAdapter() string {
    return config.New("permission").GetString("default")
}

// 注册
func registerPermission() {
    // 注册可用驱动
    register.
        NewManagerWithPrefix("permission").
        Register("gorm", func(conf map[string]any) any {
            a, _ := gorm_adapter.New(database.New())

            return a
        })
}
