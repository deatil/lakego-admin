package register

import(
    "lakego-admin/lakego/register"
    "lakego-admin/lakego/fllesystem/interfaces"
)

// 驱动前缀
var driverPrefix = "storage_driver_"

// 磁盘前缀
var diskPrefix = "storage_disk_"

/**
 * 注册适配器
 */
func RegisterDriver(name string, f func(map[string]interface{}) interfaces.Adapter) {
    name = driverPrefix + name

    register.New().With(name, func(conf map[string]interface{}) interface{} {
        return f(conf)
    })
}

/**
 * 批量注册驱动
 */
func RegisterDrivers(drivers map[string]func(map[string]interface{}) interfaces.Adapter) {
    for name, f := range drivers {
        RegisterDriver(name, f)
    }
}

/**
 * 获取已注册适配器
 */
func GetDriver(name string, conf map[string]interface{}, once ...bool) interfaces.Adapter {
    name = driverPrefix + name

    var data interface{}
    reg := register.New()
    if len(once) > 0 && once[0] {
        data = reg.GetOnce(name, conf)
    } else {
        data = reg.Get(name, conf)
    }

    if data != nil {
        return data.(interfaces.Adapter)
    }

    return nil
}
