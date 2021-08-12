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
func RegisterDriver(name string, f func() interfaces.Adapter) {
    name = driverPrefix + name

    register.New().With(name, f)
}

/**
 * 批量注册驱动
 */
func RegisterDrivers(drivers map[string]func() interfaces.Adapter) {
    for name, f := range drivers {
        RegisterDriver(name, f)
    }
}

/**
 * 获取已注册适配器
 */
func GetDriver(name string, once ...bool) interfaces.Adapter {
    name = driverPrefix + name

    data := register.New().Get(name, once...)
    if data != nil {
        newData := data.(func() interfaces.Adapter)

        return newData()
    }

    return nil
}

/**
 * 注册磁盘
 */
func RegisterDisk(name string, f func() interfaces.Fllesystem) {
    name = diskPrefix + name

    register.New().With(name, f)
}

/**
 * 批量注册磁盘
 */
func RegisterDisks(disks map[string]func() interfaces.Fllesystem) {
    for name, f := range disks {
        RegisterDisk(name, f)
    }
}

/**
 * 获取已注册磁盘
 */
func GetDisk(name string, once ...bool) interfaces.Fllesystem {
    name = diskPrefix + name

    data := register.New().Get(name, once...)
    if data != nil {
        newData := data.(func() interfaces.Fllesystem)

        return newData()
    }

    return nil
}
