package register

import(
    "lakego-admin/lakego/fllesystem/interfaces"
    driverRegister "lakego-admin/lakego/storage/register/driver"
    diskRegister "lakego-admin/lakego/storage/register/disk"
)

/**
 * 注册适配器
 */
func RegisterDriver(name string, f func() interfaces.Adapter) {
    driverRegister.New().With(name, f)
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
    return driverRegister.New().Get(name, once...)
}

/**
 * 注册磁盘
 */
func RegisterDisk(name string, f func() interfaces.Fllesystem) {
    diskRegister.New().With(name, f)
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
    return diskRegister.New().Get(name, once...)
}
