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
func GetDriver(name string) interfaces.Adapter {
    return driverRegister.New().Get(name)
}

/**
 * 注册磁盘
 */
func RegisterDisk(name string, f func() interfaces.Fllesystem) {
    diskRegister.New().With(name, f)
}

/**
 * 获取已注册磁盘
 */
func GetDisk(name string) interfaces.Fllesystem {
    return diskRegister.New().Get(name)
}
