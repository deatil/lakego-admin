package storage

import(
    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/storage/register"
    "lakego-admin/lakego/storage/fllesystem"
    localAdapter "lakego-admin/lakego/fllesystem/adapter/local"
)

// 开始就注册磁盘
func init() {
    disks := config.New("filesystem").GetStringMap("Disks")

    // 本地磁盘
    localConf := disks["local"].(map[string]interface{})
    localRoot := localConf["root"].(string)
    register.RegisterFllesystem("local", fllesystem.New(localAdapter.New(localRoot), localConf))

    // 公共磁盘
    publicConf := disks["public"].(map[string]interface{})
    publicRoot := publicConf["root"].(string)
    register.RegisterFllesystem("public", fllesystem.New(localAdapter.New(publicRoot), publicConf))
}

func Disk(disk string) interfaces.Fllesystem {
    return register.GetFllesystem(disk)
}

func GetDefaultDisk() string {
    return config.New("filesystem").GetString("Default")
}
