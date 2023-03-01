package config

import (
    "fmt"
    "sync"

    "github.com/deatil/lakego-doak/lakego/path"
    "github.com/deatil/lakego-doak/lakego/array"
    "github.com/deatil/lakego-doak/lakego/register"
    "github.com/deatil/lakego-doak/lakego/config"
    "github.com/deatil/lakego-doak/lakego/config/interfaces"
    viper_adapter "github.com/deatil/lakego-doak/lakego/config/adapter/viper"
)

var (
    // 默认驱动
    defaultAdapter = "viper"

    // 配置目录
    defaultConfigPath = "{root}/config"

    // 读写锁
    rwm = &sync.RWMutex{}

    // 使用过的配置
    usedConfigs = make(map[string]*config.Config)
)

// 初始化
func init() {
    // 注册默认
    registerAdapter()
}

// 配置别名
type Config = config.Config

/**
 * 配置
 *
 * @create 2021-9-25
 * @author deatil
 */
func New(name string) *config.Config {
    return NewWithAdapter(name, defaultAdapter)
}

// 实例化
func NewWithAdapter(name string, adapter string) *config.Config {
    key := fmt.Sprintf("%s:%s", name, adapter)

    rwm.RLock()
    cfg, ok := usedConfigs[key]
    rwm.RUnlock()

    if ok {
        return cfg
    }

    cfg = newConfig(adapter, name)

    rwm.Lock()
    usedConfigs[key] = cfg
    rwm.Unlock()

    return cfg
}

// 配置
func newConfig(adapterName string, name string, once ...bool) *config.Config {
    adapter := register.
        NewManagerWithPrefix("config").
        GetRegister(adapterName, map[string]any{
            "name": name,
        }, once...)
    if adapter == nil {
        panic("配置驱动[" + adapterName + "]没有被注册")
    }

    newAdapter, ok := adapter.(interfaces.Adapter)
    if !ok {
        panic("配置驱动[" + adapterName + "]错误")
    }

    conf := config.New(newAdapter)

    return conf
}

// 设置默认驱动
func SetAdapter(name string) {
    defaultAdapter = name
}

// 设置配置路径
func SetConfigPath(cfgPath string) {
    defaultConfigPath = cfgPath
}

// 注册磁盘
func registerAdapter() {
    // 注册可用驱动
    register.
        NewManagerWithPrefix("config").
        Register("viper", func(conf map[string]any) any {
            adapter := viper_adapter.New()

            // 配置文件夹
            configPath := path.FormatPath(defaultConfigPath)

            // 设置 env 前缀
            adapter.SetEnvPrefix("LAKEGO")
            adapter.AutomaticEnv()
            adapter.WithPath(configPath)

            // 设置文件
            name := array.ArrayGet(conf, "name").ToString()
            adapter.WithFile(name)

            return adapter
        })
}

