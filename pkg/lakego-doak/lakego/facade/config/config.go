package config

import (
    "sync"

    "github.com/deatil/lakego-doak/lakego/register"
    "github.com/deatil/lakego-doak/lakego/support/path"

    "github.com/deatil/lakego-doak/lakego/config"
    "github.com/deatil/lakego-doak/lakego/config/interfaces"
    viperAdapter "github.com/deatil/lakego-doak/lakego/config/adapter/viper"
)

var once sync.Once

// 初始化
func init() {
    // 注册默认
    Register()
}

// 配置别名
type Config = config.Config

/**
 * 配置
 *
 * @create 2021-9-25
 * @author deatil
 */
func New(name ...string) *config.Config {
    adapter := GetDefaultAdapter()

    if len(name) > 0 {
        return NewConfig(adapter).WithFile(name[0])
    }

    return NewConfig(adapter)
}

// 实例化
func NewWithAdapter(name string, adapter string) *config.Config {
    return NewConfig(adapter).WithFile(name)
}

// 配置
func NewConfig(name string, once ...bool) *config.Config {
    adapter := register.
        NewManagerWithPrefix("config").
        GetRegister(name, nil, once...)
    if adapter == nil {
        panic("配置驱动[" + name + "]没有被注册")
    }

    conf := &config.Config{}
    conf.WithAdapter(adapter.(interfaces.Adapter))

    return conf
}

func GetDefaultAdapter() string {
    return "viper"
}

// 注册磁盘
func Register() {
    once.Do(func() {
        // 注册可用驱动
        register.
            NewManagerWithPrefix("config").
            Register("viper", func(conf map[string]interface{}) interface{} {
                adapter := &viperAdapter.Viper{}

                // 配置文件夹
                configPath := path.FormatPath("{root}/config")

                adapter.Init()
                adapter.WithPath(configPath)

                return adapter
            })
    })
}

