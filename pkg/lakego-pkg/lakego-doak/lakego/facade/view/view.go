package view

import (
    "sync"
    "strings"

    "github.com/deatil/lakego-doak/lakego/register"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/view/html"
    "github.com/deatil/lakego-doak/lakego/view/html/interfaces"
    pongo2Adapter "github.com/deatil/lakego-doak/lakego/view/html/adapter/pongo2"
)

var once sync.Once

// 初始化
func init() {
    // 注册默认
    Register()
}

/**
 * 模板渲染
 *
 * @create 2022-1-9
 * @author deatil
 */
func New(once ...bool) *html.Html {
    name := GetDefaultAdapter()

    return Html(name, once...)
}

// 模板渲染
func Html(name string, once ...bool) *html.Html {
    // 连接列表
    adapters := config.New("view").GetStringMap("adapters")

    // 转为小写
    name = strings.ToLower(name)

    // 获取适配器配置
    adapterConfig, ok := adapters[name]
    if !ok {
        panic("视图适配器[" + name + "]配置不存在")
    }

    // 配置
    adapterConf := adapterConfig.(map[string]any)

    adapterType := adapterConf["type"].(string)
    adapter := register.
        NewManagerWithPrefix("view").
        GetRegister(adapterType, adapterConf, once...)
    if adapter == nil {
        panic("视图适配器[" + adapterType + "]没有被注册")
    }

    a := html.New(adapter.(interfaces.Adapter))

    return a
}

// 默认适配器
func GetDefaultAdapter() string {
    return config.New("view").GetString("default-adapter")
}

// 注册
func Register() {
    once.Do(func() {
        // 注册驱动
        register.
            NewManagerWithPrefix("view").
            RegisterMany(map[string]func(map[string]any) any {
                "pongo2": func(conf map[string]any) any {
                    path := conf["tmpl-dir"].(string)
                    adapter := pongo2Adapter.New(path)

                    return adapter
                },
            })
    })
}

