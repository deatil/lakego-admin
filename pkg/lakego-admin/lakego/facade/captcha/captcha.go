package captcha

import (
    "sync"

    "github.com/deatil/lakego-admin/lakego/register"
    "github.com/deatil/lakego-admin/lakego/facade/config"
    "github.com/deatil/lakego-admin/lakego/captcha"
    "github.com/deatil/lakego-admin/lakego/captcha/interfaces"
    redisStore "github.com/deatil/lakego-admin/lakego/captcha/store/redis"
)

var once sync.Once

// 初始化
func init() {
    // 注册默认
    Register()
}

/**
 * 验证码
 *
 * @create 2021-10-12
 * @author deatil
 */
func New(once ...bool) captcha.Captcha {
    store := GetDefaultStore()

    return Captcha(store, once...)
}

// 验证码
func Captcha(name string, once ...bool) captcha.Captcha {
    // 存储列表
    stores := config.New("captcha").GetStringMap("Stores")

    // 获取配置
    storeConfig, ok := stores[name]
    if !ok {
        panic("验证码存储驱动 " + name + " 配置不存在")
    }

    // 配置
    storeConf := storeConfig.(map[string]interface{})

    storeType := storeConf["type"].(string)
    store := register.
        NewManagerWithPrefix("captcha-store").
        GetRegister(storeType, storeConf, once...)
    if store == nil {
        panic("验证码存储驱动 " + storeType + " 没有被注册")
    }

    // 验证码配置
    conf := config.New("captcha")

    height := conf.GetInt("Captcha.Height")
    width := conf.GetInt("Captcha.Width")
    noiseCount := conf.GetInt("Captcha.NoiseCount")
    showLineOptions := conf.GetInt("Captcha.ShowLineOptions")
    length := conf.GetInt("Captcha.Length")
    source := conf.GetString("Captcha.Source")
    fonts := conf.GetString("Captcha.Fonts")

    rgbaR := conf.GetInt("Captcha.RGBA.R")
    rgbaG := conf.GetInt("Captcha.RGBA.G")
    rgbaB := conf.GetInt("Captcha.RGBA.B")
    rgbaA := conf.GetInt("Captcha.RGBA.A")

    return captcha.New(captcha.Config{
        Height: height,
        Width: width,
        NoiseCount: noiseCount,
        ShowLineOptions: showLineOptions,
        Length: length,
        Source: source,
        Fonts: fonts,

        RBGA: captcha.RBGA{
            R: uint8(rgbaR),
            G: uint8(rgbaG),
            B: uint8(rgbaB),
            A: uint8(rgbaA),
        },
    }, store.(interfaces.Store))
}

// 默认
func GetDefaultStore() string {
    return config.New("captcha").GetString("DefaultStore")
}

// 注册
func Register() {
    once.Do(func() {
        // 注册驱动
        register.
            NewManagerWithPrefix("captcha-store").
            RegisterMany(map[string]func(map[string]interface{}) interface{} {
                "redis": func(conf map[string]interface{}) interface{} {
                    store := &redisStore.Redis{}

                    store.WithConfig(conf)
                    store.Init()

                    return store
                },
            })
    })
}


