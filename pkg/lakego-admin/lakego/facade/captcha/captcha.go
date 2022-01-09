package captcha

import (
    "sync"
    "time"
    "image/color"

    "github.com/mojocn/base64Captcha"

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
    // 默认驱动
    driver := GetDefaultDriver()

    // 默认存储
    store := GetDefaultStore()

    return Captcha(driver, store, once...)
}

// 验证码
func Captcha(driverName string, storeName string, once ...bool) captcha.Captcha {
    // 验证码配置
    conf := config.New("captcha")

    // 存储列表
    stores := conf.GetStringMap("Stores")

    // 获取配置
    storeConfig, ok := stores[storeName]
    if !ok {
        panic("验证码存储驱动[" + storeName + "]配置不存在")
    }

    // 配置
    storeConf := storeConfig.(map[string]interface{})

    storeType := storeConf["type"].(string)
    store := register.
        NewManagerWithPrefix("captcha-store").
        GetRegister(storeType, storeConf, once...)
    if store == nil {
        panic("验证码存储驱动[" + storeType + "]没有被注册")
    }

    // 驱动列表
    drivers := conf.GetStringMap("Drivers")

    // 获取配置
    driverConfig, ok := drivers[driverName]
    if !ok {
        panic("验证码驱动[" + driverName + "]配置不存在")
    }

    // 驱动配置
    driverConf := driverConfig.(map[string]interface{})

    driverType := driverConf["type"].(string)
    driver := register.
        NewManagerWithPrefix("captcha-driver").
        GetRegister(driverType, driverConf, once...)
    if driver == nil {
        panic("验证码驱动[" + driverType + "]没有被注册")
    }

    return captcha.New(driver.(interfaces.Driver), store.(interfaces.Store))
}

// 默认存储
func GetDefaultStore() string {
    return config.New("captcha").GetString("DefaultStore")
}

// 默认驱动
func GetDefaultDriver() string {
    return config.New("captcha").GetString("DefaultDriver")
}

// 注册
func Register() {
    once.Do(func() {
        // 注册存储
        register.
            NewManagerWithPrefix("captcha-store").
            RegisterMany(map[string]func(map[string]interface{}) interface{} {
                "redis": func(conf map[string]interface{}) interface{} {
                    store := &redisStore.Redis{}

                    store.WithConfig(conf)
                    store.Init()

                    return store
                },
                // 验证码包该驱动有问题
                "syncmap": func(conf map[string]interface{}) interface{} {
                    liveTime := time.Minute * time.Duration(int64(conf["livetime"].(int)))

                    syncmap := base64Captcha.NewStoreSyncMap(liveTime)

                    return syncmap
                },
                "memory": func(conf map[string]interface{}) interface{} {
                    collectNum := conf["collectnum"].(int)
                    expiration := time.Minute * time.Duration(int64(conf["expiration"].(int)))

                    memory := base64Captcha.NewMemoryStore(collectNum, expiration)

                    return memory
                },
            })

        // 注册驱动
        register.
            NewManagerWithPrefix("captcha-driver").
            RegisterMany(map[string]func(map[string]interface{}) interface{} {
                // 字符
                "string": func(conf map[string]interface{}) interface{} {
                    /*
                    //go:embed fonts/*.ttf
                    //go:embed fonts/*.ttc
                    var embeddedFontsFS embed.FS

                    // 验证码字体驱动,
                    var fontsStorage *base64Captcha.EmbeddedFontsStorage = base64Captcha.NewEmbeddedFontsStorage(embeddedFontsFS)
                    */

                    bgColor := conf["bgcolor"].(map[string]interface{})

                    fonts := conf["fonts"].([]interface{})
                    newFonts := make([]string, 0)
                    for _, font := range fonts {
                        newFonts = append(newFonts, font.(string))
                    }

                    cd := base64Captcha.NewDriverString(
                        conf["height"].(int),
                        conf["width"].(int),
                        conf["noisecount"].(int),
                        conf["showlineoptions"].(int),
                        conf["length"].(int),
                        conf["source"].(string),
                        &color.RGBA{
                            R: uint8(bgColor["r"].(int)),
                            G: uint8(bgColor["g"].(int)),
                            B: uint8(bgColor["b"].(int)),
                            A: uint8(bgColor["a"].(int)),
                        },
                        // 自定义字体目录，参考 fontsStorage 相关注释
                        nil,
                        newFonts,
                    )

                    driver := cd.ConvertFonts()

                    return driver
                },
                // 中文
                "chinese": func(conf map[string]interface{}) interface{} {
                    bgColor := conf["bgcolor"].(map[string]interface{})

                    fonts := conf["fonts"].([]interface{})
                    newFonts := make([]string, 0)
                    for _, font := range fonts {
                        newFonts = append(newFonts, font.(string))
                    }

                    cd := base64Captcha.NewDriverChinese(
                        conf["height"].(int),
                        conf["width"].(int),
                        conf["noisecount"].(int),
                        conf["showlineoptions"].(int),
                        conf["length"].(int),
                        conf["source"].(string),
                        &color.RGBA{
                            R: uint8(bgColor["r"].(int)),
                            G: uint8(bgColor["g"].(int)),
                            B: uint8(bgColor["b"].(int)),
                            A: uint8(bgColor["a"].(int)),
                        },
                        // 自定义字体目录
                        nil,
                        newFonts,
                    )

                    driver := cd.ConvertFonts()

                    return driver
                },
                // 数学公式
                "math": func(conf map[string]interface{}) interface{} {
                    bgColor := conf["bgcolor"].(map[string]interface{})

                    fonts := conf["fonts"].([]interface{})
                    newFonts := make([]string, 0)
                    for _, font := range fonts {
                        newFonts = append(newFonts, font.(string))
                    }

                    cd := base64Captcha.NewDriverMath(
                        conf["height"].(int),
                        conf["width"].(int),
                        conf["noisecount"].(int),
                        conf["showlineoptions"].(int),
                        &color.RGBA{
                            R: uint8(bgColor["r"].(int)),
                            G: uint8(bgColor["g"].(int)),
                            B: uint8(bgColor["b"].(int)),
                            A: uint8(bgColor["a"].(int)),
                        },
                        // 自定义字体目录
                        nil,
                        newFonts,
                    )

                    driver := cd.ConvertFonts()

                    return driver
                },
                // 音频
                "audio": func(conf map[string]interface{}) interface{} {
                    driver := base64Captcha.NewDriverAudio(
                        conf["length"].(int),
                        conf["language"].(string),
                    )

                    return driver
                },
                // digit
                "digit": func(conf map[string]interface{}) interface{} {
                    driver := base64Captcha.NewDriverDigit(
                        conf["height"].(int),
                        conf["width"].(int),
                        conf["length"].(int),
                        conf["maxskew"].(float64),
                        conf["dotcount"].(int),
                    )

                    return driver
                },
            })
    })
}


