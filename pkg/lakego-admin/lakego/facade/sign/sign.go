package sign

import (
    "sync"
    "strings"

    "github.com/deatil/lakego-admin/lakego/register"
    "github.com/deatil/lakego-admin/lakego/support/path"
    "github.com/deatil/lakego-admin/lakego/facade/config"
    "github.com/deatil/lakego-admin/lakego/sign"
    "github.com/deatil/lakego-admin/lakego/sign/interfaces"

    signDriver "github.com/deatil/lakego-admin/lakego/sign/driver"
)

/**
 * 缓存
 *
 * @create 2021-8-29
 * @author deatil
 */

var once sync.Once

// 签名
func Sign(name string) *sign.Sign {
    driver, conf := GetDriver(name)

    s := sign.NewSign()
    s.WithConfig(conf)
    s.WithDriver(driver)

    if signType, ok := conf["signtype"]; ok {
        if signType.(string) == "query" {
            s.WithSignKey(conf["key"].(string))
        }
    }

    return s
}

// 检测
func Check(name string) *sign.Check {
    driver, conf := GetDriver(name)

    s := sign.NewCheck()
    s.WithConfig(conf)
    s.WithDriver(driver)

    return s
}

// 注册
func Register() {
    once.Do(func() {
        // 注册驱动
        register.
            NewManagerWithPrefix("sign").
            RegisterMany(map[string]func(map[string]interface{}) interface{} {
                "aes": func(conf map[string]interface{}) interface{} {
                    driver := &signDriver.Aes{}

                    driver.Init(conf)

                    return driver
                },

                "hmac": func(conf map[string]interface{}) interface{} {
                    driver := &signDriver.Hmac{}

                    driver.Init(conf)

                    return driver
                },

                "md5": func(conf map[string]interface{}) interface{} {
                    driver := &signDriver.MD5{}

                    driver.Init(conf)

                    return driver
                },

                "sha1": func(conf map[string]interface{}) interface{} {
                    driver := &signDriver.SHA1{}

                    driver.Init(conf)

                    return driver
                },

                "rsa": func(conf map[string]interface{}) interface{} {
                    driver := &signDriver.Rsa{}

                    publicKey := conf["publickey"].(string)
                    privateKey := conf["privatekey"].(string)

                    publicKey = path.FormatPath(publicKey)
                    privateKey = path.FormatPath(privateKey)

                    driver.Init(map[string]interface{}{
                        "publickey": publicKey,
                        "privatekey": privateKey,
                    })

                    return driver
                },
            })
    })
}

func GetDriver(name string) (interfaces.Driver, map[string]interface{}) {
    // 注册默认驱动
    Register()

    // 驱动列表
    crypts := config.New("sign").GetStringMap("crypts")

    // 获取驱动配置
    driverConfig, ok := crypts[name]
    if !ok {
        panic("签名驱动 " + name + " 配置不存在")
    }

    // 配置
    driverConf := driverConfig.(map[string]interface{})

    driverType := driverConf["type"].(string)
    driver := register.
        NewManagerWithPrefix("sign").
        GetRegister(driverType, driverConf)
    if driver == nil {
        panic("签名驱动 " + driverType + " 没有被注册")
    }

    return driver.(interfaces.Driver), driverConf
}
