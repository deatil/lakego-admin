package sign

import (
    "strings"

    "github.com/deatil/go-sign/sign"
    "github.com/deatil/go-sign/sign/interfaces"
    signDriver "github.com/deatil/go-sign/sign/driver"

    "github.com/deatil/lakego-doak/lakego/register"
    "github.com/deatil/lakego-doak/lakego/path"
    "github.com/deatil/lakego-doak/lakego/facade/config"
)

/**
 * 缓存
 *
 * @create 2021-8-29
 * @author deatil
 */

// 初始化
func init() {
    // 注册默认
    Register()
}

// 签名
func NewSign() *sign.Sign {
    // 默认驱动
    driver := GetDefaultCrypt()

    return Sign(driver)
}

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
func NewCheck() *sign.Check {
    // 默认驱动
    driver := GetDefaultCrypt()

    return Check(driver)
}

// 检测
func Check(name string) *sign.Check {
    driver, conf := GetDriver(name)

    s := sign.NewCheck()
    s.WithConfig(conf)
    s.WithDriver(driver)

    return s
}

func GetDriver(name string) (interfaces.Driver, map[string]any) {
    // 驱动列表
    crypts := config.New("sign").GetStringMap("crypts")

    // 转为小写
    name = strings.ToLower(name)

    // 获取驱动配置
    driverConfig, ok := crypts[name]
    if !ok {
        panic("签名驱动[" + name + "]配置不存在")
    }

    // 配置
    driverConf := driverConfig.(map[string]any)

    driverType := driverConf["type"].(string)
    driver := register.
        NewManagerWithPrefix("sign").
        GetRegister(driverType, driverConf)
    if driver == nil {
        panic("签名驱动[" + driverType + "]没有被注册")
    }

    return driver.(interfaces.Driver), driverConf
}

// 默认签名
func GetDefaultCrypt() string {
    return config.New("sign").GetString("default")
}

// 注册
func Register() {
    // 注册驱动
    register.
        NewManagerWithPrefix("sign").
        RegisterMany(map[string]func(map[string]any) any {
            "aes": func(conf map[string]any) any {
                driver := &signDriver.Aes{}

                driver.Init(conf)

                return driver
            },

            "hmac": func(conf map[string]any) any {
                driver := &signDriver.Hmac{}

                driver.Init(conf)

                return driver
            },

            "md5": func(conf map[string]any) any {
                driver := &signDriver.MD5{}

                return driver
            },

            "sha1": func(conf map[string]any) any {
                driver := &signDriver.SHA1{}

                return driver
            },

            "rsa": func(conf map[string]any) any {
                driver := &signDriver.Rsa{}

                publicKey := conf["publickey"].(string)
                privateKey := conf["privatekey"].(string)

                publicKey = path.FormatPath(publicKey)
                privateKey = path.FormatPath(privateKey)

                driver.Init(map[string]any{
                    "publickey": publicKey,
                    "privatekey": privateKey,
                })

                return driver
            },

            "bcrypt": func(conf map[string]any) any {
                driver := &signDriver.Bcrypt{}

                return driver
            },
        })
}
