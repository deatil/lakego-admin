package logger

import (
    "sync"

    "github.com/deatil/lakego-admin/lakego/register"
    "github.com/deatil/lakego-admin/lakego/facade/config"
    "github.com/deatil/lakego-admin/lakego/logger"
    "github.com/deatil/lakego-admin/lakego/logger/interfaces"
    logrusDriver "github.com/deatil/lakego-admin/lakego/logger/driver/logrus"
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
func New(once ...bool) *logger.Logger {
    // 默认驱动
    driver := GetDefaultDriver()

    return NewLogger(driver, once...)
}

// 验证码
func NewLogger(driverName string, once ...bool) *logger.Logger {
    // 配置
    conf := config.New("logger")

    // 驱动列表
    drivers := conf.GetStringMap("Drivers")

    // 获取配置
    driverConfig, ok := drivers[driverName]
    if !ok {
        panic("日志驱动 " + driverName + " 配置不存在")
    }

    // 驱动配置
    driverConf := driverConfig.(map[string]interface{})

    driverType := driverConf["type"].(string)
    driver := register.
        NewManagerWithPrefix("logger-driver").
        GetRegister(driverType, driverConf, once...)
    if driver == nil {
        panic("日志驱动 " + driverType + " 没有被注册")
    }

    return logger.New(driver.(interfaces.Driver))
}

// 默认驱动
func GetDefaultDriver() string {
    return config.New("logger").GetString("DefaultDriver")
}

// 注册
func Register() {
    once.Do(func() {
        // 注册驱动
        register.
            NewManagerWithPrefix("logger-driver").
            RegisterMany(map[string]func(map[string]interface{}) interface{} {
                // logrus 日志
                "logrus": func(conf map[string]interface{}) interface{} {
                    driver := logrusDriver.New()

                    driver.WithConfig(conf)

                    return driver
                },
            })
    })
}


