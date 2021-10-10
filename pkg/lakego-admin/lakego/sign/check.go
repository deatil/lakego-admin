package sign

import (
    "fmt"
    "time"

    "github.com/deatil/lakego-admin/lakego/sign/util"
    "github.com/deatil/lakego-admin/lakego/sign/interfaces"
)

// 实例化
func NewCheck() *Check {
    return &Check{
        data: make(map[string]string),
    }
}

/**
 * 验证
 *
 * @create 2021-8-28
 * @author deatil
 */
type Check struct {
    // 配置
    config map[string]interface{}

    // 驱动
    driver interfaces.Driver

    // 数据
    data map[string]string

    // 过期时间
    timeout int64
}

// 返回字符
func (c *Check) String() string {
    return "check"
}

// 设置配置
func (c *Check) WithConfig(config map[string]interface{}) *Check {
    c.config = config

    return c
}

// 获取配置
func (c *Check) GetConfig(name string) interface{} {
    if data, ok := c.config[name]; ok {
        return data
    }

    return nil
}

func (c *Check) WithDriver(driver interfaces.Driver) *Check {
    c.driver = driver

    return c
}

// 批量设置
func (c *Check) WithData(key string, value string) *Check {
    c.data[key] = value

    return c
}

// 批量设置
func (c *Check) WithDatas(data map[string]string) *Check {
    if len(data) > 0{
        for k, v := range data {
            c.WithData(k, v)
        }
    }

    return c
}

// 设置过期时间
func (c *Check) WithTimeout(timeout int64) *Check {
    c.timeout = timeout

    return c
}

// 返回单个
func (c *Check) GetData(key string) string {
    return c.data[key]
}

// 返回单个 int64
func (c *Check) GetDataInt64(key string) int64 {
    data, _ := util.StringToInt64(c.data[key])

    return data
}

// 获取时间戳
func (c *Check) GetTimestamp() int64 {
    time := c.GetDataInt64(KeyNameTimeStamp)

    return time
}

// 返回随机字符
func (c *Check) GetNonceStr() string {
    return c.GetData(KeyNameNonceStr)
}

// 获取 AppId
func (c *Check) GetAppID() string {
    return c.GetData(KeyNameAppID)
}

// 获取签名
func (c *Check) GetSign() string {
    return c.GetData(KeyNameSign)
}

// 获取不包含 sign 字段的数据
func (c *Check) GetDataWithoutSign() map[string]string {
    data := make(map[string]string)

    for k, val := range c.data {
        if k != KeyNameSign {
            data[k] = val
        }
    }

    return data
}

// 必须包含指定的字段参数
func (c *Check) MustHasKeys(keys ...string) error {
    for _, key := range keys {
        if _, hit := c.data[key]; !hit {
            return fmt.Errorf("丢失字段 %s", key)
        }
    }

    return nil
}

// 检测字段
func (c *Check) CheckKeys() error {
    fields := []string{
        KeyNameTimeStamp,
        KeyNameNonceStr,
        KeyNameAppID,
        KeyNameSign,
    }

    return c.MustHasKeys(fields...)
}

// 检查时间戳
func (c *Check) CheckTimeStamp() error {
    timestamp := c.GetTimestamp()
    thisTime := time.Unix(timestamp, 0)

    if timestamp > time.Now().Unix() || time.Since(thisTime) > time.Duration(c.timeout) * time.Second {
        return fmt.Errorf("时间已过期 %d", timestamp)
    }

    return nil
}

// 检测数据
func (c *Check) CheckData() (bool, error) {
    // 检测字段
    err := c.CheckKeys()
    if err != nil {
        return false, err
    }

    // 检测时间戳
    err2 := c.CheckTimeStamp()
    if err2 != nil {
        return false, err2
    }

    return true, nil
}

// 检测签名
func (c *Check) CheckSign(data string, signData string) bool {
    return c.driver.Validate(data, signData)
}
