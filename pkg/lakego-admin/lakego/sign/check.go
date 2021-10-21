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
func (this *Check) String() string {
    return "check"
}

// 设置配置
func (this *Check) WithConfig(config map[string]interface{}) *Check {
    this.config = config

    return this
}

// 获取配置
func (this *Check) GetConfig(name string) interface{} {
    if data, ok := this.config[name]; ok {
        return data
    }

    return nil
}

func (this *Check) WithDriver(driver interfaces.Driver) *Check {
    this.driver = driver

    return this
}

// 批量设置
func (this *Check) WithData(key string, value string) *Check {
    this.data[key] = value

    return this
}

// 批量设置
func (this *Check) WithDatas(data map[string]string) *Check {
    if len(data) > 0{
        for k, v := range data {
            this.WithData(k, v)
        }
    }

    return this
}

// 设置过期时间
func (this *Check) WithTimeout(timeout int64) *Check {
    this.timeout = timeout

    return this
}

// 返回单个
func (this *Check) GetData(key string) string {
    return this.data[key]
}

// 返回单个 int64
func (this *Check) GetDataInt64(key string) int64 {
    data, _ := util.StringToInt64(this.data[key])

    return data
}

// 获取时间戳
func (this *Check) GetTimestamp() int64 {
    time := this.GetDataInt64(KeyNameTimeStamp)

    return time
}

// 返回随机字符
func (this *Check) GetNonceStr() string {
    return this.GetData(KeyNameNonceStr)
}

// 获取 AppId
func (this *Check) GetAppID() string {
    return this.GetData(KeyNameAppID)
}

// 获取签名
func (this *Check) GetSign() string {
    return this.GetData(KeyNameSign)
}

// 获取不包含 sign 字段的数据
func (this *Check) GetDataWithoutSign() map[string]string {
    data := make(map[string]string)

    for k, val := range this.data {
        if k != KeyNameSign {
            data[k] = val
        }
    }

    return data
}

// 必须包含指定的字段参数
func (this *Check) MustHasKeys(keys ...string) error {
    for _, key := range keys {
        if _, hit := this.data[key]; !hit {
            return fmt.Errorf("丢失字段 %s", key)
        }
    }

    return nil
}

// 检测字段
func (this *Check) CheckKeys() error {
    fields := []string{
        KeyNameTimeStamp,
        KeyNameNonceStr,
        KeyNameAppID,
        KeyNameSign,
    }

    return this.MustHasKeys(fields...)
}

// 检查时间戳
func (this *Check) CheckTimeStamp() error {
    timestamp := this.GetTimestamp()
    thisTime := time.Unix(timestamp, 0)

    if timestamp > time.Now().Unix() || time.Since(thisTime) > time.Duration(this.timeout) * time.Second {
        return fmt.Errorf("时间已过期 %d", timestamp)
    }

    return nil
}

// 检测数据
func (this *Check) CheckData() (bool, error) {
    // 检测字段
    err := this.CheckKeys()
    if err != nil {
        return false, err
    }

    // 检测时间戳
    err2 := this.CheckTimeStamp()
    if err2 != nil {
        return false, err2
    }

    return true, nil
}

// 检测签名
func (this *Check) CheckSign(data string, signData string) bool {
    return this.driver.Validate(data, signData)
}
