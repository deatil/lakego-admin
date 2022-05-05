package sign

import (
    "time"
    "errors"
    "strconv"

    "github.com/deatil/go-sign/sign/util"
    "github.com/deatil/go-sign/sign/interfaces"
)

// 实例化
func NewSign() *Sign {
    return &Sign{
        data: make(map[string]string),
    }
}

/**
 * 签名
 *
 * @create 2021-8-28
 * @author deatil
 */
type Sign struct {
    // 配置
    config map[string]any

    // 驱动
    driver interfaces.Driver

    // 数据
    data map[string]string

    // 签名key
    signKey string
}

// 返回字符
func (this *Sign) String() string {
    return "sign"
}

// 设置配置
func (this *Sign) WithConfig(config map[string]any) *Sign {
    this.config = config

    return this
}

// 获取配置
func (this *Sign) GetConfig(name string) any {
    if data, ok := this.config[name]; ok {
        return data
    }

    return nil
}

// 设置驱动
func (this *Sign) WithDriver(driver interfaces.Driver) *Sign {
    this.driver = driver

    return this
}

// 获取驱动
func (this *Sign) GetDriver() interfaces.Driver {
    return this.driver
}

// 设置签名key
func (this *Sign) WithSignKey(signKey string) *Sign {
    this.signKey = signKey

    return this
}

// 获取签名key
func (this *Sign) GetSignKey() string {
    return this.signKey
}

// 返回单个
func (this *Sign) GetData(key string) string {
    return this.data[key]
}

// 返回全部
func (this *Sign) GetDatas() map[string]string {
    return this.data
}

// 添加签名体字段和值
func (this *Sign) WithData(key string, value string) *Sign {
    this.data[key] = value

    return this
}

// 批量设置
func (this *Sign) WithDatas(data map[string]string) *Sign {
    for k, v := range data {
        this.WithData(k, v)
    }

    return this
}

// 设置时间戳
func (this *Sign) WithTimestamp(ts int64) *Sign {
    return this.WithData(KeyNameTimeStamp, strconv.FormatInt(ts, 10))
}

// 获取时间戳
func (this *Sign) GetTimestamp() string {
    return this.GetData(KeyNameTimeStamp)
}

// 设置随机字符
func (this *Sign) WithNonceStr(nonce string) *Sign {
    return this.WithData(KeyNameNonceStr, nonce)
}

// 返回随机字符
func (this *Sign) GetNonceStr() string {
    return this.GetData(KeyNameNonceStr)
}

// 设置 AppId
func (this *Sign) WithAppID(appID string) *Sign {
    return this.WithData(KeyNameAppID, appID)
}

// 获取 AppId
func (this *Sign) GetAppID() string {
    return this.GetData(KeyNameAppID)
}

// 获取要签名的字符
func (this *Sign) GetSignDataString() (string, error) {
    // 重设时间
    timestamp := this.GetTimestamp()
    if timestamp == "" {
        this.WithTimestamp(time.Now().Unix())
    }

    // 重设随机字符
    nonceStr := this.GetNonceStr()
    if nonceStr == "" {
        this.WithNonceStr(util.RandomStr(10))
    }

    // 重设 appId
    appId := this.GetAppID()
    if appId == "" {
        return "", errors.New("签名 appId 不能为空")
    }

    signData := util.SortKVPairs(this.data)

    if this.signKey != "" {
        signData = signData + "&" + KeyNameSignKey + "=" + this.signKey
    }

    return signData, nil
}

// 生成签名
func (this *Sign) CreateSign(data string) string {
    return this.driver.Sign(data)
}

// 生成签名
func (this *Sign) MakeSign() (string, error) {
    signData, err := this.GetSignDataString()
    if err != nil {
        return "", err
    }

    return this.CreateSign(signData), nil
}

// 获取生成的所有数据
func (this *Sign) GetSignMap() map[string]string {
    sign, _ := this.MakeSign()
    this.WithData(KeyNameSign, sign)

    data := this.GetDatas()

    return data
}
