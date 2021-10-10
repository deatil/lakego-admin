package sign

import (
    "time"
    "errors"
    "strconv"

    "github.com/deatil/lakego-admin/lakego/sign/util"
    "github.com/deatil/lakego-admin/lakego/sign/interfaces"
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
    config map[string]interface{}

    // 驱动
    driver interfaces.Driver

    // 数据
    data map[string]string

    // 签名key
    signKey string
}

// 返回字符
func (s *Sign) String() string {
    return "sign"
}

// 设置配置
func (s *Sign) WithConfig(config map[string]interface{}) *Sign {
    s.config = config

    return s
}

// 获取配置
func (s *Sign) GetConfig(name string) interface{} {
    if data, ok := s.config[name]; ok {
        return data
    }

    return nil
}

// 设置驱动
func (s *Sign) WithDriver(driver interfaces.Driver) *Sign {
    s.driver = driver

    return s
}

// 获取驱动
func (s *Sign) GetDriver() interfaces.Driver {
    return s.driver
}

// 设置签名key
func (s *Sign) WithSignKey(signKey string) *Sign {
    s.signKey = signKey

    return s
}

// 获取签名key
func (s *Sign) GetSignKey() string {
    return s.signKey
}

// 返回单个
func (s *Sign) GetData(key string) string {
    return s.data[key]
}

// 返回全部
func (s *Sign) GetDatas() map[string]string {
    return s.data
}

// 添加签名体字段和值
func (s *Sign) WithData(key string, value string) *Sign {
    s.data[key] = value

    return s
}

// 批量设置
func (s *Sign) WithDatas(data map[string]string) *Sign {
    for k, v := range data {
        s.WithData(k, v)
    }

    return s
}

// 设置时间戳
func (s *Sign) WithTimestamp(ts int64) *Sign {
    return s.WithData(KeyNameTimeStamp, strconv.FormatInt(ts, 10))
}

// 获取时间戳
func (s *Sign) GetTimestamp() string {
    return s.GetData(KeyNameTimeStamp)
}

// 设置随机字符
func (s *Sign) WithNonceStr(nonce string) *Sign {
    return s.WithData(KeyNameNonceStr, nonce)
}

// 返回随机字符
func (s *Sign) GetNonceStr() string {
    return s.GetData(KeyNameNonceStr)
}

// 设置 AppId
func (s *Sign) WithAppID(appID string) *Sign {
    return s.WithData(KeyNameAppID, appID)
}

// 获取 AppId
func (s *Sign) GetAppID() string {
    return s.GetData(KeyNameAppID)
}

// 获取要签名的字符
func (s *Sign) GetSignDataString() (string, error) {
    // 重设时间
    timestamp := s.GetTimestamp()
    if timestamp == "" {
        s.WithTimestamp(time.Now().Unix())
    }

    // 重设随机字符
    nonceStr := s.GetNonceStr()
    if nonceStr == "" {
        s.WithNonceStr(util.RandomStr(10))
    }

    // 重设 appId
    appId := s.GetAppID()
    if appId == "" {
        return "", errors.New("签名 appId 不能为空")
    }

    signData := util.SortKVPairs(s.data)

    if s.signKey != "" {
        signData = signData + "&" + KeyNameSignKey + "=" + s.signKey
    }

    return signData, nil
}

// 生成签名
func (s *Sign) CreateSign(data string) string {
    return s.driver.Sign(data)
}

// 生成签名
func (s *Sign) MakeSign() (string, error) {
    signData, err := s.GetSignDataString()
    if err != nil {
        return "", err
    }

    return s.CreateSign(signData), nil
}

// 获取生成的所有数据
func (s *Sign) GetSignMap() map[string]string {
    sign, _ := s.MakeSign()
    s.WithData(KeyNameSign, sign)

    data := s.GetDatas()

    return data
}
