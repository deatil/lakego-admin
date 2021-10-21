package driver

import (
    "strings"

    "github.com/deatil/lakego-admin/lakego/sign/crypt"
)

type Hmac struct {
    key string
}

// 初始化
func (this *Hmac) Init(conf map[string]interface{}) {
    if key, ok := conf["key"]; ok {
        this.key = key.(string)
    }
}

// 签名
func (this *Hmac) Sign(data string) string {
    return strings.ToUpper(crypt.Hmac(this.key, data))
}

// 验证
func (this *Hmac) Validate(data string, signData string) bool {
    newData := this.Sign(data)

    return newData == signData
}
