package driver

import (
    "strings"

    "github.com/deatil/lakego-admin/lakego/sign/crypt"
)

type Hmac struct {
    key string
}

// 初始化
func (h *Hmac) Init(conf map[string]interface{}) {
    if key, ok := conf["key"]; ok {
        h.key = key.(string)
    }
}

// 签名
func (h *Hmac) Sign(data string) string {
    return strings.ToUpper(crypt.Hmac(h.key, data))
}

// 验证
func (h *Hmac) Validate(data string, signData string) bool {
    newData := h.Sign(data)

    return newData == signData
}
