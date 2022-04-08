package driver

import (
    "strings"

    "github.com/deatil/go-sign/sign/crypt"
)

type MD5 struct {
}

// 签名
func (this *MD5) Sign(data string) string {
    return strings.ToUpper(crypt.MD5(data))
}

// 验证
func (this *MD5) Validate(data string, signData string) bool {
    newData := this.Sign(data)

    return newData == signData
}
