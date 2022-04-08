package driver

import (
    "strings"

    "github.com/deatil/go-sign/sign/crypt"
)

type SHA1 struct {
}

// 签名
func (this *SHA1) Sign(data string) string {
    return strings.ToUpper(crypt.SHA1(data))
}

// 验证
func (this *SHA1) Validate(data string, signData string) bool {
    newData := this.Sign(data)

    return newData == signData
}
