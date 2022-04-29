package driver

import (
    "github.com/deatil/go-sign/sign/crypt"
)

// bcrypt 验证
type Bcrypt struct {
    key string
}

// 签名
func (this *Bcrypt) Sign(data string) string {
    return crypt.BcryptHash(data)
}

// 验证
func (this *Bcrypt) Validate(data string, signData string) bool {
    return crypt.BcryptCheck(data, signData)
}
