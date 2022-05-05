package driver

import (
    "strings"

    "github.com/deatil/go-sign/sign/crypt"
)

/**
 * Aes 验证
 *
 * @create 2021-8-28
 * @author deatil
 */
type Aes struct {
    // 秘钥
    key string

    iv string
}

// 初始化
func (this *Aes) Init(conf map[string]any) {
    if key, ok := conf["key"]; ok {
        this.key = key.(string)
    }

    if iv, ok := conf["iv"]; ok {
        this.iv = iv.(string)
    }
}

// 签名
func (this *Aes) Sign(data string) string {
    sha1Data := strings.ToUpper(crypt.SHA1(data))
    cryptData, _ := crypt.AesEncrypt(sha1Data, []byte(this.key), this.iv)

    return cryptData
}

// 验证
func (this *Aes) Validate(data string, signData string) bool {
    newData := strings.ToUpper(crypt.SHA1(data))

    newSignData, _ := crypt.AesDecrypt(signData, []byte(this.key), this.iv)

    return newData == newSignData
}

