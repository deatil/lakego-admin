package driver

import (
    "strings"

    "lakego-admin/lakego/sign/crypt"
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
func (a *Aes) Init(conf map[string]interface{}) {
    if key, ok := conf["key"]; ok {
        a.key = key.(string)
    }

    if iv, ok := conf["iv"]; ok {
        a.iv = iv.(string)
    }
}

// 签名
func (a *Aes) Sign(data string) string {
    sha1Data := strings.ToUpper(crypt.SHA1(data))
    cryptData, _ := crypt.AesEncrypt(sha1Data, []byte(a.key), a.iv)

    return cryptData
}

// 验证
func (a *Aes) Validate(data string, signData string) bool {
    newData := strings.ToUpper(crypt.SHA1(data))

    newSignData, _ := crypt.AesDecrypt(signData, []byte(a.key), a.iv)

    return newData == newSignData
}

