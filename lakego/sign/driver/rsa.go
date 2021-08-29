package driver

import (
    "strings"

    "lakego-admin/lakego/sign/crypt"
)

type Rsa struct {
    // 公钥
    publicKey string

    // 私钥
    privateKey string
}

// 初始化
func (r *Rsa) Init(conf map[string]interface{}) {
    if publicKey, ok := conf["publickey"]; ok {
        r.publicKey = publicKey.(string)
    }

    if privateKey, ok := conf["privatekey"]; ok {
        r.privateKey = privateKey.(string)
    }
}

// 签名
func (r *Rsa) Sign(data string) string {
    sha1Data := strings.ToUpper(crypt.SHA1(data))
    newData, _ := crypt.RsaPublicEncrypt(sha1Data, r.publicKey)

    return newData
}

// 验证
func (r *Rsa) Validate(data string, signData string) bool {
    newData := strings.ToUpper(crypt.SHA1(data))

    newSignData, _ := crypt.RsaPrivateDecrypt(signData, r.privateKey)

    return newData == newSignData
}
