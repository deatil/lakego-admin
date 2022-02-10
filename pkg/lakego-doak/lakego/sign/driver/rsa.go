package driver

import (
    "strings"

    "github.com/deatil/lakego-doak/lakego/sign/crypt"
)

type Rsa struct {
    // 公钥
    publicKey string

    // 私钥
    privateKey string
}

// 初始化
func (this *Rsa) Init(conf map[string]interface{}) {
    if publicKey, ok := conf["publickey"]; ok {
        this.publicKey = publicKey.(string)
    }

    if privateKey, ok := conf["privatekey"]; ok {
        this.privateKey = privateKey.(string)
    }
}

// 签名
func (this *Rsa) Sign(data string) string {
    sha1Data := strings.ToUpper(crypt.SHA1(data))
    newData, _ := crypt.RsaPublicEncrypt(sha1Data, this.publicKey)

    return newData
}

// 验证
func (this *Rsa) Validate(data string, signData string) bool {
    newData := strings.ToUpper(crypt.SHA1(data))

    newSignData, _ := crypt.RsaPrivateDecrypt(signData, this.privateKey)

    return newData == newSignData
}
