package rsa

// 检测公钥私钥是否匹配
func (this Rsa) CheckKeyPair() bool {
    // 私钥导出的公钥
    pubKeyFromPriKey := this.MakePublicKey().
        CreatePKCS8PublicKey().
        ToKeyString()

    // 公钥数据
    pubKeyFromPubKey := this.CreatePKCS8PublicKey().ToKeyString()

    if pubKeyFromPriKey == "" || pubKeyFromPubKey == "" {
        return false
    }

    if pubKeyFromPriKey == pubKeyFromPubKey {
        return true
    }

    return false
}
