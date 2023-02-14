package curve25519

// 检测公钥私钥是否匹配
func (this Curve25519) CheckKeyPair() bool {
    // 私钥导出的公钥
    pubKeyFromPriKey := this.MakePublicKey().
        CreatePublicKey().
        ToKeyString()

    // 公钥数据
    pubKeyFromPubKey := this.CreatePublicKey().ToKeyString()

    if pubKeyFromPriKey == "" || pubKeyFromPubKey == "" {
        return false
    }

    if pubKeyFromPriKey == pubKeyFromPubKey {
        return true
    }

    return false
}
