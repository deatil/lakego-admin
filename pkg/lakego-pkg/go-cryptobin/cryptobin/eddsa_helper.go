package cryptobin

// 私钥
func EdDSAFromPrivateKey(key []byte) EdDSA {
    return NewEdDSA().FromPrivateKey(key)
}

// 公钥
func EdDSAFromPublicKey(key []byte) EdDSA {
    return NewEdDSA().FromPublicKey(key)
}

// 生成密钥
func EdDSAGenerateKey() EdDSA {
    return NewEdDSA().GenerateKey()
}

// ==========

// 字节
func EdDSAFromBytes(data []byte) EdDSA {
    return NewEdDSA().FromBytes(data)
}

// 字符
func EdDSAFromString(data string) EdDSA {
    return NewEdDSA().FromString(data)
}

// Base64
func EdDSAFromBase64String(data string) EdDSA {
    return NewEdDSA().FromBase64String(data)
}

// Hex
func EdDSAFromHexString(data string) EdDSA {
    return NewEdDSA().FromHexString(data)
}
