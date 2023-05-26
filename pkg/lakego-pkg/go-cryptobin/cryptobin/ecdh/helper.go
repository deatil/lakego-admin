package ecdh

// 私钥
func FromPrivateKey(key []byte) Ecdh {
    return NewEcdh().FromPrivateKey(key)
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) Ecdh {
    return NewEcdh().FromPrivateKeyWithPassword(key, password)
}

// 公钥
func FromPublicKey(key []byte) Ecdh {
    return NewEcdh().FromPublicKey(key)
}

// 生成密钥
func GenerateKey() Ecdh {
    return NewEcdh().GenerateKey()
}
