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

// 根据私钥 x, y 生成
func FromKeyXYHexString(xString string, yString string) Ecdh {
    return NewEcdh().FromKeyXYHexString(xString, yString)
}

// 根据私钥 x 生成
func FromPrivateKeyXHexString(xString string) Ecdh {
    return NewEcdh().FromPrivateKeyXHexString(xString)
}

// 根据公钥 y 生成
func FromPublicKeyYHexString(yString string) Ecdh {
    return NewEcdh().FromPublicKeyYHexString(yString)
}

// 生成密钥
func GenerateKey() Ecdh {
    return NewEcdh().GenerateKey()
}
