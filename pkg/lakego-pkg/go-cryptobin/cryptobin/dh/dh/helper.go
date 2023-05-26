package dh

// 私钥
func FromPrivateKey(key []byte) Dh {
    return NewDH().FromPrivateKey(key)
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) Dh {
    return NewDH().FromPrivateKeyWithPassword(key, password)
}

// 公钥
func FromPublicKey(key []byte) Dh {
    return NewDH().FromPublicKey(key)
}

// 根据私钥 x, y 生成
func FromKeyXYHexString(xString string, yString string) Dh {
    return NewDH().FromKeyXYHexString(xString, yString)
}

// 根据私钥 x 生成
func FromPrivateKeyXHexString(xString string) Dh {
    return NewDH().FromPrivateKeyXHexString(xString)
}

// 根据公钥 y 生成
func FromPublicKeyYHexString(yString string) Dh {
    return NewDH().FromPublicKeyYHexString(yString)
}

// 生成密钥
func GenerateKey() Dh {
    return NewDH().GenerateKey()
}
