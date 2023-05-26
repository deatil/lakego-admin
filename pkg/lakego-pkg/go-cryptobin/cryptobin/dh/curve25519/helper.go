package curve25519

// 私钥
func FromPrivateKey(key []byte) Curve25519 {
    return NewCurve25519().FromPrivateKey(key)
}

// 私钥
func FromPrivateKeyWithPassword(key []byte, password string) Curve25519 {
    return NewCurve25519().FromPrivateKeyWithPassword(key, password)
}

// 公钥
func FromPublicKey(key []byte) Curve25519 {
    return NewCurve25519().FromPublicKey(key)
}

// 根据私钥 x, y 生成
func FromKeyXYHexString(xString string, yString string) Curve25519 {
    return NewCurve25519().FromKeyXYHexString(xString, yString)
}

// 根据私钥 x 生成
func FromPrivateKeyXHexString(xString string) Curve25519 {
    return NewCurve25519().FromPrivateKeyXHexString(xString)
}

// 根据公钥 y 生成
func FromPublicKeyYHexString(yString string) Curve25519 {
    return NewCurve25519().FromPublicKeyYHexString(yString)
}

// 生成密钥
func GenerateKey() Curve25519 {
    return NewCurve25519().GenerateKey()
}
