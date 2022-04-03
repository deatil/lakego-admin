package cryptobin

// 私钥/公钥
func (this Ecdsa) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this Ecdsa) ToKeyString() string {
    return string(this.keyData)
}

// ==========

// 输出字节
func (this Ecdsa) ToBytes() []byte {
    return this.paredData
}

// 输出字符
func (this Ecdsa) ToString() string {
    return string(this.paredData)
}

// 输出Base64
func (this Ecdsa) ToBase64String() string {
    return this.Base64Encode(this.paredData)
}

// 输出Hex
func (this Ecdsa) ToHexString() string {
    return this.HexEncode(this.paredData)
}

// ==========

// 验证情况
func (this Ecdsa) ToVeryed() bool {
    return this.veryed
}
