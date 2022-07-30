package ca

// 私钥/公钥/cert
func (this CA) ToKeyBytes() []byte {
    return this.keyData
}

// 私钥/公钥
func (this CA) ToKeyString() string {
    return string(this.keyData)
}
