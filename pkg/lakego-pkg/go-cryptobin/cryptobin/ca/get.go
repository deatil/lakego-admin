package ca

// 获取 cert
func (this CA) GetCert() any {
    return this.cert
}

// 获取 certRequest
func (this CA) GetCertRequest() any {
    return this.certRequest
}

// 获取 PrivateKey
func (this CA) GetPrivateKey() any {
    return this.privateKey
}

// 获取 publicKey
func (this CA) GetPublicKey() any {
    return this.publicKey
}

// 获取 keyData
func (this CA) GetKeyData() []byte {
    return this.keyData
}

// 获取错误
func (this CA) GetErrors() []error {
    return this.Errors
}
