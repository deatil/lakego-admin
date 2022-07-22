package cryptobin

import (
    "crypto/rsa"
    "crypto/x509"
)

// 获取 csr
func (this CA) GetCsr() *x509.Certificate {
    return this.csr
}

// 获取 PrivateKey
func (this CA) GetPrivateKey() *rsa.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this CA) GetPublicKey() *rsa.PublicKey {
    return this.publicKey
}

// 获取 keyData
func (this CA) GetKeyData() []byte {
    return this.keyData
}

// 获取错误
func (this CA) GetError() error {
    return this.Error
}
