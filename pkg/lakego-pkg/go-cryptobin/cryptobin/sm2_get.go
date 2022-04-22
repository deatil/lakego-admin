package cryptobin

import (
    "github.com/tjfoc/gmsm/sm2"
)

// 获取 PrivateKey
func (this SM2) GetPrivateKey() *sm2.PrivateKey {
    return this.privateKey
}

// 获取 PublicKey
func (this SM2) GetPublicKey() *sm2.PublicKey {
    return this.publicKey
}

// 获取 keyData
func (this SM2) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this SM2) GetData() []byte {
    return this.data
}

// 获取 paredData
func (this SM2) GetParedData() []byte {
    return this.paredData
}

// 获取验证后情况
func (this SM2) GetVeryed() bool {
    return this.veryed
}

// 获取错误
func (this SM2) GetError() error {
    return this.Error
}
