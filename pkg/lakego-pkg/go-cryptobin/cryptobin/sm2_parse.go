package cryptobin

import (
    "github.com/tjfoc/gmsm/sm2"
    "github.com/tjfoc/gmsm/x509"
)

// 解析 SM2 PKCS8 私钥
func (this SM2) ParseSM2PrivateKeyFromPEM(key []byte) (*sm2.PrivateKey, error) {
    return x509.ReadPrivateKeyFromPem(key, nil)
}

// 解析 SM2 PKCS8 私钥带密码
func (this SM2) ParseSM2PrivateKeyFromPEMWithPassword(key []byte, pwd []byte) (*sm2.PrivateKey, error) {
    return x509.ReadPrivateKeyFromPem(key, pwd)
}

// 解析 SM2 PKCS8 公钥
func (this SM2) ParseSM2PublicKeyFromPEM(key []byte) (*sm2.PublicKey, error) {
    return x509.ReadPublicKeyFromPem(key)
}
