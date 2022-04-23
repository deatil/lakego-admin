package cryptobin

import (
    "github.com/tjfoc/gmsm/sm2"
    "github.com/tjfoc/gmsm/x509"
)

// 解析 SM2 PKCS8 私钥
func (this SM2) ParsePrivateKeyFromPEM(key []byte) (*sm2.PrivateKey, error) {
    return x509.ReadPrivateKeyFromPem(key, nil)
}

// 解析 SM2 PKCS8 私钥带密码
func (this SM2) ParsePrivateKeyFromPEMWithPassword(key []byte, pwd []byte) (*sm2.PrivateKey, error) {
    return x509.ReadPrivateKeyFromPem(key, pwd)
}

// 解析 SM2 PKCS8 公钥
func (this SM2) ParsePublicKeyFromPEM(key []byte) (*sm2.PublicKey, error) {
    return x509.ReadPublicKeyFromPem(key)
}
