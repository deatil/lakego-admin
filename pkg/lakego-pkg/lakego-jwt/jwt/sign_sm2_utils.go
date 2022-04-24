package jwt

import (
    "github.com/tjfoc/gmsm/sm2"
    "github.com/tjfoc/gmsm/x509"
)

// 解析 SM2 PKCS8 私钥
func ParseSM2PrivateKeyFromPEM(key []byte) (*sm2.PrivateKey, error) {
    return x509.ReadPrivateKeyFromPem(key, nil)
}

// 解析 SM2 PKCS8 私钥带密码
func ParseSM2PrivateKeyFromPEMWithPassword(key []byte, pwd string) (*sm2.PrivateKey, error) {
    return x509.ReadPrivateKeyFromPem(key, []byte(pwd))
}

// 解析 SM2 PKCS8 公钥
func ParseSM2PublicKeyFromPEM(key []byte) (*sm2.PublicKey, error) {
    return x509.ReadPublicKeyFromPem(key)
}
