package cryptobin

import (
    "crypto/dsa"
    "encoding/asn1"
)

// 包装公钥
func (this DSA) MarshalPublicKey(publicKey dsa.PublicKey) ([]byte, error) {
    return asn1.Marshal(publicKey)
}

// 解析公钥
func (this DSA) ParsePublicKey(derBytes []byte) (*dsa.PublicKey, error) {
    var publicKey dsa.PublicKey
    _, err := asn1.Unmarshal(derBytes, &publicKey)
    if err != nil {
        return nil, err
    }

    return &publicKey, nil
}

// ====================

// 包装私钥
func (this DSA) MarshalPrivateKey(privateKey dsa.PrivateKey) ([]byte, error) {
    return asn1.Marshal(privateKey)
}

// 解析私钥
func (this DSA) ParsePrivateKey(derBytes []byte) (*dsa.PrivateKey, error) {
    var privateKey dsa.PrivateKey
    _, err := asn1.Unmarshal(derBytes, &privateKey)
    if err != nil {
        return nil, err
    }

    return &privateKey, nil
}
