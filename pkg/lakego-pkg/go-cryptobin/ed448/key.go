package ed448

import (
    "fmt"
    "errors"
    "encoding/asn1"
    "crypto/x509/pkix"
)

var (
    // ECDH
    oidPublicKeyEd448 = asn1.ObjectIdentifier{1, 3, 101, 113}
)

// 私钥 - 包装
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
}

// 公钥 - 包装
type pkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

// 公钥信息 - 解析
type publicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

// 包装公钥
func MarshalPublicKey(key PublicKey) ([]byte, error) {
    var publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier

    publicKeyAlgorithm.Algorithm = oidPublicKeyEd448

    publicKeyBytes = key

    pkix := pkixPublicKey{
        Algo: publicKeyAlgorithm,
        BitString: asn1.BitString{
            Bytes:     publicKeyBytes,
            BitLength: 8 * len(publicKeyBytes),
        },
    }

    return asn1.Marshal(pkix)
}

// 解析公钥
func ParsePublicKey(derBytes []byte) (pub PublicKey, err error) {
    var pki publicKeyInfo
    rest, err := asn1.Unmarshal(derBytes, &pki)
    if err != nil {
        return
    }

    if len(rest) > 0 {
        err = asn1.SyntaxError{Msg: "trailing data"}
        return
    }

    algoEq := pki.Algorithm.Algorithm.Equal(oidPublicKeyEd448)
    if !algoEq {
        err = errors.New("ed448: unknown public key algorithm")
        return
    }

    // 解析
    keyData := &pki

    publicKeyBytes := []byte(keyData.PublicKey.RightAlign())

    return PublicKey(publicKeyBytes), nil
}

// ====================

// 包装私钥
func MarshalPrivateKey(key PrivateKey) ([]byte, error) {
    var privKey pkcs8

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidPublicKeyEd448,
    }

    curvePrivateKey, err := asn1.Marshal(key.Seed())
    if err != nil {
        return nil, fmt.Errorf("ed448: failed to marshal private key: %v", err)
    }

    privKey.PrivateKey = curvePrivateKey

    return asn1.Marshal(privKey)
}

// 解析私钥
func ParsePrivateKey(derBytes []byte) (PrivateKey, error) {
    var privKey pkcs8
    var err error

    _, err = asn1.Unmarshal(derBytes, &privKey)
    if err != nil {
        return nil, err
    }

    algoEq := privKey.Algo.Algorithm.Equal(oidPublicKeyEd448)
    if !algoEq {
        err = errors.New("ed448: unknown private key algorithm")
        return nil, err
    }

    var curvePrivateKey []byte
    if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
        return nil, fmt.Errorf("ed448: invalid ED448 private key: %v", err)
    }

    if l := len(curvePrivateKey); l != SeedSize {
        return nil, fmt.Errorf("ed448: invalid ED448 private key length: %d", l)
    }

    return NewKeyFromSeed(curvePrivateKey), nil
}
