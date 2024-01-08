package xmssmt

import (
    "io"

    "github.com/deatil/go-cryptobin/xmss"
)

const XMSS_OID_LEN = 4

func GenerateKey(rand io.Reader, oid uint32) (*xmss.PrivateKey, *xmss.PublicKey, error) {
    params, err := NewParamsWithOid(oid)
    if err != nil {
        return nil, nil, err
    }

    priv, pub, err := xmss.GenerateKey(rand, params)
    if err != nil {
        return nil, nil, err
    }

    var i uint32

    d := make([]byte, XMSS_OID_LEN)
    x := make([]byte, XMSS_OID_LEN)

    for i = 0; i < XMSS_OID_LEN; i++ {
        d[XMSS_OID_LEN - i - 1] = byte((oid >> (8 * i)) & 0xFF)
        x[XMSS_OID_LEN - i - 1] = byte((oid >> (8 * i)) & 0xFF)
    }

    pri := new(xmss.PrivateKey)
    pri.D = append(d, priv.D...)

    pub2 := new(xmss.PublicKey)
    pub2.X = append(x, pub.X...)

    return pri, pub2, nil
}

func GenerateKeyWithName(rand io.Reader, name string) (*xmss.PrivateKey, *xmss.PublicKey, error) {
    oid, err := GetOidByName(name)
    if err != nil {
        return nil, nil, err
    }

    return GenerateKey(rand, oid)
}

func Sign(priv *xmss.PrivateKey, msg []byte) ([]byte, error) {
    var oid uint32 = 0
    var i uint32

    for i = 0; i < XMSS_OID_LEN; i++ {
        oid |= uint32(priv.D[XMSS_OID_LEN - i - 1]) << (i * 8)
    }

    params, err := NewParamsWithOid(oid)
    if err != nil {
        return nil, err
    }

    pri := new(xmss.PrivateKey)
    pri.D = priv.D[XMSS_OID_LEN:]

    return pri.Sign(params, msg)
}

func Verify(pub *xmss.PublicKey, msg, signature []byte) (match bool) {
    var oid uint32 = 0
    var i uint32

    for i = 0; i < XMSS_OID_LEN; i++ {
        oid |= uint32(pub.X[XMSS_OID_LEN - i - 1]) << (i * 8)
    }

    params, err := NewParamsWithOid(oid)
    if err != nil {
        return false
    }

    pub2 := new(xmss.PublicKey)
    pub2.X = pub.X[XMSS_OID_LEN:]

    return xmss.Verify(params, pub2, msg, signature)
}

// 获取私钥 OID 类型 / Get PrivateKey OID type name
func GetPrivateKeyTypeName(priv *xmss.PrivateKey) (string, error) {
    var oid uint32 = 0
    var i uint32

    for i = 0; i < XMSS_OID_LEN; i++ {
        oid |= uint32(priv.D[XMSS_OID_LEN - i - 1]) << (i * 8)
    }

    return GetNameByOid(oid)
}

// 获取公钥 OID 类型 / Get PublicKey OID type name
func GetPublicKeyTypeName(pub *xmss.PublicKey) (string, error) {
    var oid uint32 = 0
    var i uint32

    for i = 0; i < XMSS_OID_LEN; i++ {
        oid |= uint32(pub.X[XMSS_OID_LEN - i - 1]) << (i * 8)
    }

    return GetNameByOid(oid)
}

// 导出公钥 / Export PublicKey
func ExportPublicKey(priv *xmss.PrivateKey) (*xmss.PublicKey, error) {
    var oid uint32 = 0
    var i uint32

    for i = 0; i < XMSS_OID_LEN; i++ {
        oid |= uint32(priv.D[XMSS_OID_LEN - i - 1]) << (i * 8)
    }

    params, err := NewParamsWithOid(oid)
    if err != nil {
        return nil, err
    }

    pri := new(xmss.PrivateKey)
    pri.D = priv.D[XMSS_OID_LEN:]

    pub := pri.PublicKey(params)

    x := make([]byte, XMSS_OID_LEN)
    for i = 0; i < XMSS_OID_LEN; i++ {
        x[XMSS_OID_LEN - i - 1] = byte((oid >> (8 * i)) & 0xFF)
    }

    pub2 := new(xmss.PublicKey)
    pub2.X = append(x, pub.X...)

    return pub2, nil
}
