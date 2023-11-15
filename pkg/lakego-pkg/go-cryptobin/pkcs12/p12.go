package pkcs12

import (
    "io"
    "bytes"
    "crypto"
    "crypto/x509"
)

const (
    // PKCS12 系列
    PKCS12Version = 3
)

// PKCS12 结构
type PKCS12 struct {
    // 私钥
    privateKey crypto.PrivateKey

    // 证书
    cert *x509.Certificate

    // 证书链
    caCerts []*x509.Certificate

    // 证书链带名称, 适配 JAVA
    trustStores []TrustStoreEntry

    // 密钥
    secretKey []byte

    // 解析后数据
    parsedData map[string][]ISafeBagData
}

func (this *PKCS12) String() string {
    return "PKCS12"
}

func NewPKCS12() *PKCS12 {
    return &PKCS12{
        caCerts:     make([]*x509.Certificate, 0),
        trustStores: make([]TrustStoreEntry, 0),
        parsedData:  make(map[string][]ISafeBagData),
    }
}

// LoadPKCS12FromReader loads the key store from the specified file.
func LoadPKCS12FromReader(reader io.Reader, password string) (*PKCS12, error) {
    buf := bytes.NewBuffer(nil)

    // 保存
    if _, err := io.Copy(buf, reader); err != nil {
        return nil, err
    }

    return LoadPKCS12FromBytes(buf.Bytes(), password)
}

// LoadPKCS12FromBytes loads the key store from the bytes data.
func LoadPKCS12FromBytes(data []byte, password string) (*PKCS12, error) {
    pkcs12 := NewPKCS12()

    _, err := pkcs12.Parse(data, password)
    if err != nil {
        return nil, err
    }

    return pkcs12, err
}

// 别名
var NewPKCS12Encode = NewPKCS12
