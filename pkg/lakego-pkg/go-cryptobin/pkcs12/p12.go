package pkcs12

import (
    "io"
    "bytes"
)

const (
    // PKCS12 系列
    PKCS12Version = 3
)

// PKCS12 结构
type PKCS12 struct {
    // 私钥
    privateKey []byte

    // 证书
    cert []byte

    // 证书链
    caCerts [][]byte

    // 证书链带名称, 适配 JAVA
    trustStores []TrustStoreData

    // sdsi
    sdsiCert []byte

    // 证书移除列表
    crl []byte

    // 密钥
    secretKey []byte

    // localKeyId
    localKeyId []byte

    // 解析后数据
    parsedData map[string][]ISafeBagData

    // Enveloped 加密配置
    envelopedOpts *EnvelopedOpts
}

func NewPKCS12() *PKCS12 {
    return &PKCS12{
        caCerts:     make([][]byte, 0),
        trustStores: make([]TrustStoreData, 0),
        parsedData:  make(map[string][]ISafeBagData),
    }
}

func (this *PKCS12) WithLocalKeyId(id []byte) *PKCS12 {
    this.localKeyId = id

    return this
}

func (this *PKCS12) WithEnvelopedOpts(opts EnvelopedOpts) *PKCS12 {
    this.envelopedOpts = &opts

    return this
}

func (this *PKCS12) String() string {
    return "PKCS12"
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
var LoadPKCS12      = LoadPKCS12FromBytes
var NewPKCS12Encode = NewPKCS12
