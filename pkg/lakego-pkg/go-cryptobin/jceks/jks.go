package jceks

import (
    "io"
    "time"
    "bytes"
)

/**
 * Jks
 *
 * @create 2022-9-19
 * @author deatil
 */
type JKS struct {
    // 别名
    aliases      []string

    // 证书
    trustedCerts map[string][]byte

    // 私钥
    privateKeys  map[string][]byte

    // 证书链
    certChains   map[string][][]byte

    // 时间
    dates        map[string]time.Time
}

// 构造函数
func NewJKS() *JKS {
    return &JKS{
        aliases:      make([]string, 0),
        trustedCerts: make(map[string][]byte),
        privateKeys:  make(map[string][]byte),
        certChains:   make(map[string][][]byte),
        dates:        make(map[string]time.Time),
    }
}

// LoadJksFromReader loads the key store from the specified file.
func LoadJksFromReader(reader io.Reader, password string) (*JKS, error) {
    ks := NewJKS()

    err := ks.Parse(reader, password)
    if err != nil {
        return nil, err
    }

    return ks, err
}

// LoadFromBytes loads the key store from the bytes data.
func LoadJksFromBytes(data []byte, password string) (*JKS, error) {
    buf := bytes.NewReader(data)

    return LoadJksFromReader(buf, password)
}

// 编码
var NewJksEncode = NewJKS
