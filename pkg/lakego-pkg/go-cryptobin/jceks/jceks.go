package jceks

import (
    "io"
    "bytes"
)

// LoadFromReader loads the key store from the specified file.
func LoadFromReader(reader io.Reader, password string) (*JceksDecode, error) {
    ks := &JceksDecode{
        entries: make(map[string]interface{}),
    }

    err := ks.Parse(reader, password)
    if err != nil {
        return nil, err
    }

    return ks, err
}

// LoadFromBytes loads the key store from the bytes data.
func LoadFromBytes(data []byte, password string) (*JceksDecode, error) {
    buf := bytes.NewReader(data)

    return LoadFromReader(buf, password)
}

// 构造函数
func NewJceksEncode() *JceksEncode {
    return &JceksEncode{
        privateKeys:  make(map[string]privateKeyEntryData),
        trustedCerts: make(map[string]trustedCertEntryData),
        secretKeys:   make(map[string]secretKeyEntryData),
        count:        0,
    }
}
