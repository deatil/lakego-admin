package jceks

import (
    "io"
    "time"
    "bytes"
)

// LoadJksFromReader loads the key store from the specified file.
func LoadJksFromReader(reader io.Reader, password string) (*JksDecode, error) {
    ks := &JksDecode{
        aliases:      make([]string, 0),
        trustedCerts: make(map[string][]byte),
        privateKeys:  make(map[string][]byte),
        certChains:   make(map[string][][]byte),
        dates:        make(map[string]time.Time),
    }

    err := ks.Parse(reader, password)
    if err != nil {
        return nil, err
    }

    return ks, err
}

// LoadFromBytes loads the key store from the bytes data.
func LoadJksFromBytes(data []byte, password string) (*JksDecode, error) {
    buf := bytes.NewReader(data)

    return LoadJksFromReader(buf, password)
}

// 构造函数
func NewJksEncode() *JksEncode {
    return &JksEncode{
        aliases:      make([]string, 0),
        trustedCerts: make(map[string][]byte),
        privateKeys:  make(map[string][]byte),
        certChains:   make(map[string][][]byte),
        dates:        make(map[string]time.Time),
    }
}
