package jceks

import (
    "io"
    "bytes"
)

/**
 * JCEKS
 *
 * @create 2022-9-19
 * @author deatil
 */
type JCEKS struct {
    // 解析后数据
    entries      map[string]any
}

// 构造函数
func NewJCEKS() *JCEKS {
    return &JCEKS{
        entries: make(map[string]any),
    }
}

// LoadJceksFromReader loads the key store from the specified file.
func LoadJceksFromReader(reader io.Reader, password string) (*JCEKS, error) {
    ks := &JCEKS{
        entries: make(map[string]any),
    }

    err := ks.Parse(reader, password)
    if err != nil {
        return nil, err
    }

    return ks, err
}

// LoadJceksFromBytes loads the key store from the bytes data.
func LoadJceksFromBytes(data []byte, password string) (*JCEKS, error) {
    buf := bytes.NewReader(data)

    return LoadJceksFromReader(buf, password)
}

// 别名
var LoadFromReader = LoadJceksFromReader
var LoadFromBytes  = LoadJceksFromBytes
var NewJceksEncode = NewJCEKS
