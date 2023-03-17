package jceks

import (
    "io"
    "bytes"
)

const (
    UberVersionV1 = 1
)

/**
 * UBER
 *
 * @create 2022-9-19
 * @author deatil
 */
type UBER struct {
    BKS
}

// 构造函数
func NewUBER() *UBER {
    uber := &UBER{
        BKS{
            entries: make(map[string]any),
        },
    }

    return uber
}

// LoadUberFromReader
func LoadUberFromReader(reader io.Reader, password string) (*UBER, error) {
    buf := bytes.NewBuffer(nil)

    // 保存
    if _, err := io.Copy(buf, reader); err != nil {
        return nil, err
    }

    return LoadUberFromBytes(buf.Bytes(), password)
}

// LoadUberFromBytes loads the key store from the bytes data.
func LoadUberFromBytes(data []byte, password string) (*UBER, error) {
    uber := &UBER{
        BKS{
            entries: make(map[string]any),
        },
    }

    err := uber.Parse(data, password)
    if err != nil {
        return nil, err
    }

    return uber, err
}

// 别名
var LoadUber      = LoadUberFromBytes
var NewUberEncode = NewUBER
