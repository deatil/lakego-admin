package jceks

import (
    "io"
    "bytes"
)

const (
    BksVersionV1 = 1
    BksVersionV2 = 2

    bksEntryTypeCert   = 1
    bksEntryTypeKey    = 2
    bksEntryTypeSecret = 3
    bksEntryTypeSealed = 4

    bksKeyTypePrivate = 0
    bksKeyTypePublic  = 1
    bksKeyTypeSecret  = 2
)

/**
 * BKS
 *
 * @create 2022-9-19
 * @author deatil
 */
type BKS struct {
    // version
    version   uint32

    // storeType
    storeType string

    // data
    entries   map[string]any
}

// NewBKS
func NewBKS() *BKS {
    return &BKS{
        entries: make(map[string]any),
    }
}

// LoadBksFromReader loads the key store from the specified file.
func LoadBksFromReader(reader io.Reader, password string) (*BKS, error) {
    bks := &BKS{
        entries: make(map[string]any),
    }

    err := bks.Parse(reader, password)
    if err != nil {
        return nil, err
    }

    return bks, err
}

// LoadBksFromBytes loads the key store from the bytes data.
func LoadBksFromBytes(data []byte, password string) (*BKS, error) {
    buf := bytes.NewReader(data)

    return LoadBksFromReader(buf, password)
}

// alias
var NewBksEncode = NewBKS
