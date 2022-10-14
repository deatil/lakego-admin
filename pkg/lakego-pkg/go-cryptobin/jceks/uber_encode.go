package jceks

import (
    "bytes"
    "crypto/sha1"
    "encoding/asn1"
)

// 配置
type UBEROpts struct {
    SaltSize       int
    IterationCount int
}

// 默认配置
var UBERDefaultOpts = UBEROpts{
    SaltSize:       20,
    IterationCount: 10000,
}

func (this *UBER) Marshal(password string, opts ...UBEROpts) ([]byte, error) {
    opt := UBERDefaultOpts
    if len(opts) > 0 {
        opt = opts[0]
    }

    var err error

    version := UberVersionV1
    saltSize := opt.SaltSize
    iterationCount := opt.IterationCount

    // 原始数据
    entryBuf := bytes.NewBuffer(nil)

    this.marshalEntries(entryBuf)

    entryData := entryBuf.Bytes()

    h := sha1.New()
    h.Write(entryData)
    computed := h.Sum([]byte{})

    // 需要加密的数据
    plainBuf := bytes.NewBuffer(nil)

    err = writeOnly(plainBuf, entryData)
    if err != nil {
        return nil, err
    }

    err = writeOnly(plainBuf, computed)
    if err != nil {
        return nil, err
    }

    plaintext := plainBuf.Bytes()

    // 加密数据
    cipher := CipherSHA1AndTwofishForUBER
    cipher.saltSize = saltSize
    cipher.iterationCount = iterationCount

    encrypted, params, err := cipher.Encrypt([]byte(password), plaintext)
    if err != nil {
        return nil, err
    }

    var param pbeParam
    if _, err := asn1.Unmarshal(params, &param); err != nil {
        return nil, err
    }

    salt := param.Salt

    // 最后数据
    buf := bytes.NewBuffer(nil)

    err = writeUint32(buf, uint32(version))
    if err != nil {
        return nil, err
    }

    err = writeBytes(buf, salt)
    if err != nil {
        return nil, err
    }

    err = writeInt32(buf, int32(iterationCount))
    if err != nil {
        return nil, err
    }

    err = writeOnly(buf, encrypted)
    if err != nil {
        return nil, err
    }

    bufBytes := buf.Bytes()

    return bufBytes, nil
}
