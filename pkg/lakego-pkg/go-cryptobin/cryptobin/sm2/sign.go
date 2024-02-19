package sm2

import (
    "errors"
    "math/big"
    "crypto/rand"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/tool"
    "github.com/deatil/go-cryptobin/gm/sm2"
)

// 私钥签名
func (this SM2) Sign() SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: privateKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    parsedData, err := this.privateKey.Sign(rand.Reader, hashed, nil)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this SM2) Verify(data []byte) SM2 {
    if this.publicKey == nil {
        err := errors.New("SM2: publicKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.signHash, data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = this.publicKey.Verify(hashed, this.data, nil)

    return this
}

// ===============

type sm2Signature struct {
    R, S *big.Int
}

// 私钥签名
func (this SM2) SignASN1(uid []byte) SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: privateKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    r, s, err := sm2.SignWithSM2(rand.Reader, this.privateKey, hashed, uid)
    if err != nil {
        return this.AppendError(err)
    }

    parsedData, err := asn1.Marshal(sm2Signature{r, s})
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this SM2) VerifyASN1(data []byte, uid []byte) SM2 {
    if this.publicKey == nil {
        err := errors.New("SM2: publicKey error.")
        return this.AppendError(err)
    }

    var sm2Sign sm2Signature
    _, err := asn1.Unmarshal(this.data, &sm2Sign)
    if err != nil {
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.signHash, data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = sm2.VerifyWithSM2(this.publicKey, hashed, uid, sm2Sign.R, sm2Sign.S)

    return this
}

// ===============

// 私钥签名
// 兼容[招行]
func (this SM2) SignBytes(uid []byte) SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: privateKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    r, s, err := sm2.SignWithSM2(rand.Reader, this.privateKey, hashed, uid)
    if err != nil {
        return this.AppendError(err)
    }

    parsedData := make([]byte, 64)

    copy(parsedData[:32], tool.BytesPadding(r.Bytes(), 32))
    copy(parsedData[32:], tool.BytesPadding(s.Bytes(), 32))

    this.parsedData = parsedData

    return this
}

// 公钥验证
// 兼容[招行]
// 使用原始数据[data]对比签名后数据
func (this SM2) VerifyBytes(data []byte, uid []byte) SM2 {
    if this.publicKey == nil {
        err := errors.New("SM2: publicKey error.")
        return this.AppendError(err)
    }

    if len(this.data) != 64 {
        err := errors.New("SM2: sig error.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.signHash, data)
    if err != nil {
        return this.AppendError(err)
    }

    r := new(big.Int).SetBytes(this.data[:32])
    s := new(big.Int).SetBytes(this.data[32:])

    this.verify = sm2.VerifyWithSM2(this.publicKey, hashed, uid, r, s)

    return this
}

// ===============

// 签名后数据
func (this SM2) dataHash(fn HashFunc, data []byte) ([]byte, error) {
    if fn == nil {
        return data, nil
    }

    h := fn()
    h.Write(data)

    return h.Sum(nil), nil
}
