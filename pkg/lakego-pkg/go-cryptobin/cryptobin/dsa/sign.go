package dsa

import (
    "errors"
    "strings"
    "math/big"
    "crypto/dsa"
    "crypto/rand"
    "encoding/asn1"
)

// 私钥签名
func (this DSA) Sign() DSA {
    switch this.encoding {
        case EncodingASN1:
            return this.SignASN1()
        case EncodingBytes:
            return this.SignBytes()
    }

    return this.SignASN1()
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this DSA) Verify(data []byte) DSA {
    switch this.encoding {
        case EncodingASN1:
            return this.VerifyASN1(data)
        case EncodingBytes:
            return this.VerifyBytes(data)
    }

    return this.VerifyASN1(data)
}

// ===============

type dsaSignature struct {
    R, S *big.Int
}

// 私钥签名
func (this DSA) SignASN1() DSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/dsa: privateKey empty.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.data)
    if err != nil {
        return this.AppendError(err)
    }

    r, s, err := dsa.Sign(rand.Reader, this.privateKey, hashed)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData, err = asn1.Marshal(dsaSignature{r, s})

    return this.AppendError(err)
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this DSA) VerifyASN1(data []byte) DSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/dsa: publicKey empty.")
        return this.AppendError(err)
    }

    var dsaSign dsaSignature
    _, err := asn1.Unmarshal(this.data, &dsaSign)
    if err != nil {
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = dsa.Verify(this.publicKey, hashed, dsaSign.R, dsaSign.S)

    return this
}

// ===============

const (
    // 字节大小
    dsaByteLen = 32
)

// 私钥签名
func (this DSA) SignBytes() DSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/dsa: privateKey empty.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.data)
    if err != nil {
        return this.AppendError(err)
    }

    r, s, err := dsa.Sign(rand.Reader, this.privateKey, hashed)
    if err != nil {
        return this.AppendError(err)
    }

    if (r.BitLen() / 8) > dsaByteLen || (s.BitLen() / 8) > dsaByteLen {
        err := errors.New("go-cryptobin/dsa: signature too large.")
        return this.AppendError(err)
    }

    buf := make([]byte, 2*dsaByteLen)

    r.FillBytes(buf[         0:  dsaByteLen])
    s.FillBytes(buf[dsaByteLen:2*dsaByteLen])

    this.parsedData = buf

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this DSA) VerifyBytes(data []byte) DSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/dsa: publicKey empty.")
        return this.AppendError(err)
    }

    // 签名结果数据
    sig := this.data

    if len(sig) != 2*dsaByteLen {
        err := errors.New("go-cryptobin/dsa: sig data error.")
        return this.AppendError(err)
    }

    r := new(big.Int).SetBytes(sig[:dsaByteLen])
    s := new(big.Int).SetBytes(sig[dsaByteLen:])

    hashed, err := this.dataHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = dsa.Verify(this.publicKey, hashed, r, s)

    return this
}

// ===============

// 私钥签名
func (this DSA) SignWithSeparator(separator ...string) DSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/dsa: privateKey empty.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.data)
    if err != nil {
        return this.AppendError(err)
    }

    r, s, err := dsa.Sign(rand.Reader, this.privateKey, hashed)
    if err != nil {
        return this.AppendError(err)
    }

    rt, err := r.MarshalText()
    if err != nil {
        return this.AppendError(err)
    }

    st, err := s.MarshalText()
    if err != nil {
        return this.AppendError(err)
    }

    sep := "+"
    if len(separator) > 0 {
        sep = separator[0]
    }

    signStr := string(rt) + sep + string(st)

    this.parsedData = []byte(signStr)

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this DSA) VerifyWithSeparator(data []byte, separator ...string) DSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/dsa: publicKey empty.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    sep := "+"
    if len(separator) > 0 {
        sep = separator[0]
    }

    split := strings.Split(string(this.data), sep)
    if len(split) != 2 {
        err := errors.New("go-cryptobin/dsa: sign data is error.")
        return this.AppendError(err)
    }

    rr := new(big.Int)
    ss := new(big.Int)

    err = rr.UnmarshalText([]byte(split[0]))
    if err != nil {
        return this.AppendError(err)
    }

    err = ss.UnmarshalText([]byte(split[1]))
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = dsa.Verify(this.publicKey, hashed, rr, ss)

    return this
}

// ===============

// 签名后数据
func (this DSA) dataHash(data []byte) ([]byte, error) {
    if this.signHash == nil {
        return nil, errors.New("go-cryptobin/dsa: hash func empty.")
    }

    h := this.signHash()
    h.Write(data)

    return h.Sum(nil), nil
}
