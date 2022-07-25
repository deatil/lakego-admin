package cryptobin

import (
    "errors"
    "strings"
    "math/big"
    "crypto/dsa"
    "crypto/rand"
    "encoding/asn1"
)

// 私钥签名
func (this DSA) Sign(separator ...string) DSA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    hashData := this.DataHash(this.signHash, this.data)

    r, s, err := dsa.Sign(rand.Reader, this.privateKey, hashData)
    if err != nil {
        this.Error = err
        return this
    }

    rt, err := r.MarshalText()
    if err != nil {
        this.Error = err
        return this
    }

    st, err := s.MarshalText()
    if err != nil {
        this.Error = err
        return this
    }

    sep := "+"
    if len(separator) > 0 {
        sep = separator[0]
    }

    signStr := string(rt) + sep + string(st)

    this.paredData = []byte(signStr)

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this DSA) Very(data []byte, separator ...string) DSA {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")
        return this
    }

    hashData := this.DataHash(this.signHash, data)

    sep := "+"
    if len(separator) > 0 {
        sep = separator[0]
    }

    split := strings.Split(string(this.data), sep)
    if len(split) != 2 {
        this.Error = errors.New("sign data is error.")
        return this
    }

    rStr := split[0]
    sStr := split[1]
    rr := new(big.Int)
    ss := new(big.Int)

    err := rr.UnmarshalText([]byte(rStr))
    if err != nil {
        this.Error = err
        return this
    }

    err = ss.UnmarshalText([]byte(sStr))
    if err != nil {
        this.Error = err
        return this
    }

    this.veryed = dsa.Verify(this.publicKey, hashData, rr, ss)

    return this
}

// ===============

type DSASignature struct {
    R, S *big.Int
}

// 私钥签名
func (this DSA) SignAsn1() DSA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    hashData := this.DataHash(this.signHash, this.data)

    r, s, err := dsa.Sign(rand.Reader, this.privateKey, hashData)
    if err != nil {
        this.Error = err
        return this
    }

    this.paredData, this.Error = asn1.Marshal(DSASignature{r, s})

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this DSA) VerifyAsn1(data []byte) DSA {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")
        return this
    }

    var dsaSign DSASignature
    _, err := asn1.Unmarshal(this.data, &dsaSign)
    if err != nil {
        this.Error = err

        return this
    }

    hashData := this.DataHash(this.signHash, data)

    r := dsaSign.R
    s := dsaSign.S

    this.veryed = dsa.Verify(this.publicKey, hashData, r, s)

    return this
}

// ===============

// 私钥签名
func (this DSA) SignHex() DSA {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")
        return this
    }

    hashData := this.DataHash(this.signHash, this.data)

    r, s, err := dsa.Sign(rand.Reader, this.privateKey, hashData)
    if err != nil {
        this.Error = err
        return this
    }

    encoding := NewEncoding()

    rHex := encoding.HexEncode(r.Bytes())
    sHex := encoding.HexEncode(s.Bytes())

    sign := encoding.HexPadding(rHex, 64) + encoding.HexPadding(sHex, 64)

    this.paredData, this.Error = encoding.HexDecode(sign)

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this DSA) VerifyHex(data []byte) DSA {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")
        return this
    }

    signData := NewEncoding().HexEncode(this.data)

    r, _ := new(big.Int).SetString(signData[:64], 16)
    s, _ := new(big.Int).SetString(signData[64:], 16)

    hashData := this.DataHash(this.signHash, data)

    this.veryed = dsa.Verify(this.publicKey, hashData, r, s)

    return this
}

// ===============

// 签名后数据
func (this DSA) DataHash(signHash string, data []byte) []byte {
    return NewHash().DataHash(signHash, data)
}
