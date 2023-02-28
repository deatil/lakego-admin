package ecdsa

import (
    "errors"
    "strings"
    "math/big"
    "crypto/rand"
    "crypto/ecdsa"
    "encoding/asn1"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 私钥签名
func (this Ecdsa) Sign(separator ...string) Ecdsa {
    if this.privateKey == nil {
        err := errors.New("Ecdsa: [Sign()] privateKey error.")
        return this.AppendError(err)
    }

    hashData := this.DataHash(this.signHash, this.data)

    r, s, err := ecdsa.Sign(rand.Reader, this.privateKey, hashData)
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

    this.paredData = []byte(signStr)

    return this
}

// 公钥验证
func (this Ecdsa) Verify(data []byte, separator ...string) Ecdsa {
    if this.publicKey == nil {
        err := errors.New("Ecdsa: [Verify()] publicKey error.")
        return this.AppendError(err)
    }

    hashData := this.DataHash(this.signHash, data)

    sep := "+"
    if len(separator) > 0 {
        sep = separator[0]
    }

    split := strings.Split(string(this.data), sep)
    if len(split) != 2 {
        err := errors.New("Ecdsa: [Verify()] sign data is error.")
        return this.AppendError(err)
    }

    rStr := split[0]
    sStr := split[1]
    rr := new(big.Int)
    ss := new(big.Int)

    err := rr.UnmarshalText([]byte(rStr))
    if err != nil {
        return this.AppendError(err)
    }

    err = ss.UnmarshalText([]byte(sStr))
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = ecdsa.Verify(this.publicKey, hashData, rr, ss)

    return this
}

// ===============

type ecdsaSignature struct {
    R, S *big.Int
}

// 私钥签名
func (this Ecdsa) SignAsn1() Ecdsa {
    if this.privateKey == nil {
        err := errors.New("Ecdsa: [SignAsn1()] privateKey error.")
        return this.AppendError(err)
    }

    hashData := this.DataHash(this.signHash, this.data)

    r, s, err := ecdsa.Sign(rand.Reader, this.privateKey, hashData)
    if err != nil {
        return this.AppendError(err)
    }

    paredData, err := asn1.Marshal(ecdsaSignature{r, s})

    this.paredData = paredData
    
    return this.AppendError(err)
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this Ecdsa) VerifyAsn1(data []byte) Ecdsa {
    if this.publicKey == nil {
        err := errors.New("Ecdsa: [VerifyAsn1()] publicKey error.")
        return this.AppendError(err)
    }

    var ecdsaSign ecdsaSignature
    _, err := asn1.Unmarshal(this.data, &ecdsaSign)
    if err != nil {
        return this.AppendError(err)
    }

    r := ecdsaSign.R
    s := ecdsaSign.S

    hashData := this.DataHash(this.signHash, data)

    this.verify = ecdsa.Verify(this.publicKey, hashData, r, s)

    return this
}

// ===============

// 私钥签名
func (this Ecdsa) SignHex() Ecdsa {
    if this.privateKey == nil {
        err := errors.New("Ecdsa: [SignHex()] privateKey error.")
        return this.AppendError(err)
    }

    hashData := this.DataHash(this.signHash, this.data)

    r, s, err := ecdsa.Sign(rand.Reader, this.privateKey, hashData)
    if err != nil {
        return this.AppendError(err)
    }

    encoding := cryptobin_tool.NewEncoding()

    rHex := encoding.HexEncode(r.Bytes())
    sHex := encoding.HexEncode(s.Bytes())

    sign := encoding.HexPadding(rHex, 64) + encoding.HexPadding(sHex, 64)

    paredData, err := encoding.HexDecode(sign)

    this.paredData = paredData
    
    return this.AppendError(err)
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this Ecdsa) VerifyHex(data []byte) Ecdsa {
    if this.publicKey == nil {
        err := errors.New("Ecdsa: [VerifyHex()] publicKey error.")
        return this.AppendError(err)
    }

    signData := cryptobin_tool.NewEncoding().HexEncode(this.data)

    r, _ := new(big.Int).SetString(signData[:64], 16)
    s, _ := new(big.Int).SetString(signData[64:], 16)

    hashData := this.DataHash(this.signHash, data)

    this.verify = ecdsa.Verify(this.publicKey, hashData, r, s)

    return this
}

// ===============

// 签名后数据
func (this Ecdsa) DataHash(signHash string, data []byte) []byte {
    return cryptobin_tool.NewHash().DataHash(signHash, data)
}
