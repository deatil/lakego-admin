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
        err := errors.New("Ecdsa: privateKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.DataHash(this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    r, s, err := ecdsa.Sign(rand.Reader, this.privateKey, hashed)
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
        err := errors.New("Ecdsa: publicKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.DataHash(this.signHash, data)
    if err != nil {
        return this.AppendError(err)
    }

    sep := "+"
    if len(separator) > 0 {
        sep = separator[0]
    }

    split := strings.Split(string(this.data), sep)
    if len(split) != 2 {
        err := errors.New("Ecdsa: sign data is error.")
        return this.AppendError(err)
    }

    rStr := split[0]
    sStr := split[1]
    rr := new(big.Int)
    ss := new(big.Int)

    err = rr.UnmarshalText([]byte(rStr))
    if err != nil {
        return this.AppendError(err)
    }

    err = ss.UnmarshalText([]byte(sStr))
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = ecdsa.Verify(this.publicKey, hashed, rr, ss)

    return this
}

// ===============

// 私钥签名, 官方默认
func (this Ecdsa) SignASN1() Ecdsa {
    if this.privateKey == nil {
        err := errors.New("Ecdsa: privateKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.DataHash(this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    paredData, err := ecdsa.SignASN1(rand.Reader, this.privateKey, hashed)
    if err != nil {
        return this.AppendError(err)
    }

    this.paredData = paredData

    return this.AppendError(err)
}

// 公钥验证, 官方默认
// 使用原始数据[data]对比签名后数据
func (this Ecdsa) VerifyASN1(data []byte) Ecdsa {
    if this.publicKey == nil {
        err := errors.New("Ecdsa: publicKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.DataHash(this.signHash, data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = ecdsa.VerifyASN1(this.publicKey, hashed, this.data)

    return this
}

// ===============

type ecdsaSignature struct {
    R, S *big.Int
}

// 私钥签名
func (this Ecdsa) SignAsn1() Ecdsa {
    if this.privateKey == nil {
        err := errors.New("Ecdsa: privateKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.DataHash(this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    r, s, err := ecdsa.Sign(rand.Reader, this.privateKey, hashed)
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
        err := errors.New("Ecdsa: publicKey error.")
        return this.AppendError(err)
    }

    var ecdsaSign ecdsaSignature
    _, err := asn1.Unmarshal(this.data, &ecdsaSign)
    if err != nil {
        return this.AppendError(err)
    }

    r := ecdsaSign.R
    s := ecdsaSign.S

    hashed, err := this.DataHash(this.signHash, data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = ecdsa.Verify(this.publicKey, hashed, r, s)

    return this
}

// ===============

// 私钥签名
func (this Ecdsa) SignHex() Ecdsa {
    if this.privateKey == nil {
        err := errors.New("Ecdsa: privateKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.DataHash(this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    r, s, err := ecdsa.Sign(rand.Reader, this.privateKey, hashed)
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
        err := errors.New("Ecdsa: publicKey error.")
        return this.AppendError(err)
    }

    signData := cryptobin_tool.NewEncoding().HexEncode(this.data)

    r, _ := new(big.Int).SetString(signData[:64], 16)
    s, _ := new(big.Int).SetString(signData[64:], 16)

    hashed, err := this.DataHash(this.signHash, data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = ecdsa.Verify(this.publicKey, hashed, r, s)

    return this
}

// ===============

// 签名后数据
func (this Ecdsa) DataHash(signHash string, data []byte) ([]byte, error) {
    return cryptobin_tool.HashSum(signHash, data)
}
