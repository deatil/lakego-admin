package ecdsa

import (
    "errors"
    "strings"
    "math/big"
    "crypto/rand"
    "crypto/ecdsa"

    "github.com/deatil/go-cryptobin/tool"
)

// 私钥签名
func (this ECDSA) Sign(separator ...string) ECDSA {
    if this.privateKey == nil {
        err := errors.New("ecdsa: privateKey error.")
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

    this.parsedData = []byte(signStr)

    return this
}

// 公钥验证
func (this ECDSA) Verify(data []byte, separator ...string) ECDSA {
    if this.publicKey == nil {
        err := errors.New("ecdsa: publicKey error.")
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
        err := errors.New("ecdsa: sign data is error.")
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

// 私钥签名
func (this ECDSA) SignASN1() ECDSA {
    if this.privateKey == nil {
        err := errors.New("ecdsa: privateKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.DataHash(this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    parsedData, err := ecdsa.SignASN1(rand.Reader, this.privateKey, hashed)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this.AppendError(err)
}

// 公钥验证, 官方默认
// 使用原始数据[data]对比签名后数据
func (this ECDSA) VerifyASN1(data []byte) ECDSA {
    if this.publicKey == nil {
        err := errors.New("ecdsa: publicKey error.")
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

// 私钥签名
func (this ECDSA) SignBytes() ECDSA {
    if this.privateKey == nil {
        err := errors.New("ecdsa: privateKey error.")
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

    encoding := tool.NewEncoding()

    rHex := encoding.HexEncode(r.Bytes())
    sHex := encoding.HexEncode(s.Bytes())

    sign := encoding.HexPadding(rHex, 64) + encoding.HexPadding(sHex, 64)

    parsedData, err := encoding.HexDecode(sign)

    this.parsedData = parsedData

    return this.AppendError(err)
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this ECDSA) VerifyBytes(data []byte) ECDSA {
    if this.publicKey == nil {
        err := errors.New("ecdsa: publicKey error.")
        return this.AppendError(err)
    }

    signData := tool.NewEncoding().HexEncode(this.data)

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
func (this ECDSA) DataHash(fn HashFunc, data []byte) ([]byte, error) {
    h := fn()
    h.Write(data)

    return h.Sum(nil), nil
}
