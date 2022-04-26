package cryptobin

import (
    "strings"
    "math/big"
    "crypto/md5"
    "crypto/rand"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/ecdsa"
)

// 私钥签名
func (this Ecdsa) Sign(separator ...string) Ecdsa {
    hashData := this.DataHash(this.signHash, this.data)

    r, s, err := ecdsa.Sign(rand.Reader, this.privateKey, hashData)
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
func (this Ecdsa) Very(data []byte, separator ...string) Ecdsa {
    hashData := this.DataHash(this.signHash, data)

    sep := "+"
    if len(separator) > 0 {
        sep = separator[0]
    }

    split := strings.Split(string(this.data), sep)
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

    this.veryed = ecdsa.Verify(this.publicKey, hashData, rr, ss)

    return this
}

// 签名后数据
func (this Ecdsa) DataHash(signHash string, data []byte) []byte {
    switch signHash {
        case "MD5":
            sum := md5.Sum(data)
            return sum[:]
        case "SHA1":
            sum := sha1.Sum(data)
            return sum[:]
        case "SHA224":
            sum := sha256.Sum224(data)
            return sum[:]
        case "SHA256":
            sum := sha256.Sum256(data)
            return sum[:]
        case "SHA384":
            sum := sha512.Sum384(data)
            return sum[:]
        case "SHA512":
            sum := sha512.Sum512(data)
            return sum[:]
    }

    return data
}
