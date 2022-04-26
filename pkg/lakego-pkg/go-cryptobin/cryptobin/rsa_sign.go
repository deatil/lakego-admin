package cryptobin

import (
    "crypto"
    "crypto/rsa"
    "crypto/rand"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
)

// 私钥签名
func (this Rsa) Sign() Rsa {
    hasher := this.HashType(this.signHash)
    hashData := this.DataHash(this.signHash, this.data)

    this.paredData, this.Error = rsa.SignPKCS1v15(rand.Reader, this.privateKey, hasher, hashData)

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this Rsa) Very(data []byte) Rsa {
    hasher := this.HashType(this.signHash)
    hashData := this.DataHash(this.signHash, data)

    err := rsa.VerifyPKCS1v15(this.publicKey, hasher, hashData, this.data)
    if err != nil {
        this.veryed = false
        this.Error = err

        return this
    }

    this.veryed = true

    return this
}

// 签名
func (this Rsa) HashType(signHash string) crypto.Hash {
    hashs := map[string]crypto.Hash{
        "MD5": crypto.MD5,
        "SHA1": crypto.SHA1,
        "SHA224": crypto.SHA224,
        "SHA256": crypto.SHA256,
        "SHA384": crypto.SHA384,
        "SHA512": crypto.SHA512,
    }

    hash, ok := hashs[signHash]
    if ok {
        return hash
    }

    return crypto.SHA512
}

// 签名后数据
func (this Rsa) DataHash(signHash string, data []byte) []byte {
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
