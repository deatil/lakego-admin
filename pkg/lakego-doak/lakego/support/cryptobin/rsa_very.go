package cryptobin

import (
    "crypto"
    "crypto/md5"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
)

// 签名
func (this *Rsa) GetCryptoHash() crypto.Hash {
    hashs := map[string]crypto.Hash{
        "MD5": crypto.MD5,
        "SHA1": crypto.SHA1,
        "SHA224": crypto.SHA224,
        "SHA256": crypto.SHA256,
        "SHA384": crypto.SHA384,
        "SHA512": crypto.SHA512,
    }

    hash, ok := hashs[this.hash]
    if ok {
        return hash
    }

    return crypto.SHA512
}

// 签名后数据
func (this *Rsa) GetCryptoHashInfo(data []byte) []byte {
    switch this.hash {
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

    return nil
}

// 私钥签名
func (this *Rsa) Sign(data []byte, keyBytes []byte, password ...string) ([]byte, error) {
    hash := this.GetCryptoHash()
    hashed := this.GetCryptoHashInfo(data)

    var priv *rsa.PrivateKey
    var err error

    if len(password) > 0 {
        priv, err = this.ParseRSAPrivateKeyFromPEMWithPassword(keyBytes, password[0])
    } else {
        priv, err = this.ParseRSAPrivateKeyFromPEM(keyBytes)
    }

    signature, err := rsa.SignPKCS1v15(rand.Reader, priv, hash, hashed)
    if err != nil {
        return nil, err
    }

    return signature, nil
}

// 公钥验证
func (this *Rsa) Very(data, signData, keyBytes []byte) (bool, error) {
    pubKey, err := this.ParseRSAPublicKeyFromPEM(keyBytes)
    if err != nil {
        return false, err
    }

    hash := this.GetCryptoHash()
    hashed := this.GetCryptoHashInfo(data)

    err = rsa.VerifyPKCS1v15(pubKey, hash, hashed, signData)
    if err != nil {
        return false, err
    }

    return true, nil
}
