package crypto

import (
    cryptobin_sm2 "github.com/deatil/go-cryptobin/cryptobin/sm2"
)

// SM2 公钥加密
func (this Cryptobin) SM2Encrypt() Cryptobin {
    sm2 := cryptobin_sm2.NewSM2().
        FromPublicKey(this.key).
        FromBytes(this.data).
        Encrypt()
    if len(sm2.Errors) > 0 {
        return this.AppendError(sm2.Errors...)
    }

    this.parsedData = sm2.ToBytes()

    return this
}

// SM2 私钥解密
func (this Cryptobin) SM2Decrypt(password ...string) Cryptobin {
    sm2 := cryptobin_sm2.NewSM2()

    if len(password) > 0 {
        sm2 = sm2.FromPrivateKeyWithPassword(this.key, password[0])
    } else {
        sm2 = sm2.FromPrivateKey(this.key)
    }

    sm2 = sm2.
        FromBytes(this.data).
        Decrypt()
    if len(sm2.Errors) > 0 {
        return this.AppendError(sm2.Errors...)
    }

    this.parsedData = sm2.ToBytes()

    return this
}
