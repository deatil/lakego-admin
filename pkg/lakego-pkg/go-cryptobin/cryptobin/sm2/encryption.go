package sm2

import (
    "io"
    "errors"
    "crypto/rand"

    "github.com/tjfoc/gmsm/sm2"
)

// 公钥加密
func (this SM2) Encrypt() SM2 {
    if this.publicKey == nil {
        err := errors.New("SM2: [Encrypt()] publicKey error.")
        return this.AppendError(err)
    }

    paredData, err := this.EncryptAsn1(this.publicKey, this.data, this.mode, rand.Reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.paredData = paredData

    return this
}

// 私钥解密
func (this SM2) Decrypt() SM2 {
    if this.privateKey == nil {
        err := errors.New("SM2: [Decrypt()] privateKey error.")
        return this.AppendError(err)
    }

    paredData, err := this.DecryptAsn1(this.privateKey, this.data, this.mode)
    if err != nil {
        return this.AppendError(err)
    }

    this.paredData = paredData

    return this
}

// sm2 加密，返回 asn.1 编码格式的密文内容
func (this SM2) EncryptAsn1(pub *sm2.PublicKey, data []byte, mode int, rand io.Reader) ([]byte, error) {
    cipher, err := sm2.Encrypt(pub, data, rand, mode)
    if err != nil {
        return nil, err
    }

    return sm2.CipherMarshal(cipher)
}

// sm2 解密，解析 asn.1 编码格式的密文内容
func (this SM2) DecryptAsn1(pub *sm2.PrivateKey, data []byte, mode int) ([]byte, error) {
    cipher, err := sm2.CipherUnmarshal(data)
    if err != nil {
        return nil, err
    }

    return sm2.Decrypt(pub, cipher, mode)
}
