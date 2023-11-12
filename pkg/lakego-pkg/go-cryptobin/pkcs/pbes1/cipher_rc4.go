package pbes1

import (
    "io"
    "hash"
    "errors"
    "crypto/rc4"
    "encoding/asn1"
)

// pbe 数据
type pbeRC4Params struct {
    Salt           []byte
    IterationCount int
}

// rc4 模式加密
type CipherRC4 struct {
    // hash 摘要
    hashFunc       func() hash.Hash
    // 密钥生成
    derivedKeyFunc DerivedKeyFunc
    // salt 长度
    saltSize       int
    // 与 key 长度相关
    keySize        int
    // 与 iv 长度相关
    blockSize      int
    // 迭代次数
    iterationCount int
    // oid
    oid            asn1.ObjectIdentifier
}

// 值大小
func (this CipherRC4) KeySize() int {
    return this.keySize
}

// oid
func (this CipherRC4) OID() asn1.ObjectIdentifier {
    return this.oid
}

// 加密
func (this CipherRC4) Encrypt(rand io.Reader, password, plaintext []byte) ([]byte, []byte, error) {
    salt := make([]byte, this.saltSize)
    if _, err := io.ReadFull(rand, salt); err != nil {
        return nil, nil, errors.New("pkcs1: failed to generate salt: " + err.Error())
    }

    key, _ := this.derivedKeyFunc(string(password), string(salt), this.iterationCount, this.keySize, this.blockSize, this.hashFunc)

    rc, err := rc4.NewCipher(key)
    if err != nil {
        return nil, nil, errors.New("pkcs/cipher:" + err.Error() + " failed to create cipher")
    }

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    rc.XORKeyStream(encrypted, plaintext)

    // 返回数据
    paramBytes, err := asn1.Marshal(pbeRC4Params{
        Salt:           salt,
        IterationCount: this.iterationCount,
    })
    if err != nil {
        return nil, nil, err
    }

    return encrypted, paramBytes, nil
}

// 解密
func (this CipherRC4) Decrypt(password, params, ciphertext []byte) ([]byte, error) {
    var param pbeRC4Params
    if _, err := asn1.Unmarshal(params, &param); err != nil {
        return nil, errors.New("pkcs/cipher: invalid PBE parameters")
    }

    key, _ := this.derivedKeyFunc(string(password), string(param.Salt), param.IterationCount, this.keySize, this.blockSize, this.hashFunc)

    rc, err := rc4.NewCipher(key)
    if err != nil {
        return nil, err
    }

    plaintext := make([]byte, len(ciphertext))

    rc.XORKeyStream(plaintext, ciphertext)

    return plaintext, nil
}

// 设置 saltSize
func (this CipherRC4) WithSaltSize(saltSize int) CipherRC4 {
    this.saltSize = saltSize

    return this
}

// 设置 derivedKeyFunc
func (this CipherRC4) WithDerivedKeyFunc(derivedKeyFunc DerivedKeyFunc) CipherRC4 {
    this.derivedKeyFunc = derivedKeyFunc

    return this
}
