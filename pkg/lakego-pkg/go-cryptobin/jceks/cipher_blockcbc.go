package jceks

import (
    "fmt"
    "hash"
    "errors"
    "crypto/cipher"
    "encoding/asn1"
)

// pbe 数据
type pbeParam struct {
    Salt           []byte
    IterationCount int
}

// cbc 模式加密
type CipherBlockCBC struct {
    // 对称加密
    cipherFunc     func(key []byte) (cipher.Block, error)
    // hash 摘要
    hashFunc       func() hash.Hash
    // 密钥生成
    derivedKeyFunc func(password string, salt string, iter int, keyLen int, ivLen int, h func() hash.Hash) ([]byte, []byte)
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
func (this CipherBlockCBC) KeySize() int {
    return this.keySize
}

// oid
func (this CipherBlockCBC) OID() asn1.ObjectIdentifier {
    return this.oid
}

// 加密
func (this CipherBlockCBC) Encrypt(password, plaintext []byte) ([]byte, []byte, error) {
    // 加密数据补码
    plaintext = pkcs7Padding(plaintext, this.blockSize)

    salt, err := genRandom(this.saltSize)
    if err != nil {
        return nil, nil, errors.New(err.Error() + " failed to generate salt")
    }

    key, iv := this.derivedKeyFunc(string(password), string(salt), this.iterationCount, this.keySize, this.blockSize, this.hashFunc)
    if key == nil && iv == nil {
        return nil, nil, fmt.Errorf("unexpected salt length: %d", len(salt))
    }

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("pkcs8:" + err.Error() + " failed to create cipher")
    }

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    enc := cipher.NewCBCEncrypter(block, iv)
    enc.CryptBlocks(encrypted, plaintext)

    // 返回数据
    paramBytes, err := asn1.Marshal(pbeParam{
        Salt:           salt,
        IterationCount: this.iterationCount,
    })
    if err != nil {
        return nil, nil, err
    }

    return encrypted, paramBytes, nil
}

// 解密
func (this CipherBlockCBC) Decrypt(password, params, ciphertext []byte) ([]byte, error) {
    var param pbeParam
    if _, err := asn1.Unmarshal(params, &param); err != nil {
        return nil, errors.New("pkcs8: invalid PBES2 parameters")
    }

    key, iv := this.derivedKeyFunc(string(password), string(param.Salt), param.IterationCount, this.keySize, this.blockSize, this.hashFunc)
    if key == nil && iv == nil {
        return nil, fmt.Errorf("unexpected salt length: %d", len(param.Salt))
    }

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    // 判断数据是否为填充数据
    blockSize := block.BlockSize()
    dlen := len(ciphertext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("pkcs8: invalid padding")
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(plaintext, ciphertext)

    // 解析加密数据
    plaintext = pkcs7UnPadding(plaintext)

    return plaintext, nil
}

// 设置 saltSize
func (this CipherBlockCBC) WithSaltSize(saltSize int) CipherBlockCBC {
    this.saltSize = saltSize

    return this
}
