package jceks

import (
    "fmt"
    "hash"
    "errors"
    "crypto/cipher"
    "encoding/asn1"
)

// pbe parameters
type pbeParam struct {
    Salt           []byte
    IterationCount int
}

// Cipher Block CBC mode
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

// Key Size
func (this CipherBlockCBC) KeySize() int {
    return this.keySize
}

// oid
func (this CipherBlockCBC) OID() asn1.ObjectIdentifier {
    return this.oid
}

// with saltSize
func (this CipherBlockCBC) WithSaltSize(saltSize int) CipherBlockCBC {
    this.saltSize = saltSize

    return this
}

// Encrypt data
func (this CipherBlockCBC) Encrypt(password, plaintext []byte) ([]byte, []byte, error) {
    encrypted, salt, iterationCount, err := this.encrypt(password, plaintext)
    if err != nil {
        return nil, nil, err
    }

    // Marshal pbe param
    paramBytes, err := asn1.Marshal(pbeParam{
        Salt:           salt,
        IterationCount: iterationCount,
    })
    if err != nil {
        return nil, nil, err
    }

    return encrypted, paramBytes, nil
}

// Decrypt data
func (this CipherBlockCBC) Decrypt(password, params, ciphertext []byte) ([]byte, error) {
    var param pbeParam
    if _, err := asn1.Unmarshal(params, &param); err != nil {
        return nil, errors.New("go-cryptobin/jceks: invalid PBE parameters")
    }

    return this.decrypt(password, param.Salt, param.IterationCount, ciphertext)
}

func (this CipherBlockCBC) encrypt(password, plaintext []byte) (encrypted, salt []byte, iterationCount int, err error) {
    // pkcs7 padding
    plaintext = pkcs7Padding(plaintext, this.blockSize)

    salt, err = genRandom(this.saltSize)
    if err != nil {
        err = errors.New("go-cryptobin/jceks: failed to generate salt")
        return
    }

    key, iv := this.derivedKeyFunc(string(password), string(salt), this.iterationCount, this.keySize, this.blockSize, this.hashFunc)
    if key == nil && iv == nil {
        err = fmt.Errorf("go-cryptobin/jceks: unexpected salt length: %d", len(salt))
        return
    }

    block, err := this.cipherFunc(key)
    if err != nil {
        err = fmt.Errorf("go-cryptobin/jceks: failed to create cipher: %s", err.Error())
        return
    }

    // 需要保存的加密数据
    encrypted = make([]byte, len(plaintext))

    enc := cipher.NewCBCEncrypter(block, iv)
    enc.CryptBlocks(encrypted, plaintext)

    iterationCount = this.iterationCount

    return
}

func (this CipherBlockCBC) decrypt(password, salt []byte, iterationCount int, ciphertext []byte) ([]byte, error) {
    key, iv := this.derivedKeyFunc(string(password), string(salt), iterationCount, this.keySize, this.blockSize, this.hashFunc)
    if key == nil && iv == nil {
        return nil, fmt.Errorf("go-cryptobin/jceks: unexpected salt length: %d", len(salt))
    }

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    // check ciphertext length
    blockSize := block.BlockSize()
    dlen := len(ciphertext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("go-cryptobin/jceks: invalid padding")
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(plaintext, ciphertext)

    // pkcs7 UnPadding
    plaintext, err = pkcs7UnPadding(plaintext)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}
