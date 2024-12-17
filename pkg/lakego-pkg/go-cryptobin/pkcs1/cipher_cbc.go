package pkcs1

import (
    "io"
    "errors"
    "crypto/cipher"
)

// CBC 模式加密
type CipherCBC struct {
    // 对称加密
    cipherFunc     func(key []byte) (cipher.Block, error)
    // 密钥生成
    derivedKeyFunc func(password []byte, salt []byte, keySize int) []byte
    // salt 长度
    saltSize       int
    // 与 key 长度相关
    keySize        int
    // 与 iv 长度相关
    blockSize      int
    // name
    name           string
}

// 块大小
func (this CipherCBC) BlockSize() int {
    return this.blockSize
}

// 名称
func (this CipherCBC) Name() string {
    return this.name
}

// 加密
func (this CipherCBC) Encrypt(rand io.Reader, password, plaintext []byte) ([]byte, []byte, error) {
    iv := make([]byte, this.blockSize)
    if _, err := io.ReadFull(rand, iv); err != nil {
        return nil, nil, errors.New("go-cryptobin/pkcs1: cannot generate IV: " + err.Error())
    }

    // The salt is the first 8 bytes of the initialization vector,
    // matching the key derivation in DecryptPEMBlock.
    salt := iv[:this.saltSize]
    key := this.derivedKeyFunc(password, salt, this.keySize)

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("go-cryptobin/pkcs1: failed to create cipher: " + err.Error())
    }

    // We could save this copy by encrypting all the whole blocks in
    // the data separately, but it doesn't seem worth the additional
    // code.

    // 加密数据补码
    // See RFC 1423, Section 1.1.
    plaintext = pkcs7Padding(plaintext, block.BlockSize())

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    enc := cipher.NewCBCEncrypter(block, iv)
    enc.CryptBlocks(encrypted, plaintext)

    return encrypted, iv, nil
}

// 解密
func (this CipherCBC) Decrypt(password, iv, ciphertext []byte) ([]byte, error) {
    if len(iv) < this.saltSize {
        return nil, errors.New("go-cryptobin/pkcs1: iv length is too short")
    }

    salt := iv[:this.saltSize]
    key := this.derivedKeyFunc(password, salt, this.keySize)

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()

    if len(ciphertext)%blockSize != 0 {
        return nil, errors.New("go-cryptobin/pkcs1: encrypted PEM data is not a multiple of the block size")
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(plaintext, ciphertext)

    // 判断数据是否为填充数据
    dlen := len(plaintext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("go-cryptobin/pkcs1: invalid padding")
    }

    // 解析加密数据
    pt, err := pkcs7UnPadding(plaintext)
    if err != nil {
        return plaintext, nil
    }

    return pt, nil
}
