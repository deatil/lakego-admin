package pbes2

import (
    "io"
    "errors"
    "crypto/cipher"
    "encoding/asn1"
)

// cbc 模式加密参数
type cbcParams []byte

// cbc 模式加密
type CipherCBC struct {
    cipherFunc   func(key []byte) (cipher.Block, error)
    keySize      int
    blockSize    int
    identifier   asn1.ObjectIdentifier
    hasKeyLength bool
    needBmpPass  bool
}

// 值大小
func (this CipherCBC) KeySize() int {
    return this.keySize
}

// oid
func (this CipherCBC) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 是否有 KeyLength
func (this CipherCBC) HasKeyLength() bool {
    return this.hasKeyLength
}

// 密码是否需要 Bmp 处理
func (this CipherCBC) NeedBmpPassword() bool {
    return this.needBmpPass
}

// 加密
func (this CipherCBC) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("go-cryptobin/pkcs: failed to create cipher: " + err.Error())
    }

    // 随机生成 iv
    iv := make(cbcParams, this.blockSize)
    if _, err := io.ReadFull(rand, iv); err != nil {
        return nil, nil, errors.New("go-cryptobin/pkcs: failed to generate IV: " + err.Error())
    }

    // 加密数据补码
    plaintext = pkcs7Padding(plaintext, this.blockSize)

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(encrypted, plaintext)

    // 编码 iv
    paramBytes, err := asn1.Marshal(iv)
    if err != nil {
        return nil, nil, err
    }

    return encrypted, paramBytes, nil
}

// 解密
func (this CipherCBC) Decrypt(key, params, ciphertext []byte) ([]byte, error) {
    // 解析出 iv
    var iv cbcParams
    if _, err := asn1.Unmarshal(params, &iv); err != nil {
        return nil, errors.New("go-cryptobin/pkcs: invalid iv parameters")
    }

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()

    if len(ciphertext)%blockSize != 0 {
        return nil, errors.New("go-cryptobin/pkcs: encrypted PEM data is not a multiple of the block size")
    }

    if len(iv) != blockSize {
        return nil, errors.New("go-cryptobin/pkcs: incorrect IV size")
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(plaintext, ciphertext)

    // 判断数据是否为填充数据
    dlen := len(plaintext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("go-cryptobin/pkcs: invalid padding")
    }

    // 解析加密数据
    pt, err := pkcs7UnPadding(plaintext)
    if err != nil {
        return plaintext, nil
    }

    return pt, nil
}

// 设置 keySize
func (this CipherCBC) WithKeySize(keySize int) CipherCBC {
    this.keySize = keySize

    return this
}

func (this CipherCBC) WithHasKeyLength(hasKeyLength bool) CipherCBC {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this CipherCBC) WithNeedBmpPassword(needBmpPass bool) CipherCBC {
    this.needBmpPass = needBmpPass

    return this
}
