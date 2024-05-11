package pbes2

import (
    "io"
    "errors"
    "crypto/cipher"
    "encoding/asn1"
)

// CFB 模式加密参数
type cfbParams []byte

// CFB 模式加密
type CipherCFB struct {
    cipherFunc   func(key []byte) (cipher.Block, error)
    keySize      int
    blockSize    int
    identifier   asn1.ObjectIdentifier
    hasKeyLength bool
    needBmpPass  bool
}

// 值大小
func (this CipherCFB) KeySize() int {
    return this.keySize
}

// oid
func (this CipherCFB) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 是否有 KeyLength
func (this CipherCFB) HasKeyLength() bool {
    return this.hasKeyLength
}

// 密码是否需要 Bmp 处理
func (this CipherCFB) NeedBmpPassword() bool {
    return this.needBmpPass
}

// 加密
func (this CipherCFB) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to create cipher: " + err.Error())
    }

    // 随机生成 iv
    iv := make(cfbParams, this.blockSize)
    if _, err := io.ReadFull(rand, iv); err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to generate IV: " + err.Error())
    }

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    enc := cipher.NewCFBEncrypter(block, iv)
    enc.XORKeyStream(encrypted, plaintext)

    // 编码 iv
    paramBytes, err := asn1.Marshal(iv)
    if err != nil {
        return nil, nil, err
    }

    return encrypted, paramBytes, nil
}

// 解密
func (this CipherCFB) Decrypt(key, params, ciphertext []byte) ([]byte, error) {
    // 解析出 iv
    var iv cfbParams
    if _, err := asn1.Unmarshal(params, &iv); err != nil {
        return nil, errors.New("pkcs/cipher: invalid iv parameters")
    }

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    if len(iv) != block.BlockSize() {
        return nil, errors.New("pkcs/cipher: incorrect IV size")
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCFBDecrypter(block, iv)
    mode.XORKeyStream(plaintext, ciphertext)

    return plaintext, nil
}

// 设置 keySize
func (this CipherCFB) WithKeySize(keySize int) CipherCFB {
    this.keySize = keySize

    return this
}

func (this CipherCFB) WithHasKeyLength(hasKeyLength bool) CipherCFB {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this CipherCFB) WithNeedBmpPassword(needBmpPass bool) CipherCFB {
    this.needBmpPass = needBmpPass

    return this
}
