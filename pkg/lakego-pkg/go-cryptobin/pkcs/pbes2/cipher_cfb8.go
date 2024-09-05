package pbes2

import (
    "io"
    "errors"
    "crypto/cipher"
    "encoding/asn1"

    cryptobin_mode "github.com/deatil/go-cryptobin/mode"
)

// CFB8 模式加密参数
type cfb8Params []byte

// CFB8 模式加密
type CipherCFB8 struct {
    cipherFunc   func(key []byte) (cipher.Block, error)
    keySize      int
    blockSize    int
    identifier   asn1.ObjectIdentifier
    hasKeyLength bool
    needBmpPass  bool
}

// 值大小
func (this CipherCFB8) KeySize() int {
    return this.keySize
}

// oid
func (this CipherCFB8) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 是否有 KeyLength
func (this CipherCFB8) HasKeyLength() bool {
    return this.hasKeyLength
}

// 密码是否需要 Bmp 处理
func (this CipherCFB8) NeedBmpPassword() bool {
    return this.needBmpPass
}

// 加密
func (this CipherCFB8) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to create cipher: " + err.Error())
    }

    // 随机生成 iv
    iv := make(cfb8Params, this.blockSize)
    if _, err := io.ReadFull(rand, iv); err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to generate IV: " + err.Error())
    }

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    enc := cryptobin_mode.NewCFB8Encrypter(block, iv)
    enc.XORKeyStream(encrypted, plaintext)

    // 编码 iv
    paramBytes, err := asn1.Marshal(iv)
    if err != nil {
        return nil, nil, err
    }

    return encrypted, paramBytes, nil
}

// 解密
func (this CipherCFB8) Decrypt(key, params, ciphertext []byte) ([]byte, error) {
    // 解析出 iv
    var iv cfb8Params
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

    mode := cryptobin_mode.NewCFB8Decrypter(block, iv)
    mode.XORKeyStream(plaintext, ciphertext)

    return plaintext, nil
}

// 设置 keySize
func (this CipherCFB8) WithKeySize(keySize int) CipherCFB8 {
    this.keySize = keySize

    return this
}

func (this CipherCFB8) WithHasKeyLength(hasKeyLength bool) CipherCFB8 {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this CipherCFB8) WithNeedBmpPassword(needBmpPass bool) CipherCFB8 {
    this.needBmpPass = needBmpPass

    return this
}
