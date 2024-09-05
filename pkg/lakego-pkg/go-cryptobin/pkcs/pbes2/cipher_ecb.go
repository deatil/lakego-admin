package pbes2

import (
    "io"
    "errors"
    "crypto/cipher"
    "encoding/asn1"

    cryptobin_mode "github.com/deatil/go-cryptobin/mode"
)

// ecb 模式加密
type CipherECB struct {
    cipherFunc   func(key []byte) (cipher.Block, error)
    keySize      int
    blockSize    int
    identifier   asn1.ObjectIdentifier
    hasKeyLength bool
    needBmpPass  bool
}

// 值大小
func (this CipherECB) KeySize() int {
    return this.keySize
}

// oid
func (this CipherECB) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 是否有 KeyLength
func (this CipherECB) HasKeyLength() bool {
    return this.hasKeyLength
}

// 密码是否需要 Bmp 处理
func (this CipherECB) NeedBmpPassword() bool {
    return this.needBmpPass
}

// 加密
func (this CipherECB) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to create cipher: " + err.Error())
    }

    // 加密数据补码
    plaintext = pkcs7Padding(plaintext, this.blockSize)

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    mode := cryptobin_mode.NewECBEncrypter(block)
    mode.CryptBlocks(encrypted, plaintext)

    // 返回数据
    paramBytes := asn1.NullBytes

    return encrypted, paramBytes, nil
}

// 解密
func (this CipherECB) Decrypt(key, params, ciphertext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()

    if len(ciphertext)%blockSize != 0 {
        return nil, errors.New("pkcs/cipher: encrypted PEM data is not a multiple of the block size")
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cryptobin_mode.NewECBDecrypter(block)
    mode.CryptBlocks(plaintext, ciphertext)

    // 判断数据是否为填充数据
    dlen := len(plaintext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("pkcs/cipher: invalid padding")
    }

    // 解析加密数据
    pt, err := pkcs7UnPadding(plaintext)
    if err != nil {
        return plaintext, nil
    }

    return pt, nil
}

// 设置 keySize
func (this CipherECB) WithKeySize(keySize int) CipherECB {
    this.keySize = keySize

    return this
}

func (this CipherECB) WithHasKeyLength(hasKeyLength bool) CipherECB {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this CipherECB) WithNeedBmpPassword(needBmpPass bool) CipherECB {
    this.needBmpPass = needBmpPass

    return this
}
