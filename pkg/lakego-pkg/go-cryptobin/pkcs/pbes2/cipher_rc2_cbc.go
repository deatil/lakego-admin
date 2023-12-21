package pbes2

import (
    "io"
    "errors"
    "crypto/cipher"
    "encoding/asn1"
)

// cbc 模式加密参数
type rc2CBCParams struct {
    RC2Version int
    IV         []byte
}

// cbc 模式加密
type CipherRC2CBC struct {
    cipherFunc   func(key []byte) (cipher.Block, error)
    rc2Version   int
    keySize      int
    blockSize    int
    identifier   asn1.ObjectIdentifier
    hasKeyLength bool
    needPassBmp  bool
}

// 值大小
func (this CipherRC2CBC) KeySize() int {
    return this.keySize
}

// oid
func (this CipherRC2CBC) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 是否有 KeyLength
func (this CipherRC2CBC) HasKeyLength() bool {
    return this.hasKeyLength
}

// 密码是否需要 Bmp 处理
func (this CipherRC2CBC) NeedPasswordBmpString() bool {
    return this.needPassBmp
}

// 加密
func (this CipherRC2CBC) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, []byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to create cipher: " + err.Error())
    }

    // 随机生成 iv
    iv := make([]byte, this.blockSize)
    if _, err := io.ReadFull(rand, iv); err != nil {
        return nil, nil, errors.New("pkcs/cipher: failed to generate IV: " + err.Error())
    }

    // 加密数据补码
    plaintext = pkcs7Padding(plaintext, this.blockSize)

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    enc := cipher.NewCBCEncrypter(block, iv)
    enc.CryptBlocks(encrypted, plaintext)

    // 需要编码的参数
    paramSeq := rc2CBCParams{
        RC2Version: this.rc2Version,
        IV:         iv,
    }

    // 编码 iv
    paramBytes, err := asn1.Marshal(paramSeq)
    if err != nil {
        return nil, nil, err
    }

    return encrypted, paramBytes, nil
}

// 解密
func (this CipherRC2CBC) Decrypt(key, params, ciphertext []byte) ([]byte, error) {
    // 解析参数
    var param rc2CBCParams
    if _, err := asn1.Unmarshal(params, &param); err != nil {
        return nil, errors.New("pkcs/cipher: invalid parameters")
    }

    if param.RC2Version > 1024 || param.RC2Version < 1 {
        return nil, errors.New("pkcs/cipher: invalid RC2Version parameters")
    }

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()

    if len(param.IV) != blockSize {
        return nil, errors.New("pkcs/cipher: incorrect IV size")
    }

    if len(ciphertext)%blockSize != 0 {
        return nil, errors.New("pkcs/cipher: encrypted PEM data is not a multiple of the block size")
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCBCDecrypter(block, param.IV)
    mode.CryptBlocks(plaintext, ciphertext)

    // 判断数据是否为填充数据
    dlen := len(plaintext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("pkcs/cipher: invalid padding")
    }

    // 解析加密数据
    plaintext, err = pkcs7UnPadding(plaintext)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}

// 设置 RC2Version
func (this CipherRC2CBC) WithRC2Version(rc2Version int) CipherRC2CBC {
    this.rc2Version = rc2Version

    return this
}

// 设置 keySize
func (this CipherRC2CBC) WithKeySize(keySize int) CipherRC2CBC {
    this.keySize = keySize

    return this
}

func (this CipherRC2CBC) WithHasKeyLength(hasKeyLength bool) CipherRC2CBC {
    this.hasKeyLength = hasKeyLength

    return this
}

func (this CipherRC2CBC) WithNeedPasswordBmpString(needPassBmp bool) CipherRC2CBC {
    this.needPassBmp = needPassBmp

    return this
}
