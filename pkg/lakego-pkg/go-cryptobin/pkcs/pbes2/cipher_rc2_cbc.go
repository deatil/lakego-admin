package pbes2

import (
    "errors"
    "crypto/rand"
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
    cipherFunc func(key []byte) (cipher.Block, error)
    rc2Version int
    keySize    int
    blockSize  int
    identifier asn1.ObjectIdentifier
}

// 值大小
func (this CipherRC2CBC) KeySize() int {
    return this.keySize
}

// oid
func (this CipherRC2CBC) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 加密
func (this CipherRC2CBC) Encrypt(key, plaintext []byte) ([]byte, []byte, error) {
    // 随机生成 iv
    iv := make(cbcParams, this.blockSize)
    if _, err := rand.Read(iv); err != nil {
        return nil, nil, errors.New("pkcs/cipher:" + err.Error() + " failed to generate IV")
    }

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("pkcs/cipher:" + err.Error() + " failed to create cipher")
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

    plaintext := make([]byte, len(ciphertext))

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    if param.RC2Version > 1024 || param.RC2Version < 1 {
        return nil, errors.New("pkcs/cipher: invalid RC2Version parameters")
    }

    // 判断数据是否为填充数据
    blockSize := block.BlockSize()
    dlen := len(ciphertext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("pkcs/cipher: invalid padding")
    }

    mode := cipher.NewCBCDecrypter(block, param.IV)
    mode.CryptBlocks(plaintext, ciphertext)

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
