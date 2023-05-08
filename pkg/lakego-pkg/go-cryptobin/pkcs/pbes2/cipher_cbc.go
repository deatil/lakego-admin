package pbes2

import (
    "errors"
    "crypto/rand"
    "crypto/cipher"
    "encoding/asn1"
)

// cbc 模式加密参数
type cbcParams []byte

// cbc 模式加密
type CipherCBC struct {
    cipherFunc func(key []byte) (cipher.Block, error)
    keySize    int
    blockSize  int
    identifier asn1.ObjectIdentifier
}

// 值大小
func (this CipherCBC) KeySize() int {
    return this.keySize
}

// oid
func (this CipherCBC) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 加密
func (this CipherCBC) Encrypt(key, plaintext []byte) ([]byte, []byte, error) {
    // 加密数据补码
    plaintext = pkcs7Padding(plaintext, this.blockSize)

    // 随机生成 iv
    iv := make(cbcParams, this.blockSize)
    if _, err := rand.Read(iv); err != nil {
        return nil, nil, errors.New("pkcs/cipher:" + err.Error() + " failed to generate IV")
    }

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("pkcs/cipher:" + err.Error() + " failed to create cipher")
    }

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    enc := cipher.NewCBCEncrypter(block, iv)
    enc.CryptBlocks(encrypted, plaintext)

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
        return nil, errors.New("pkcs/cipher: invalid iv parameters")
    }

    plaintext := make([]byte, len(ciphertext))

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    // 判断数据是否为填充数据
    blockSize := block.BlockSize()
    dlen := len(ciphertext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("pkcs/cipher: invalid padding")
    }

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(plaintext, ciphertext)

    // 解析加密数据
    plaintext = pkcs7UnPadding(plaintext)

    return plaintext, nil
}
