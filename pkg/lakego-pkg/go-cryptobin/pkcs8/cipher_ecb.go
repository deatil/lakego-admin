package pkcs8

import (
    "errors"
    "crypto/cipher"
    "encoding/asn1"
)

// ecb 模式加密
type CipherECB struct {
    cipherFunc func(key []byte) (cipher.Block, error)
    keySize    int
    blockSize  int
    identifier asn1.ObjectIdentifier
}

// 值大小
func (this CipherECB) KeySize() int {
    return this.keySize
}

// oid
func (this CipherECB) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 加密
func (this CipherECB) Encrypt(key, plaintext []byte) ([]byte, []byte, error) {
    // 加密数据补码
    plaintext = pkcs7Padding(plaintext, this.blockSize)

    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("pkcs8:" + err.Error() + " failed to create cipher")
    }

    bs := block.BlockSize()

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))

    dst := encrypted
    for len(plaintext) > 0 {
        block.Encrypt(dst, plaintext[:bs])
        plaintext = plaintext[bs:]
        dst = dst[bs:]
    }

    // 返回数据
    paramBytes, err := asn1.Marshal([]byte(""))
    if err != nil {
        return nil, nil, err
    }

    return encrypted, paramBytes, nil
}

// 解密
func (this CipherECB) Decrypt(key, params, ciphertext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    bs := block.BlockSize()

    // 判断数据是否为填充数据
    dlen := len(ciphertext)
    if dlen == 0 || dlen%bs != 0 {
        return nil, errors.New("pkcs8: invalid padding")
    }

    plaintext := make([]byte, len(ciphertext))

    dstTmp := plaintext
    for len(ciphertext) > 0 {
        block.Decrypt(dstTmp, ciphertext[:bs])
        ciphertext = ciphertext[bs:]
        dstTmp = dstTmp[bs:]
    }

    // 解析加密数据
    plaintext = pkcs7UnPadding(plaintext)

    return plaintext, nil
}
