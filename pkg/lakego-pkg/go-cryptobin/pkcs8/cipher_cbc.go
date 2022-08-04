package pkcs8

import (
    "errors"
    "crypto/x509"
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
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, nil, errors.New("pkcs8:" + err.Error() + " failed to create cipher")
    }

    pad := this.blockSize - len(plaintext)%this.blockSize
    if pad == 0 {
        pad = this.blockSize
    }

    encrypted := make([]byte, len(plaintext), len(plaintext)+pad)

    copy(encrypted, plaintext)
    for i := 0; i < pad; i++ {
        encrypted = append(encrypted, byte(pad))
    }

    iv := make(cbcParams, this.blockSize)
    if _, err := rand.Read(iv); err != nil {
        return nil, nil, errors.New("pkcs8:" + err.Error() + " failed to generate IV")
    }

    enc := cipher.NewCBCEncrypter(block, iv)
    enc.CryptBlocks(encrypted, encrypted)

    // 编码 iv
    paramBytes, err := asn1.Marshal(iv)
    if err != nil {
        return nil, nil, err
    }

    return encrypted, paramBytes, nil
}

// 解密
func (this CipherCBC) Decrypt(key, params, ciphertext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    // 解析 iv
    var iv cbcParams
    if _, err := asn1.Unmarshal(params, &iv); err != nil {
        return nil, errors.New("pkcs8: invalid iv parameters")
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(plaintext, ciphertext)

    // 解析加密数据
    blockSize := block.BlockSize()
    dlen := len(plaintext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("pkcs8: invalid padding")
    }

    last := int(plaintext[dlen-1])
    if dlen < last {
        return nil, x509.IncorrectPasswordError
    }
    if last == 0 || last > blockSize {
        return nil, x509.IncorrectPasswordError
    }

    // 保证最后填充数据为连续数据
    for _, val := range plaintext[dlen-last:] {
        if int(val) != last {
            return nil, x509.IncorrectPasswordError
        }
    }

    return plaintext[:dlen-last], nil
}
