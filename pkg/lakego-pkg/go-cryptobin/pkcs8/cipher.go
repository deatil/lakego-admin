package pkcs8

import (
    "errors"
    "crypto/x509"
    "crypto/cipher"
    "encoding/asn1"
)

// 加密
type CipherBlock struct {
    cipherFunc func(key []byte) (cipher.Block, error)
    keySize    int
    blockSize  int
    identifier asn1.ObjectIdentifier
}

func (this CipherBlock) BlockSize() int {
    return this.blockSize
}

func (this CipherBlock) KeySize() int {
    return this.keySize
}

func (this CipherBlock) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 加密
func (this CipherBlock) Encrypt(key, iv, plaintext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, errors.New(err.Error() + " failed to create cipher")
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

    enc := cipher.NewCBCEncrypter(block, iv)
    enc.CryptBlocks(encrypted, encrypted)

    return encrypted, nil
}

// 解密
func (this CipherBlock) Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(plaintext, ciphertext)

    // 解析加密数据
    blockSize := block.BlockSize()
    dlen := len(plaintext)
    if dlen == 0 || dlen%blockSize != 0 {
        return nil, errors.New("error decrypting PEM: invalid padding")
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
