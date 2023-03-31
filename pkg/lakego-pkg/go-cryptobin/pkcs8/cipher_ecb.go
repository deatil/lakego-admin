package pkcs8

import (
    "fmt"
    "errors"
    "crypto/cipher"
    "encoding/asn1"

    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
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
    if len(plaintext)%bs != 0 {
        err := errors.New(fmt.Sprintf("pkcs8: the length of the completed data must be an integer multiple of the block, the completed data size is %d, block size is %d", len(plaintext), bs))
        return nil, nil, err
    }

    // 需要保存的加密数据
    encrypted := make([]byte, len(plaintext))
    cryptobin_cipher.NewECBEncrypter(block).CryptBlocks(encrypted, plaintext)

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
    cryptobin_cipher.NewECBDecrypter(block).CryptBlocks(plaintext, ciphertext)

    // 解析加密数据
    plaintext = pkcs7UnPadding(plaintext)

    return plaintext, nil
}
