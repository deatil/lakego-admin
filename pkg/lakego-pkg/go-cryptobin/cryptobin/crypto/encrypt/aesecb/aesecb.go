package aesecb

import (
    "crypto/aes"

    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

// AesECB key 处理
// AesECB Generate Key
func AesECBGenerateKey(key []byte) (genKey []byte) {
    genKey = make([]byte, 16)
    copy(genKey, key)

    for i := 16; i < len(key); {
        for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
            genKey[j] ^= key[i]
        }
    }

    return genKey
}

type EncryptAesECB struct {}

func (this EncryptAesECB) Encrypt(origData []byte, opt crypto.IOption) ([]byte, error) {
    key := opt.Key()

    cipher, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    length := (len(origData) + aes.BlockSize) / aes.BlockSize
    plain := make([]byte, length*aes.BlockSize)
    copy(plain, origData)

    pad := byte(len(plain) - len(origData))
    for i := len(origData); i < len(plain); i++ {
        plain[i] = pad
    }

    encrypted := make([]byte, len(plain))

    // 分组分块加密
    for bs, be := 0, cipher.BlockSize(); bs <= len(origData); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
        cipher.Encrypt(encrypted[bs:be], plain[bs:be])
    }

    return encrypted, nil
}

func (this EncryptAesECB) Decrypt(encrypted []byte, opt crypto.IOption) ([]byte, error) {
    key := opt.Key()

    cipher, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    decrypted := make([]byte, len(encrypted))

    // 分组分块解密
    for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
        cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
    }

    trim := 0
    if len(decrypted) > 0 {
        trim = len(decrypted) - int(decrypted[len(decrypted)-1])
    }

    return decrypted[:trim], nil
}

// 特殊的 AesECB 组合模式
// 也可以使用: MultipleBy(AesECB)
// AesECB Encrypt type
// and can use MultipleBy(AesECB)
var AesECB = crypto.TypeMultiple.Generate()

func init() {
    crypto.TypeMultiple.Names().Add(AesECB, func() string {
        return "AesECB"
    })

    crypto.UseEncrypt.Add(AesECB, func() crypto.IEncrypt {
        return EncryptAesECB{}
    })
}
