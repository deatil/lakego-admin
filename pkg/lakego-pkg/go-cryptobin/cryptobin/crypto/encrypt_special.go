package crypto

import (
    "io"
    "errors"
    "crypto/aes"
    "crypto/rand"
    "crypto/cipher"
)

var (
    AesCFB = TypeMultiple.Generate()
    AesECB = TypeMultiple.Generate()
)

func init() {
    TypeMultiple.Names().Add(AesCFB, func() string {
        return "AesCFB"
    })
    TypeMultiple.Names().Add(AesECB, func() string {
        return "AesECB"
    })
}

type EncryptAesCFB struct {}

// 加密
func (this EncryptAesCFB) Encrypt(origData []byte, opt IOption) ([]byte, error) {
    key := opt.Key()

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    encrypted := make([]byte, aes.BlockSize + len(origData))

    iv := encrypted[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(encrypted[aes.BlockSize:], origData)

    return encrypted, nil
}

// 解密
func (this EncryptAesCFB) Decrypt(encrypted []byte, opt IOption) ([]byte, error) {
    key := opt.Key()

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(encrypted) < aes.BlockSize {
        err := errors.New("Cryptobin: ciphertext too short")
        return nil, err
    }

    iv := encrypted[:aes.BlockSize]
    encoded := encrypted[aes.BlockSize:]

    dst := make([]byte, len(encoded))
    cipher.NewCFBDecrypter(block, iv).XORKeyStream(dst, encoded)

    return dst, nil
}

func init() {
    UseEncrypt.Add(AesCFB, func() IEncrypt {
        return EncryptAesCFB{}
    })
}

// 特殊的 AesCFB 组合模式
// 也可以使用: MultipleBy(AesCFB)
func (this Cryptobin) AesCFB() Cryptobin {
    this.multiple = AesCFB

    return this
}

// ===================

type EncryptAesECB struct {}

func (this EncryptAesECB) Encrypt(origData []byte, opt IOption) ([]byte, error) {
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

func (this EncryptAesECB) Decrypt(encrypted []byte, opt IOption) ([]byte, error) {
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

func init() {
    UseEncrypt.Add(AesECB, func() IEncrypt {
        return EncryptAesECB{}
    })
}

// 特殊的 AesECB 组合模式
// 也可以使用: MultipleBy(AesECB)
func (this Cryptobin) AesECB() Cryptobin {
    this.multiple = AesECB

    return this
}

// ===================

// AesECB key 处理
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
