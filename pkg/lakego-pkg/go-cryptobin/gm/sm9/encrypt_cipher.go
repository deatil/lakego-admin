package sm9

import (
    "io"
    "crypto/cipher"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/cipher/sm4"
    cryptobin_cipher "github.com/deatil/go-cryptobin/cipher"
)

const(
    EncTypeXOR int = 0
    EncTypeECB int = 1
    EncTypeCBC int = 2
    EncTypeOFB int = 4
    EncTypeCFB int = 8
)

type cipherFunc func(key []byte) (cipher.Block, error)

// =======

// XOREncrypt represents XOR mode.
type XOREncrypt struct{}

func NewXOREncrypt() IEncrypt {
    enc := new(XOREncrypt)

    return enc
}

func (this *XOREncrypt) Type() int {
    return EncTypeXOR
}

func (this *XOREncrypt) KeySize() int {
    return 0
}

func (this *XOREncrypt) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
    subtle.XORBytes(key, key, plaintext)

    return key, nil
}

func (this *XOREncrypt) Decrypt(key, ciphertext []byte) ([]byte, error) {
    if len(ciphertext) == 0 {
        return nil, ErrDecryption
    }

    subtle.XORBytes(key, ciphertext, key)

    return key, nil
}

// =======

type CBCEncrypt struct {
    cipherFunc cipherFunc
    keySize    int
}

func NewCBCEncrypt(cipherFunc cipherFunc, keySize int) IEncrypt {
    enc := new(CBCEncrypt)
    enc.cipherFunc = cipherFunc
    enc.keySize = keySize

    return enc
}

func (this *CBCEncrypt) Type() int {
    return EncTypeCBC
}

func (this *CBCEncrypt) KeySize() int {
    return this.keySize
}

// Encrypt encrypts the plaintext with the key, includes generated IV at the beginning of the ciphertext.
func (this *CBCEncrypt) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()

    paddedPlainText := pkcs7Padding(plaintext, blockSize)

    ciphertext := make([]byte, blockSize + len(paddedPlainText))

    iv := ciphertext[:blockSize]
    if _, err := io.ReadFull(rand, iv); err != nil {
        return nil, err
    }

    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext[blockSize:], paddedPlainText)

    return ciphertext, nil
}

func (this *CBCEncrypt) Decrypt(key, ciphertext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()
    if len(ciphertext) <= blockSize {
        return nil, ErrDecryption
    }

    iv := ciphertext[:blockSize]
    ciphertext = ciphertext[blockSize:]

    plaintext := make([]byte, len(ciphertext))

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(plaintext, ciphertext)

    plaintext, err = pkcs7UnPadding(plaintext)
    if err != nil {
        return nil, ErrDecryption
    }

    return plaintext, nil
}

// =====

// ECBEncrypt represents ECB (Electronic Code Book) mode.
type ECBEncrypt struct {
    cipherFunc cipherFunc
    keySize    int
}

func (this *ECBEncrypt) Type() int {
    return EncTypeECB
}

func (this *ECBEncrypt) KeySize() int {
    return this.keySize
}

func NewECBEncrypt(cipherFunc cipherFunc, keySize int) IEncrypt {
    enc := new(ECBEncrypt)
    enc.cipherFunc = cipherFunc
    enc.keySize = keySize

    return enc
}

func (this *ECBEncrypt) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()
    paddedPlainText := pkcs7Padding(plaintext, blockSize)

    ciphertext := make([]byte, len(paddedPlainText))

    mode := cryptobin_cipher.NewECBEncrypter(block)
    mode.CryptBlocks(ciphertext, paddedPlainText)

    return ciphertext, nil
}

func (this *ECBEncrypt) Decrypt(key, ciphertext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    if len(ciphertext) == 0 {
        return nil, ErrDecryption
    }

    plaintext := make([]byte, len(ciphertext))

    mode := cryptobin_cipher.NewECBDecrypter(block)
    mode.CryptBlocks(plaintext, ciphertext)

    plaintext, err = pkcs7UnPadding(plaintext)
    if err != nil {
        return nil, ErrDecryption
    }

    return plaintext, nil
}

// ==============

// CFBEncrypt represents CFB (Cipher Feedback) mode.
type CFBEncrypt struct {
    cipherFunc cipherFunc
    keySize    int
}

func NewCFBEncrypt(cipherFunc cipherFunc, keySize int) IEncrypt {
    enc := new(CFBEncrypt)
    enc.cipherFunc = cipherFunc
    enc.keySize = keySize

    return enc
}

func (this *CFBEncrypt) Type() int {
    return EncTypeCFB
}

func (this *CFBEncrypt) KeySize() int {
    return this.keySize
}

// Encrypt encrypts the plaintext with the key, includes generated IV at the beginning of the ciphertext.
func (this *CFBEncrypt) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()

    ciphertext := make([]byte, blockSize+len(plaintext))

    iv := ciphertext[:blockSize]
    if _, err := io.ReadFull(rand, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[blockSize:], plaintext)

    return ciphertext, nil
}

func (this *CFBEncrypt) Decrypt(key, ciphertext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()
    if len(ciphertext) <= blockSize {
        return nil, ErrDecryption
    }

    iv := ciphertext[:blockSize]
    ciphertext = ciphertext[blockSize:]

    plaintext := make([]byte, len(ciphertext))
    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(plaintext, ciphertext)

    return plaintext, nil
}

// =========

// OFBEncrypt represents OFB (Output Feedback) mode.
type OFBEncrypt struct {
    cipherFunc cipherFunc
    keySize    int
}

func NewOFBEncrypt(cipherFunc cipherFunc, keySize int) IEncrypt {
    enc := new(OFBEncrypt)
    enc.cipherFunc = cipherFunc
    enc.keySize = keySize

    return enc
}

func (this *OFBEncrypt) Type() int {
    return EncTypeOFB
}

func (this *OFBEncrypt) KeySize() int {
    return this.keySize
}

// Encrypt encrypts the plaintext with the key, includes generated IV at the beginning of the ciphertext.
func (this *OFBEncrypt) Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()

    ciphertext := make([]byte, blockSize + len(plaintext))

    iv := ciphertext[:blockSize]
    if _, err := io.ReadFull(rand, iv); err != nil {
        return nil, err
    }

    stream := cipher.NewOFB(block, iv)
    stream.XORKeyStream(ciphertext[blockSize:], plaintext)

    return ciphertext, nil
}

func (this *OFBEncrypt) Decrypt(key, ciphertext []byte) ([]byte, error) {
    block, err := this.cipherFunc(key)
    if err != nil {
        return nil, err
    }

    blockSize := block.BlockSize()
    if len(ciphertext) <= blockSize {
        return nil, ErrDecryption
    }

    iv := ciphertext[:blockSize]
    ciphertext = ciphertext[blockSize:]

    plaintext := make([]byte, len(ciphertext))

    stream := cipher.NewOFB(block, iv)
    stream.XORKeyStream(plaintext, ciphertext)

    return plaintext, nil
}

// =========

// SM4ECBEncrypt option represents SM4 ECB mode
var SM4ECBEncrypt = NewECBEncrypt(sm4.NewCipher, sm4.BlockSize)

// SM4CBCEncrypt option represents SM4 CBC mode
var SM4CBCEncrypt = NewCBCEncrypt(sm4.NewCipher, sm4.BlockSize)

// SM4CFBEncrypt option represents SM4 CFB mode
var SM4CFBEncrypt = NewCFBEncrypt(sm4.NewCipher, sm4.BlockSize)

// SM4OFBEncrypt option represents SM4 OFB mode
var SM4OFBEncrypt = NewOFBEncrypt(sm4.NewCipher, sm4.BlockSize)

// XorEncrypt default option represents XOR mode
var XorEncrypt = NewXOREncrypt()

// Default Encrypt
var DefaultEncrypt = SM4CBCEncrypt

func GetEncryptType(encType int) IEncrypt {
    switch encType {
        case EncTypeECB:
            return SM4ECBEncrypt
        case EncTypeCBC:
            return SM4CBCEncrypt
        case EncTypeCFB:
            return SM4CFBEncrypt
        case EncTypeOFB:
            return SM4OFBEncrypt
        case EncTypeXOR:
            return XorEncrypt
    }

    return nil
}
