package pkcs1

import (
    "crypto/aes"
    "crypto/des"
)

// DES_CBC 模式
var CipherDESCBC = CipherCBC{
    cipherFunc:     des.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        8,
    blockSize:      des.BlockSize,
    name:           "DES-CBC",
}
var Cipher3DESCBC = CipherCBC{
    cipherFunc:     des.NewTripleDESCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        24,
    blockSize:      des.BlockSize,
    name:           "DES-EDE3-CBC",
}

// AES_CBC 模式
var CipherAES128CBC = CipherCBC{
    cipherFunc:     aes.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        16,
    blockSize:      aes.BlockSize,
    name:           "AES-128-CBC",
}
var CipherAES192CBC = CipherCBC{
    cipherFunc:     aes.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        24,
    blockSize:      aes.BlockSize,
    name:           "AES-192-CBC",
}
var CipherAES256CBC = CipherCBC{
    cipherFunc:     aes.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        32,
    blockSize:      aes.BlockSize,
    name:           "AES-256-CBC",
}

func init() {
    AddCipher(CipherDESCBC.Name(), func() Cipher {
        return CipherDESCBC
    })
    AddCipher(Cipher3DESCBC.Name(), func() Cipher {
        return Cipher3DESCBC
    })

    AddCipher(CipherAES128CBC.Name(), func() Cipher {
        return CipherAES128CBC
    })
    AddCipher(CipherAES192CBC.Name(), func() Cipher {
        return CipherAES192CBC
    })
    AddCipher(CipherAES256CBC.Name(), func() Cipher {
        return CipherAES256CBC
    })
}

// =================

// DES_CFB 模式
var CipherDESCFB = CipherCFB{
    cipherFunc:     des.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        8,
    blockSize:      des.BlockSize,
    name:           "DES-CFB",
}
var Cipher3DESCFB = CipherCFB{
    cipherFunc:     des.NewTripleDESCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        24,
    blockSize:      des.BlockSize,
    name:           "DES-EDE3-CFB",
}

// AES_CFB 模式
var CipherAES128CFB = CipherCFB{
    cipherFunc:     aes.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        16,
    blockSize:      aes.BlockSize,
    name:           "AES-128-CFB",
}
var CipherAES192CFB = CipherCFB{
    cipherFunc:     aes.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        24,
    blockSize:      aes.BlockSize,
    name:           "AES-192-CFB",
}
var CipherAES256CFB = CipherCFB{
    cipherFunc:     aes.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        32,
    blockSize:      aes.BlockSize,
    name:           "AES-256-CFB",
}

func init() {
    AddCipher(CipherDESCFB.Name(), func() Cipher {
        return CipherDESCFB
    })
    AddCipher(Cipher3DESCFB.Name(), func() Cipher {
        return Cipher3DESCFB
    })

    AddCipher(CipherAES128CFB.Name(), func() Cipher {
        return CipherAES128CFB
    })
    AddCipher(CipherAES192CFB.Name(), func() Cipher {
        return CipherAES192CFB
    })
    AddCipher(CipherAES256CFB.Name(), func() Cipher {
        return CipherAES256CFB
    })
}

// =================

// DES_OFB 模式
var CipherDESOFB = CipherOFB{
    cipherFunc:     des.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        8,
    blockSize:      des.BlockSize,
    name:           "DES-OFB",
}
var Cipher3DESOFB = CipherOFB{
    cipherFunc:     des.NewTripleDESCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        24,
    blockSize:      des.BlockSize,
    name:           "DES-EDE3-OFB",
}

// AES_OFB 模式
var CipherAES128OFB = CipherOFB{
    cipherFunc:     aes.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        16,
    blockSize:      aes.BlockSize,
    name:           "AES-128-OFB",
}
var CipherAES192OFB = CipherOFB{
    cipherFunc:     aes.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        24,
    blockSize:      aes.BlockSize,
    name:           "AES-192-OFB",
}
var CipherAES256OFB = CipherOFB{
    cipherFunc:     aes.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        32,
    blockSize:      aes.BlockSize,
    name:           "AES-256-OFB",
}

func init() {
    AddCipher(CipherDESOFB.Name(), func() Cipher {
        return CipherDESOFB
    })
    AddCipher(Cipher3DESOFB.Name(), func() Cipher {
        return Cipher3DESOFB
    })

    AddCipher(CipherAES128OFB.Name(), func() Cipher {
        return CipherAES128OFB
    })
    AddCipher(CipherAES192OFB.Name(), func() Cipher {
        return CipherAES192OFB
    })
    AddCipher(CipherAES256OFB.Name(), func() Cipher {
        return CipherAES256OFB
    })
}

// =================

// DES_CTR 模式
var CipherDESCTR = CipherCTR{
    cipherFunc:     des.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        8,
    blockSize:      des.BlockSize,
    name:           "DES-CTR",
}
var Cipher3DESCTR = CipherCTR{
    cipherFunc:     des.NewTripleDESCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        24,
    blockSize:      des.BlockSize,
    name:           "DES-EDE3-CTR",
}

// AES_CTR 模式
var CipherAES128CTR = CipherCTR{
    cipherFunc:     aes.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        16,
    blockSize:      aes.BlockSize,
    name:           "AES-128-CTR",
}
var CipherAES192CTR = CipherCTR{
    cipherFunc:     aes.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        24,
    blockSize:      aes.BlockSize,
    name:           "AES-192-CTR",
}
var CipherAES256CTR = CipherCTR{
    cipherFunc:     aes.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        32,
    blockSize:      aes.BlockSize,
    name:           "AES-256-CTR",
}

func init() {
    AddCipher(CipherDESCTR.Name(), func() Cipher {
        return CipherDESCTR
    })
    AddCipher(Cipher3DESCTR.Name(), func() Cipher {
        return Cipher3DESCTR
    })

    AddCipher(CipherAES128CTR.Name(), func() Cipher {
        return CipherAES128CTR
    })
    AddCipher(CipherAES192CTR.Name(), func() Cipher {
        return CipherAES192CTR
    })
    AddCipher(CipherAES256CTR.Name(), func() Cipher {
        return CipherAES256CTR
    })
}
