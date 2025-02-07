package pkcs1

import (
    "crypto/aes"
    "crypto/des"

    "github.com/deatil/go-cryptobin/cipher/sm4"
    "github.com/deatil/go-cryptobin/cipher/kuznyechik"
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
var CipherDESEDE3CBC = CipherCBC{
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

// SM4_CBC 模式
var CipherSM4CBC = CipherCBC{
    cipherFunc:     sm4.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        16,
    blockSize:      sm4.BlockSize,
    name:           "SM4-CBC",
}

// GRASSHOPPER_CBC 模式
var CipherGrasshopperCBC = CipherCBC{
    cipherFunc:     kuznyechik.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        32,
    blockSize:      kuznyechik.BlockSize,
    name:           "GRASSHOPPER-CBC",
}

func init() {
    AddCipher(CipherDESCBC.Name(), func() Cipher {
        return CipherDESCBC
    })
    AddCipher(CipherDESEDE3CBC.Name(), func() Cipher {
        return CipherDESEDE3CBC
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

    AddCipher(CipherSM4CBC.Name(), func() Cipher {
        return CipherSM4CBC
    })

    AddCipher(CipherGrasshopperCBC.Name(), func() Cipher {
        return CipherGrasshopperCBC
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
var CipherDESEDE3CFB = CipherCFB{
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

// SM4_CFB 模式
var CipherSM4CFB = CipherCFB{
    cipherFunc:     sm4.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        16,
    blockSize:      sm4.BlockSize,
    name:           "SM4-CFB",
}

// GRASSHOPPER_CFB 模式
var CipherGrasshopperCFB = CipherCFB{
    cipherFunc:     kuznyechik.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        32,
    blockSize:      kuznyechik.BlockSize,
    name:           "GRASSHOPPER-CFB",
}

func init() {
    AddCipher(CipherDESCFB.Name(), func() Cipher {
        return CipherDESCFB
    })
    AddCipher(CipherDESEDE3CFB.Name(), func() Cipher {
        return CipherDESEDE3CFB
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

    AddCipher(CipherSM4CFB.Name(), func() Cipher {
        return CipherSM4CFB
    })

    AddCipher(CipherGrasshopperCFB.Name(), func() Cipher {
        return CipherGrasshopperCFB
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
var CipherDESEDE3OFB = CipherOFB{
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

// SM4_OFB 模式
var CipherSM4OFB = CipherOFB{
    cipherFunc:     sm4.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        16,
    blockSize:      sm4.BlockSize,
    name:           "SM4-OFB",
}

// GRASSHOPPER_OFB 模式
var CipherGrasshopperOFB = CipherOFB{
    cipherFunc:     kuznyechik.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        32,
    blockSize:      kuznyechik.BlockSize,
    name:           "GRASSHOPPER-OFB",
}

func init() {
    AddCipher(CipherDESOFB.Name(), func() Cipher {
        return CipherDESOFB
    })
    AddCipher(CipherDESEDE3OFB.Name(), func() Cipher {
        return CipherDESEDE3OFB
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

    AddCipher(CipherSM4OFB.Name(), func() Cipher {
        return CipherSM4OFB
    })

    AddCipher(CipherGrasshopperOFB.Name(), func() Cipher {
        return CipherGrasshopperOFB
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
var CipherDESEDE3CTR = CipherCTR{
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

// SM4_CTR 模式
var CipherSM4CTR = CipherCTR{
    cipherFunc:     sm4.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        16,
    blockSize:      sm4.BlockSize,
    name:           "SM4-CTR",
}

// GRASSHOPPER_CTR 模式
var CipherGrasshopperCTR = CipherCTR{
    cipherFunc:     kuznyechik.NewCipher,
    derivedKeyFunc: DeriveKey,
    saltSize:       8,
    keySize:        32,
    blockSize:      kuznyechik.BlockSize,
    name:           "GRASSHOPPER-CTR",
}

func init() {
    AddCipher(CipherDESCTR.Name(), func() Cipher {
        return CipherDESCTR
    })
    AddCipher(CipherDESEDE3CTR.Name(), func() Cipher {
        return CipherDESEDE3CTR
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

    AddCipher(CipherSM4CTR.Name(), func() Cipher {
        return CipherSM4CTR
    })

    AddCipher(CipherGrasshopperCTR.Name(), func() Cipher {
        return CipherGrasshopperCTR
    })
}
