package ssh

import (
    "crypto/aes"
)

var (
    SSHAES128CTR = "aes128-ctr"
    SSHAES192CTR = "aes192-ctr"
    SSHAES256CTR = "aes256-ctr"

    SSHAES128CBC = "aes128-cbc"
    SSHAES192CBC = "aes192-cbc"
    SSHAES256CBC = "aes256-cbc"
)

// AES128CTR is the 128-bit key AES cipher in CTR mode.
var AES128CTR = CipherCTR{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    blockSize:  aes.BlockSize,
    identifier: SSHAES128CTR,
}
// AES192CTR is the 192-bit key AES cipher in CTR mode.
var AES192CTR = CipherCTR{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    blockSize:  aes.BlockSize,
    identifier: SSHAES192CTR,
}
// AES256CTR is the 256-bit key AES cipher in CTR mode.
var AES256CTR = CipherCTR{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    blockSize:  aes.BlockSize,
    identifier: SSHAES256CTR,
}

// AES128CBC is the 128-bit key AES cipher in CBC mode.
var AES128CBC = CipherCBC{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    blockSize:  aes.BlockSize,
    identifier: SSHAES128CBC,
}
// AES192CBC is the 192-bit key AES cipher in CBC mode.
var AES192CBC = CipherCBC{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    blockSize:  aes.BlockSize,
    identifier: SSHAES192CBC,
}
// AES256CBC is the 256-bit key AES cipher in CBC mode.
var AES256CBC = CipherCBC{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    blockSize:  aes.BlockSize,
    identifier: SSHAES256CBC,
}

func init() {
    AddCipher(SSHAES128CTR, func() Cipher {
        return AES128CTR
    })
    AddCipher(SSHAES192CTR, func() Cipher {
        return AES192CTR
    })
    AddCipher(SSHAES256CTR, func() Cipher {
        return AES256CTR
    })

    AddCipher(SSHAES128CBC, func() Cipher {
        return AES128CBC
    })
    AddCipher(SSHAES192CBC, func() Cipher {
        return AES192CBC
    })
    AddCipher(SSHAES256CBC, func() Cipher {
        return AES256CBC
    })
}
