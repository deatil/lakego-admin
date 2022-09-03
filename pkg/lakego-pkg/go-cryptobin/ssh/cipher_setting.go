package ssh

import (
    "crypto/aes"
    "crypto/des"
    "crypto/cipher"

    "golang.org/x/crypto/cast5"
    "golang.org/x/crypto/blowfish"
    "golang.org/x/crypto/chacha20poly1305"

    "github.com/tjfoc/gmsm/sm4"
)

var (
    SSHDESEDE3CBC = "3des-cbc"

    SSHAES128CBC = "aes128-cbc"
    SSHAES192CBC = "aes192-cbc"
    SSHAES256CBC = "aes256-cbc"

    SSHAES128CTR = "aes128-ctr"
    SSHAES192CTR = "aes192-ctr"
    SSHAES256CTR = "aes256-ctr"

    SSHAES128GCM = "aes128-gcm@openssh.com"
    SSHAES256GCM = "aes256-gcm@openssh.com"

    // RC4 = arcfour
    SSHArcfour     = "arcfour"
    SSHArcfour128  = "arcfour128"
    SSHArcfour256  = "arcfour256"

    SSHBlowfishCBC = "blowfish-cbc"

    // cast5 = cast128
    SSHCast128CBC  = "cast128-cbc"

    SSHChacha20poly1305 = "chacha20-poly1305@openssh.com"

    SSHSM4CBC = "sm4-cbc"
    SSHSM4CTR = "sm4-ctr"
)

var (
    newBlowfishCipher = func(key []byte) (cipher.Block, error) {
        return blowfish.NewCipher(key)
    }
    newCast5Cipher = func(key []byte) (cipher.Block, error) {
        return cast5.NewCipher(key)
    }
)

// DESEDE3CBC is the 168-bit key 3DES cipher in CBC mode.
var DESEDE3CBC = CipherCBC{
    cipherFunc: des.NewTripleDESCipher,
    keySize:    24,
    blockSize:  des.BlockSize,
    identifier: SSHDESEDE3CBC,
}
// BlowfishCBC is the key (from 1 to 56 bytes) blowfish cipher in CBC mode.
var BlowfishCBC = CipherCBC{
    cipherFunc: newBlowfishCipher,
    keySize:    24,
    blockSize:  blowfish.BlockSize,
    identifier: SSHBlowfishCBC,
}
// Chacha20poly1305 is the 256-bit chacha20poly1305 cipher.
var Chacha20poly1305 = CipherChacha20poly1305{
    keySize:    32,
    nonceSize:  chacha20poly1305.NonceSize,
    identifier: SSHChacha20poly1305,
}

// Cast128CBC is the 128-bit key cast5 cipher in CBC mode.
var Cast128CBC = CipherCBC{
    cipherFunc: newCast5Cipher,
    keySize:    16,
    blockSize:  cast5.BlockSize,
    identifier: SSHCast128CBC,
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

// AES128GCM is the 128-bit key AES cipher in GCM mode.
var AES128GCM = CipherGCM{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    nonceSize:  12,
    identifier: SSHAES128GCM,
}
// AES256GCM is the 256-bit key AES cipher in GCM mode.
var AES256GCM = CipherGCM{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    nonceSize:  12,
    identifier: SSHAES256GCM,
}

// Arcfour is the (from 1 to 256 bytes) key RC4 cipher.
var Arcfour = CipherRC4{
    keySize:    8,
    blockSize:  0,
    identifier: SSHArcfour,
}
// Arcfour128 is the 128-bit key RC4 cipher.
var Arcfour128 = CipherRC4{
    keySize:    16,
    blockSize:  0,
    identifier: SSHArcfour128,
}
// Arcfour256 is the 256-bit key RC4 cipher.
var Arcfour256 = CipherRC4{
    keySize:    32,
    blockSize:  0,
    identifier: SSHArcfour256,
}

// SM4CBC is the 128-bit SM4 AES cipher in CBC mode.
var SM4CBC = CipherCBC{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    blockSize:  sm4.BlockSize,
    identifier: SSHSM4CBC,
}
// SM4CTR is the 128-bit SM4 AES cipher in CTR mode.
var SM4CTR = CipherCTR{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    blockSize:  sm4.BlockSize,
    identifier: SSHSM4CTR,
}

func init() {
    AddCipher(SSHDESEDE3CBC, func() Cipher {
        return DESEDE3CBC
    })
    AddCipher(SSHBlowfishCBC, func() Cipher {
        return BlowfishCBC
    })
    AddCipher(SSHChacha20poly1305, func() Cipher {
        return Chacha20poly1305
    })

    // Cast128CBC
    AddCipher(SSHCast128CBC, func() Cipher {
        return Cast128CBC
    })

    AddCipher(SSHAES128CBC, func() Cipher {
        return AES128CBC
    })
    AddCipher(SSHAES128CTR, func() Cipher {
        return AES128CTR
    })

    AddCipher(SSHAES192CBC, func() Cipher {
        return AES192CBC
    })
    AddCipher(SSHAES192CTR, func() Cipher {
        return AES192CTR
    })

    AddCipher(SSHAES256CBC, func() Cipher {
        return AES256CBC
    })
    AddCipher(SSHAES256CTR, func() Cipher {
        return AES256CTR
    })

    AddCipher(SSHAES128GCM, func() Cipher {
        return AES128GCM
    })
    AddCipher(SSHAES256GCM, func() Cipher {
        return AES256GCM
    })

    AddCipher(SSHArcfour, func() Cipher {
        return Arcfour
    })
    AddCipher(SSHArcfour128, func() Cipher {
        return Arcfour128
    })
    AddCipher(SSHArcfour256, func() Cipher {
        return Arcfour256
    })

    AddCipher(SSHSM4CBC, func() Cipher {
        return SM4CBC
    })
    AddCipher(SSHSM4CTR, func() Cipher {
        return SM4CTR
    })
}
