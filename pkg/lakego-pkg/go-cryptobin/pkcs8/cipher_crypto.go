package pkcs8

import (
    "crypto/aes"
    "crypto/des"
    "encoding/asn1"

    "github.com/tjfoc/gmsm/sm4"
)

var (
    // 加密方式
    oidDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
    oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}

    oidAES       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1}
    oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
    oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
    oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

    oidAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
    oidAES192GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 26}
    oidAES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}

    oidSM4CBC = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 2}
    oidSM4GCM = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 8}
)

// DESCBC is the 56-bit key 3DES cipher in CBC mode.
var DESCBC = CipherCBC{
    cipherFunc: des.NewCipher,
    keySize:    8,
    blockSize:  des.BlockSize,
    identifier: oidDESCBC,
}

// TripleDESCBC is the 168-bit key 3DES cipher in CBC mode.
var DESEDE3CBC = CipherCBC{
    cipherFunc: des.NewTripleDESCipher,
    keySize:    24,
    blockSize:  des.BlockSize,
    identifier: oidDESEDE3CBC,
}

// AES128CBC is the 128-bit key AES cipher in CBC mode.
var AES128CBC = CipherCBC{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    blockSize:  aes.BlockSize,
    identifier: oidAES128CBC,
}

// AES192CBC is the 192-bit key AES cipher in CBC mode.
var AES192CBC = CipherCBC{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    blockSize:  aes.BlockSize,
    identifier: oidAES192CBC,
}

// AES256CBC is the 256-bit key AES cipher in CBC mode.
var AES256CBC = CipherCBC{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    blockSize:  aes.BlockSize,
    identifier: oidAES256CBC,
}

// AES128GCM is the 128-bit key AES cipher in GCM mode.
var AES128GCM = CipherGCM{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    nonceSize:  12,
    identifier: oidAES128GCM,
}

// AES192GCM is the 192-bit key AES cipher in GCM mode.
var AES192GCM = CipherGCM{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    nonceSize:  12,
    identifier: oidAES192GCM,
}

// AES256GCM is the 256-bit key AES cipher in GCM mode.
var AES256GCM = CipherGCM{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    nonceSize:  12,
    identifier: oidAES256GCM,
}

// SM4CBC is the 128-bit key SM4 cipher in CBC mode.
var SM4CBC = CipherCBC{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    blockSize:  sm4.BlockSize,
    identifier: oidSM4CBC,
}

// SM4GCM is the 128-bit key SM4 cipher in GCM mode.
var SM4GCM = CipherGCM{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    nonceSize:  12,
    identifier: oidSM4GCM,
}

func init() {
    // des-cbc 模式
    AddCipher(oidDESCBC, DESCBC)
    AddCipher(oidDESEDE3CBC, DESEDE3CBC)

    // aes-cbc 模式
    AddCipher(oidAES128CBC, AES128CBC)
    AddCipher(oidAES192CBC, AES192CBC)
    AddCipher(oidAES256CBC, AES256CBC)

    // aes-gcm 模式
    AddCipher(oidAES128GCM, AES128GCM)
    AddCipher(oidAES192GCM, AES192GCM)
    AddCipher(oidAES256GCM, AES256GCM)

    // sm4-cbc 模式
    AddCipher(oidSM4CBC, SM4CBC)

    // sm4-gcm 模式
    AddCipher(oidSM4GCM, SM4GCM)
}
