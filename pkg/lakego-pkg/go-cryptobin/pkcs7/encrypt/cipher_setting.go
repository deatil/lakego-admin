package encrypt

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

    oidAES        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1}
    oidAES128ECB  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 1}
    oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
    oidAES128OFB  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 3}
    oidAES128CFB  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 4}
    oidAES128GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
    oidAES128CCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 7}

    oidAES192ECB  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 21}
    oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
    oidAES192OFB  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 23}
    oidAES192CFB  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 24}
    oidAES192GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 26}
    oidAES192CCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 27}

    oidAES256ECB  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 41}
    oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
    oidAES256OFB  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 43}
    oidAES256CFB  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 44}
    oidAES256GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
    oidAES256CCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 47}

    oidSM4ECB     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 1}
    oidSM4CBC     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 2}
    oidSM4OFB     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 3}
    oidSM4CFB     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 4}
    // CFB1 暂时不提供
    oidSM4CFB1    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 5}
    oidSM4CFB8    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 6}
    oidSM4GCM     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 8}
    oidSM4CCM     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 9}
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

// ==========

// AES128ECB is the 128-bit key AES cipher in ECB mode.
var AES128ECB = CipherECB{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    blockSize:  aes.BlockSize,
    identifier: oidAES128ECB,
}
// AES128CBC is the 128-bit key AES cipher in CBC mode.
var AES128CBC = CipherCBC{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    blockSize:  aes.BlockSize,
    identifier: oidAES128CBC,
}
// AES128OFB is the 128-bit key AES cipher in OFB mode.
var AES128OFB = CipherOFB{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    blockSize:  aes.BlockSize,
    identifier: oidAES128OFB,
}
// AES128CFB is the 128-bit key AES cipher in CFB mode.
var AES128CFB = CipherCFB{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    blockSize:  aes.BlockSize,
    identifier: oidAES128CFB,
}
// AES128GCM is the 128-bit key AES cipher in GCM mode.
var AES128GCM = CipherGCM{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    nonceSize:  12,
    identifier: oidAES128GCM,
}
// AES128GCMb is the 128-bit key AES cipher in GCM mode.
var AES128GCMb = CipherGCMb{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    nonceSize:  12,
    identifier: oidAES128GCM,
}
// AES128CCM is the 128-bit key AES cipher in CCM mode.
var AES128CCM = CipherCCM{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    nonceSize:  12,
    identifier: oidAES128CCM,
}
// AES128CCMb is the 128-bit key AES cipher in CCM mode.
var AES128CCMb = CipherCCMb{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    nonceSize:  12,
    identifier: oidAES128CCM,
}

// ==========

// AES192ECB is the 192-bit key AES cipher in ECB mode.
var AES192ECB = CipherECB{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    blockSize:  aes.BlockSize,
    identifier: oidAES192ECB,
}
// AES192CBC is the 192-bit key AES cipher in CBC mode.
var AES192CBC = CipherCBC{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    blockSize:  aes.BlockSize,
    identifier: oidAES192CBC,
}
// AES192OFB is the 192-bit key AES cipher in OFB mode.
var AES192OFB = CipherOFB{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    blockSize:  aes.BlockSize,
    identifier: oidAES192OFB,
}
// AES192CFB is the 192-bit key AES cipher in CFB mode.
var AES192CFB = CipherCFB{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    blockSize:  aes.BlockSize,
    identifier: oidAES192CFB,
}
// AES192GCM is the 192-bit key AES cipher in GCM mode.
var AES192GCM = CipherGCM{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    nonceSize:  12,
    identifier: oidAES192GCM,
}
// AES192GCMb is the 192-bit key AES cipher in GCM mode.
var AES192GCMb = CipherGCMb{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    nonceSize:  12,
    identifier: oidAES192GCM,
}
// AES192CCM is the 192-bit key AES cipher in CCM mode.
var AES192CCM = CipherCCM{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    nonceSize:  12,
    identifier: oidAES192CCM,
}
// AES192CCMb is the 192-bit key AES cipher in CCM mode.
var AES192CCMb = CipherCCMb{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    nonceSize:  12,
    identifier: oidAES192CCM,
}

// ==========

// AES256ECB is the 256-bit key AES cipher in ECB mode.
var AES256ECB = CipherECB{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    blockSize:  aes.BlockSize,
    identifier: oidAES256ECB,
}
// AES256CBC is the 256-bit key AES cipher in CBC mode.
var AES256CBC = CipherCBC{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    blockSize:  aes.BlockSize,
    identifier: oidAES256CBC,
}
// AES256OFB is the 256-bit key AES cipher in OFB mode.
var AES256OFB = CipherOFB{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    blockSize:  aes.BlockSize,
    identifier: oidAES256OFB,
}
// AES256CFB is the 256-bit key AES cipher in CFB mode.
var AES256CFB = CipherCFB{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    blockSize:  aes.BlockSize,
    identifier: oidAES256CFB,
}
// AES256GCM is the 256-bit key AES cipher in GCM mode.
var AES256GCM = CipherGCM{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    nonceSize:  12,
    identifier: oidAES256GCM,
}
// AES256GCMb is the 256-bit key AES cipher in GCM mode.
var AES256GCMb = CipherGCMb{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    nonceSize:  12,
    identifier: oidAES256GCM,
}
// AES256CCM is the 256-bit key AES cipher in CCM mode.
var AES256CCM = CipherCCM{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    nonceSize:  12,
    identifier: oidAES256CCM,
}
// AES256CCMb is the 256-bit key AES cipher in CCM mode.
var AES256CCMb = CipherCCMb{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    nonceSize:  12,
    identifier: oidAES256CCM,
}

// ==========

// SM4ECB is the 128-bit key SM4 cipher in ECB mode.
var SM4ECB = CipherECB{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    blockSize:  sm4.BlockSize,
    identifier: oidSM4ECB,
}
// SM4CBC is the 128-bit key SM4 cipher in CBC mode.
var SM4CBC = CipherCBC{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    blockSize:  sm4.BlockSize,
    identifier: oidSM4CBC,
}
// SM4OFB is the 128-bit key SM4 cipher in OFB mode.
var SM4OFB = CipherOFB{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    blockSize:  sm4.BlockSize,
    identifier: oidSM4OFB,
}
// SM4CFB is the 128-bit key SM4 cipher in CFB mode.
var SM4CFB = CipherCFB{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    blockSize:  sm4.BlockSize,
    identifier: oidSM4CFB,
}
// SM4CFB8 is the 128-bit key SM4 cipher in CFB mode.
var SM4CFB8 = CipherCFB8{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    blockSize:  sm4.BlockSize,
    identifier: oidSM4CFB8,
}
// SM4GCM is the 128-bit key SM4 cipher in GCM mode.
var SM4GCM = CipherGCM{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    nonceSize:  12,
    identifier: oidSM4GCM,
}
// SM4GCMb is the 128-bit key SM4 cipher in GCM mode.
var SM4GCMb = CipherGCMb{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    nonceSize:  12,
    identifier: oidSM4GCM,
}
// SM4CCM is the 128-bit key SM4 cipher in CCM mode.
var SM4CCM = CipherCCM{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    nonceSize:  12,
    identifier: oidSM4CCM,
}
// SM4CCM is the 128-bit key SM4 cipher in CCM mode.
var SM4CCMb = CipherCCMb{
    cipherFunc: sm4.NewCipher,
    keySize:    16,
    nonceSize:  12,
    identifier: oidSM4CCM,
}

func init() {
    // des
    AddCipher(oidDESCBC, func() Cipher {
        return DESCBC
    })
    AddCipher(oidDESEDE3CBC, func() Cipher {
        return DESEDE3CBC
    })

    // aes128
    AddCipher(oidAES128ECB, func() Cipher {
        return AES128ECB
    })
    AddCipher(oidAES128CBC, func() Cipher {
        return AES128CBC
    })
    AddCipher(oidAES128OFB, func() Cipher {
        return AES128OFB
    })
    AddCipher(oidAES128CFB, func() Cipher {
        return AES128CFB
    })
    AddCipher(oidAES128GCM, func() Cipher {
        return AES128GCM
    })
    AddCipher(oidAES128CCM, func() Cipher {
        return AES128CCM
    })

    // aes192
    AddCipher(oidAES192ECB, func() Cipher {
        return AES192ECB
    })
    AddCipher(oidAES192CBC, func() Cipher {
        return AES192CBC
    })
    AddCipher(oidAES192OFB, func() Cipher {
        return AES192OFB
    })
    AddCipher(oidAES192CFB, func() Cipher {
        return AES192CFB
    })
    AddCipher(oidAES192GCM, func() Cipher {
        return AES192GCM
    })
    AddCipher(oidAES192CCM, func() Cipher {
        return AES192CCM
    })

    // aes256
    AddCipher(oidAES256ECB, func() Cipher {
        return AES256ECB
    })
    AddCipher(oidAES256CBC, func() Cipher {
        return AES256CBC
    })
    AddCipher(oidAES256OFB, func() Cipher {
        return AES256OFB
    })
    AddCipher(oidAES256CFB, func() Cipher {
        return AES256CFB
    })
    AddCipher(oidAES256GCM, func() Cipher {
        return AES256GCM
    })
    AddCipher(oidAES256CCM, func() Cipher {
        return AES256CCM
    })

    // sm4
    AddCipher(oidSM4ECB, func() Cipher {
        return SM4ECB
    })
    AddCipher(oidSM4CBC, func() Cipher {
        return SM4CBC
    })
    AddCipher(oidSM4OFB, func() Cipher {
        return SM4OFB
    })
    AddCipher(oidSM4CFB, func() Cipher {
        return SM4CFB
    })
    AddCipher(oidSM4CFB8, func() Cipher {
        return SM4CFB8
    })
    AddCipher(oidSM4GCM, func() Cipher {
        return SM4GCM
    })
    AddCipher(oidSM4CCM, func() Cipher {
        return SM4CCM
    })
}
