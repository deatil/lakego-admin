package pbes2

import (
    "crypto/aes"
    "crypto/des"
    "crypto/cipher"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/cipher/rc2"
    "github.com/deatil/go-cryptobin/cipher/rc5"
    "github.com/deatil/go-cryptobin/cipher/sm4"
    "github.com/deatil/go-cryptobin/cipher/seed"
    "github.com/deatil/go-cryptobin/cipher/aria"
    "github.com/deatil/go-cryptobin/cipher/gost"
    "github.com/deatil/go-cryptobin/cipher/misty1"
    "github.com/deatil/go-cryptobin/cipher/serpent"
)

var (
    // 加密方式
    oidDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
    oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
    oidRC2CBC     = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 2}
    oidRC5CBCPad  = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 9}

    // AES
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

    // SM4
    oidSM4     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104}
    oidSM4ECB  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 1}
    oidSM4CBC  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 2}
    oidSM4OFB  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 3}
    oidSM4CFB  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 4}
    oidSM4CFB1 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 5}
    oidSM4CFB8 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 6}
    oidSM4GCM  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 8}
    oidSM4CCM  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 9}

    // gost
    oidGostCipher = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 21}

    // ARIA
    oidARIA128ECB = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 1}
    oidARIA128CBC = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 2}
    oidARIA128CFB = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 3}
    oidARIA128OFB = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 4}
    oidARIA128CTR = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 5}
    oidARIA128GCM = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 34}
    oidARIA128CCM = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 37}

    oidARIA192ECB = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 6}
    oidARIA192CBC = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 7}
    oidARIA192CFB = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 8}
    oidARIA192OFB = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 9}
    oidARIA192CTR = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 10}
    oidARIA192GCM = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 35}
    oidARIA192CCM = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 38}

    oidARIA256ECB = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 11}
    oidARIA256CBC = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 12}
    oidARIA256CFB = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 13}
    oidARIA256OFB = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 14}
    oidARIA256CTR = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 15}
    oidARIA256GCM = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 36}
    oidARIA256CCM = asn1.ObjectIdentifier{1, 2, 410, 200046, 1, 1, 39}

    // Misty1
    oidMisty1CBC = asn1.ObjectIdentifier{1, 2, 392, 200011, 61, 1, 1, 1, 1}

    // Seed
    oidSeedECB = asn1.ObjectIdentifier{1, 2, 410, 200004, 1, 3}
    oidSeedCBC = asn1.ObjectIdentifier{1, 2, 410, 200004, 1, 4}
    oidSeedOFB = asn1.ObjectIdentifier{1, 2, 410, 200004, 1, 5}
    oidSeedCFB = asn1.ObjectIdentifier{1, 2, 410, 200004, 1, 6}

    // Serpent
    oidSerpent128ECB = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 13, 2, 1}
    oidSerpent128CBC = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 13, 2, 2}
    oidSerpent128OFB = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 13, 2, 3}
    oidSerpent128CFB = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 13, 2, 4}

    oidSerpent192ECB = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 13, 2, 21}
    oidSerpent192CBC = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 13, 2, 22}
    oidSerpent192OFB = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 13, 2, 23}
    oidSerpent192CFB = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 13, 2, 24}

    oidSerpent256ECB = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 13, 2, 41}
    oidSerpent256CBC = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 13, 2, 42}
    oidSerpent256OFB = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 13, 2, 43}
    oidSerpent256CFB = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 13, 2, 44}
)

var (
    newRC2Cipher = func(key []byte) (cipher.Block, error) {
        return rc2.NewCipher(key, len(key)*8)
    }
)

// DESCBC is the 56-bit key DES cipher in CBC mode.
var DESCBC = CipherCBC{
    cipherFunc:   des.NewCipher,
    keySize:      8,
    blockSize:    des.BlockSize,
    identifier:   oidDESCBC,
    hasKeyLength: false,
}
// TripleDESCBC is the 168-bit key 3DES cipher in CBC mode.
var DESEDE3CBC = CipherCBC{
    cipherFunc:   des.NewTripleDESCipher,
    keySize:      24,
    blockSize:    des.BlockSize,
    identifier:   oidDESEDE3CBC,
    hasKeyLength: false,
}
// RC2CBC is the [40-bit, 64-bit, 168-bit] key RC2 cipher in CBC mode.
// [rc2Version, keySize] = [58, 16] | [120, 8] | [160, 5]
var RC2CBC = CipherRC2CBC{
    cipherFunc:   newRC2Cipher,
    rc2Version:   58,
    keySize:      16,
    blockSize:    rc2.BlockSize,
    identifier:   oidRC2CBC,
    hasKeyLength: true,
}

var RC2_40CBC  = RC2CBC.WithRC2Version(160).WithKeySize(5)
var RC2_64CBC  = RC2CBC.WithRC2Version(120).WithKeySize(8)
var RC2_128CBC = RC2CBC.WithRC2Version(58).WithKeySize(16)

// RC5CBC is the [16, 24, 32] bytes key RC5 cipher in CBC mode.
// wordSize = [32, 64] | rounds = [8, 127]
var RC5CBC = CipherRC5CBC{
    cipherFunc:   rc5.NewCipher,
    wordSize:     32,
    rounds:       16,
    keySize:      16,
    identifier:   oidRC5CBCPad,
    hasKeyLength: true,
}

var RC5_128CBC = RC5CBC.WithKeySize(16)
var RC5_192CBC = RC5CBC.WithKeySize(24)
var RC5_256CBC = RC5CBC.WithKeySize(32)

// ==========

// AES128ECB is the 128-bit key AES cipher in ECB mode.
var AES128ECB = CipherECB{
    cipherFunc:   aes.NewCipher,
    keySize:      16,
    blockSize:    aes.BlockSize,
    identifier:   oidAES128ECB,
    hasKeyLength: false,
}
// AES128CBC is the 128-bit key AES cipher in CBC mode.
var AES128CBC = CipherCBC{
    cipherFunc:   aes.NewCipher,
    keySize:      16,
    blockSize:    aes.BlockSize,
    identifier:   oidAES128CBC,
    hasKeyLength: false,
}
// AES128OFB is the 128-bit key AES cipher in OFB mode.
var AES128OFB = CipherOFB{
    cipherFunc:   aes.NewCipher,
    keySize:      16,
    blockSize:    aes.BlockSize,
    identifier:   oidAES128OFB,
    hasKeyLength: false,
}
// AES128CFB is the 128-bit key AES cipher in CFB mode.
var AES128CFB = CipherCFB{
    cipherFunc:   aes.NewCipher,
    keySize:      16,
    blockSize:    aes.BlockSize,
    identifier:   oidAES128CFB,
    hasKeyLength: false,
}
// AES128GCM is the 128-bit key AES cipher in GCM mode.
var AES128GCM = CipherGCM{
    cipherFunc:   aes.NewCipher,
    keySize:      16,
    nonceSize:    12,
    identifier:   oidAES128GCM,
    hasKeyLength: false,
}
// AES128GCMIv is the 128-bit key AES cipher in GCM mode.
var AES128GCMIv = CipherGCMIv{
    cipherFunc:   aes.NewCipher,
    keySize:      16,
    nonceSize:    12,
    identifier:   oidAES128GCM,
    hasKeyLength: false,
}
// AES128CCM is the 128-bit key AES cipher in CCM mode.
var AES128CCM = CipherCCM{
    cipherFunc:   aes.NewCipher,
    keySize:      16,
    nonceSize:    12,
    identifier:   oidAES128CCM,
    hasKeyLength: false,
}
// AES128CCMIv is the 128-bit key AES cipher in CCM mode.
var AES128CCMIv = CipherCCMIv{
    cipherFunc:   aes.NewCipher,
    keySize:      16,
    nonceSize:    12,
    identifier:   oidAES128CCM,
    hasKeyLength: false,
}

// ==========

// AES192ECB is the 192-bit key AES cipher in ECB mode.
var AES192ECB = CipherECB{
    cipherFunc:   aes.NewCipher,
    keySize:      24,
    blockSize:    aes.BlockSize,
    identifier:   oidAES192ECB,
    hasKeyLength: false,
}
// AES192CBC is the 192-bit key AES cipher in CBC mode.
var AES192CBC = CipherCBC{
    cipherFunc:   aes.NewCipher,
    keySize:      24,
    blockSize:    aes.BlockSize,
    identifier:   oidAES192CBC,
    hasKeyLength: false,
}
// AES192OFB is the 192-bit key AES cipher in OFB mode.
var AES192OFB = CipherOFB{
    cipherFunc:   aes.NewCipher,
    keySize:      24,
    blockSize:    aes.BlockSize,
    identifier:   oidAES192OFB,
    hasKeyLength: false,
}
// AES192CFB is the 192-bit key AES cipher in CFB mode.
var AES192CFB = CipherCFB{
    cipherFunc:   aes.NewCipher,
    keySize:      24,
    blockSize:    aes.BlockSize,
    identifier:   oidAES192CFB,
    hasKeyLength: false,
}
// AES192GCM is the 192-bit key AES cipher in GCM mode.
var AES192GCM = CipherGCM{
    cipherFunc:   aes.NewCipher,
    keySize:      24,
    nonceSize:    12,
    identifier:   oidAES192GCM,
    hasKeyLength: false,
}
// AES192GCMIv is the 192-bit key AES cipher in GCM mode.
var AES192GCMIv = CipherGCMIv{
    cipherFunc:   aes.NewCipher,
    keySize:      24,
    nonceSize:    12,
    identifier:   oidAES192GCM,
    hasKeyLength: false,
}
// AES192CCM is the 192-bit key AES cipher in CCM mode.
var AES192CCM = CipherCCM{
    cipherFunc:   aes.NewCipher,
    keySize:      24,
    nonceSize:    12,
    identifier:   oidAES192CCM,
    hasKeyLength: false,
}
// AES192CCMIv is the 192-bit key AES cipher in CCM mode.
var AES192CCMIv = CipherCCMIv{
    cipherFunc:   aes.NewCipher,
    keySize:      24,
    nonceSize:    12,
    identifier:   oidAES192CCM,
    hasKeyLength: false,
}

// ==========

// AES256ECB is the 256-bit key AES cipher in ECB mode.
var AES256ECB = CipherECB{
    cipherFunc:   aes.NewCipher,
    keySize:      32,
    blockSize:    aes.BlockSize,
    identifier:   oidAES256ECB,
    hasKeyLength: false,
}
// AES256CBC is the 256-bit key AES cipher in CBC mode.
var AES256CBC = CipherCBC{
    cipherFunc:   aes.NewCipher,
    keySize:      32,
    blockSize:    aes.BlockSize,
    identifier:   oidAES256CBC,
    hasKeyLength: false,
}
// AES256OFB is the 256-bit key AES cipher in OFB mode.
var AES256OFB = CipherOFB{
    cipherFunc:   aes.NewCipher,
    keySize:      32,
    blockSize:    aes.BlockSize,
    identifier:   oidAES256OFB,
    hasKeyLength: false,
}
// AES256CFB is the 256-bit key AES cipher in CFB mode.
var AES256CFB = CipherCFB{
    cipherFunc:   aes.NewCipher,
    keySize:      32,
    blockSize:    aes.BlockSize,
    identifier:   oidAES256CFB,
    hasKeyLength: false,
}
// AES256GCM is the 256-bit key AES cipher in GCM mode.
var AES256GCM = CipherGCM{
    cipherFunc:   aes.NewCipher,
    keySize:      32,
    nonceSize:    12,
    identifier:   oidAES256GCM,
    hasKeyLength: false,
}
// AES256GCMIv is the 256-bit key AES cipher in GCM mode.
var AES256GCMIv = CipherGCMIv{
    cipherFunc:   aes.NewCipher,
    keySize:      32,
    nonceSize:    12,
    identifier:   oidAES256GCM,
    hasKeyLength: false,
}
// AES256CCM is the 256-bit key AES cipher in CCM mode.
var AES256CCM = CipherCCM{
    cipherFunc:   aes.NewCipher,
    keySize:      32,
    nonceSize:    12,
    identifier:   oidAES256CCM,
    hasKeyLength: false,
}
// AES256CCMIv is the 256-bit key AES cipher in CCM mode.
var AES256CCMIv = CipherCCMIv{
    cipherFunc:   aes.NewCipher,
    keySize:      32,
    nonceSize:    12,
    identifier:   oidAES256CCM,
    hasKeyLength: false,
}

// ==========

// SM4ECB is the 128-bit key SM4 cipher in ECB mode.
var SM4ECB = CipherECB{
    cipherFunc:   sm4.NewCipher,
    keySize:      16,
    blockSize:    sm4.BlockSize,
    identifier:   oidSM4ECB,
    hasKeyLength: false,
}
// SM4CBC is the 128-bit key SM4 cipher in CBC mode.
var SM4CBC = CipherCBC{
    cipherFunc:   sm4.NewCipher,
    keySize:      16,
    blockSize:    sm4.BlockSize,
    identifier:   oidSM4CBC,
    hasKeyLength: false,
}
// SM4OFB is the 128-bit key SM4 cipher in OFB mode.
var SM4OFB = CipherOFB{
    cipherFunc:   sm4.NewCipher,
    keySize:      16,
    blockSize:    sm4.BlockSize,
    identifier:   oidSM4OFB,
    hasKeyLength: false,
}
// SM4CFB is the 128-bit key SM4 cipher in CFB mode.
var SM4CFB = CipherCFB{
    cipherFunc:   sm4.NewCipher,
    keySize:      16,
    blockSize:    sm4.BlockSize,
    identifier:   oidSM4CFB,
    hasKeyLength: false,
}
// SM4CFB1 is the 128-bit key SM4 cipher in CFB mode.
var SM4CFB1 = CipherCFB1{
    cipherFunc:   sm4.NewCipher,
    keySize:      16,
    blockSize:    sm4.BlockSize,
    identifier:   oidSM4CFB1,
    hasKeyLength: false,
}
// SM4CFB8 is the 128-bit key SM4 cipher in CFB mode.
var SM4CFB8 = CipherCFB8{
    cipherFunc:   sm4.NewCipher,
    keySize:      16,
    blockSize:    sm4.BlockSize,
    identifier:   oidSM4CFB8,
    hasKeyLength: false,
}
// SM4GCM is the 128-bit key SM4 cipher in GCM mode.
var SM4GCM = CipherGCM{
    cipherFunc:   sm4.NewCipher,
    keySize:      16,
    nonceSize:    12,
    identifier:   oidSM4GCM,
    hasKeyLength: false,
}
// SM4GCMIv is the 128-bit key SM4 cipher in GCM mode.
var SM4GCMIv = CipherGCMIv{
    cipherFunc:   sm4.NewCipher,
    keySize:      16,
    nonceSize:    12,
    identifier:   oidSM4GCM,
    hasKeyLength: false,
}
// SM4CCM is the 128-bit key SM4 cipher in CCM mode.
var SM4CCM = CipherCCM{
    cipherFunc:   sm4.NewCipher,
    keySize:      16,
    nonceSize:    12,
    identifier:   oidSM4CCM,
    hasKeyLength: false,
}
// SM4CCMIv is the 128-bit key SM4 cipher in CCM mode.
var SM4CCMIv = CipherCCMIv{
    cipherFunc:   sm4.NewCipher,
    keySize:      16,
    nonceSize:    12,
    identifier:   oidSM4CCM,
    hasKeyLength: false,
}

// ==========

// GostCipher is the 256-bit key Gost cipher in CFB mode.
var GostCipher = CipherGostCFB{
    cipherFunc:   gost.NewCipher,
    keySize:      32,
    blockSize:    gost.BlockSize,
    identifier:   oidGostCipher,
    sboxOid:      oidGostTc26CipherZ,
    hasKeyLength: false,
}

// ==========

// ARIA128ECB is the 128-bit key ARIA cipher in ECB mode.
var ARIA128ECB = CipherECB{
    cipherFunc:   aria.NewCipher,
    keySize:      16,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA128ECB,
    hasKeyLength: false,
}
// ARIA128CBC is the 128-bit key ARIA cipher in CBC mode.
var ARIA128CBC = CipherCBC{
    cipherFunc:   aria.NewCipher,
    keySize:      16,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA128CBC,
    hasKeyLength: false,
}
// ARIA128CFB is the 128-bit key ARIA cipher in CFB mode.
var ARIA128CFB = CipherCFB{
    cipherFunc:   aria.NewCipher,
    keySize:      16,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA128CFB,
    hasKeyLength: false,
}
// ARIA128OFB is the 128-bit key ARIA cipher in OFB mode.
var ARIA128OFB = CipherOFB{
    cipherFunc:   aria.NewCipher,
    keySize:      16,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA128OFB,
    hasKeyLength: false,
}
// ARIA128CTR is the 128-bit key ARIA cipher in CTR mode.
var ARIA128CTR = CipherCTR{
    cipherFunc:   aria.NewCipher,
    keySize:      16,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA128CTR,
    hasKeyLength: false,
}
// ARIA128GCM is the 128-bit key ARIA cipher in GCM mode.
var ARIA128GCM = CipherGCM{
    cipherFunc:   aria.NewCipher,
    keySize:      16,
    nonceSize:    12,
    identifier:   oidARIA128GCM,
    hasKeyLength: false,
}
// ARIA128CCM is the 128-bit key ARIA cipher in CCM mode.
var ARIA128CCM = CipherCCM{
    cipherFunc:   aria.NewCipher,
    keySize:      16,
    nonceSize:    12,
    identifier:   oidARIA128CCM,
    hasKeyLength: false,
}

// ==========

// ARIA192ECB is the 192-bit key ARIA cipher in ECB mode.
var ARIA192ECB = CipherECB{
    cipherFunc:   aria.NewCipher,
    keySize:      24,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA192ECB,
    hasKeyLength: false,
}
// ARIA192CBC is the 192-bit key ARIA cipher in CBC mode.
var ARIA192CBC = CipherCBC{
    cipherFunc:   aria.NewCipher,
    keySize:      24,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA192CBC,
    hasKeyLength: false,
}
// ARIA192CFB is the 192-bit key ARIA cipher in CFB mode.
var ARIA192CFB = CipherCFB{
    cipherFunc:   aria.NewCipher,
    keySize:      24,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA192CFB,
    hasKeyLength: false,
}
// ARIA192OFB is the 192-bit key ARIA cipher in OFB mode.
var ARIA192OFB = CipherOFB{
    cipherFunc:   aria.NewCipher,
    keySize:      24,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA192OFB,
    hasKeyLength: false,
}
// ARIA192CTR is the 192-bit key ARIA cipher in CTR mode.
var ARIA192CTR = CipherCTR{
    cipherFunc:   aria.NewCipher,
    keySize:      24,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA192CTR,
    hasKeyLength: false,
}
// ARIA192GCM is the 192-bit key ARIA cipher in GCM mode.
var ARIA192GCM = CipherGCM{
    cipherFunc:   aria.NewCipher,
    keySize:      24,
    nonceSize:    12,
    identifier:   oidARIA192GCM,
    hasKeyLength: false,
}
// ARIA192CCM is the 192-bit key ARIA cipher in CCM mode.
var ARIA192CCM = CipherCCM{
    cipherFunc:   aria.NewCipher,
    keySize:      24,
    nonceSize:    12,
    identifier:   oidARIA192CCM,
    hasKeyLength: false,
}

// ==========

// ARIA256ECB is the 256-bit key ARIA cipher in ECB mode.
var ARIA256ECB = CipherECB{
    cipherFunc:   aria.NewCipher,
    keySize:      32,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA256ECB,
    hasKeyLength: false,
}
// ARIA256CBC is the 256-bit key ARIA cipher in CBC mode.
var ARIA256CBC = CipherCBC{
    cipherFunc:   aria.NewCipher,
    keySize:      32,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA256CBC,
    hasKeyLength: false,
}
// ARIA256CFB is the 256-bit key ARIA cipher in CFB mode.
var ARIA256CFB = CipherCFB{
    cipherFunc:   aria.NewCipher,
    keySize:      32,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA256CFB,
    hasKeyLength: false,
}
// ARIA256OFB is the 256-bit key ARIA cipher in OFB mode.
var ARIA256OFB = CipherOFB{
    cipherFunc:   aria.NewCipher,
    keySize:      32,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA256OFB,
    hasKeyLength: false,
}
// ARIA256CTR is the 256-bit key ARIA cipher in CTR mode.
var ARIA256CTR = CipherCTR{
    cipherFunc:   aria.NewCipher,
    keySize:      32,
    blockSize:    aria.BlockSize,
    identifier:   oidARIA256CTR,
    hasKeyLength: false,
}
// ARIA256GCM is the 256-bit key ARIA cipher in GCM mode.
var ARIA256GCM = CipherGCM{
    cipherFunc:   aria.NewCipher,
    keySize:      32,
    nonceSize:    12,
    identifier:   oidARIA256GCM,
    hasKeyLength: false,
}
// ARIA256CCM is the 256-bit key ARIA cipher in CCM mode.
var ARIA256CCM = CipherCCM{
    cipherFunc:   aria.NewCipher,
    keySize:      32,
    nonceSize:    12,
    identifier:   oidARIA256CCM,
    hasKeyLength: false,
}

// ==========

// Misty1CBC is the 168-bit key Misty1 cipher in CBC mode.
var Misty1CBC = CipherCBC{
    cipherFunc:   misty1.NewCipher,
    keySize:      16,
    blockSize:    misty1.BlockSize,
    identifier:   oidMisty1CBC,
    hasKeyLength: false,
}

// ==========

// SeedECB is the 128-bit key Seed cipher in ECB mode.
var SeedECB = CipherECB{
    cipherFunc:   seed.NewCipher,
    keySize:      16,
    blockSize:    seed.BlockSize,
    identifier:   oidSeedECB,
    hasKeyLength: true,
}
// SeedCBC is the 128-bit key Seed cipher in CBC mode.
var SeedCBC = CipherCBC{
    cipherFunc:   seed.NewCipher,
    keySize:      16,
    blockSize:    seed.BlockSize,
    identifier:   oidSeedCBC,
    hasKeyLength: true,
}
// SeedOFB is the 128-bit key Seed cipher in OFB mode.
var SeedOFB = CipherOFB{
    cipherFunc:   seed.NewCipher,
    keySize:      16,
    blockSize:    seed.BlockSize,
    identifier:   oidSeedOFB,
    hasKeyLength: true,
}
// SeedCFB is the 128-bit key Seed cipher in CFB mode.
var SeedCFB = CipherCFB{
    cipherFunc:   seed.NewCipher,
    keySize:      16,
    blockSize:    seed.BlockSize,
    identifier:   oidSeedCFB,
    hasKeyLength: true,
}

// Seed is the 256-bit key Seed cipher in ECB mode.
var Seed256ECB = SeedECB.WithKeySize(32)
var Seed256CBC = SeedCBC.WithKeySize(32)
var Seed256OFB = SeedOFB.WithKeySize(32)
var Seed256CFB = SeedCFB.WithKeySize(32)

// ==========

// Serpent128ECB is the 128-bit key Serpent cipher in ECB mode.
var Serpent128ECB = CipherECB{
    cipherFunc:   serpent.NewCipher,
    keySize:      16,
    blockSize:    serpent.BlockSize,
    identifier:   oidSerpent128ECB,
    hasKeyLength: false,
}
// Serpent128CBC is the 128-bit key Serpent cipher in CBC mode.
var Serpent128CBC = CipherCBC{
    cipherFunc:   serpent.NewCipher,
    keySize:      16,
    blockSize:    serpent.BlockSize,
    identifier:   oidSerpent128CBC,
    hasKeyLength: false,
}
// Serpent128OFB is the 128-bit key Serpent cipher in OFB mode.
var Serpent128OFB = CipherOFB{
    cipherFunc:   serpent.NewCipher,
    keySize:      16,
    blockSize:    serpent.BlockSize,
    identifier:   oidSerpent128OFB,
    hasKeyLength: false,
}
// Serpent128CFB is the 128-bit key Serpent cipher in CFB mode.
var Serpent128CFB = CipherCFB{
    cipherFunc:   serpent.NewCipher,
    keySize:      16,
    blockSize:    serpent.BlockSize,
    identifier:   oidSerpent128CFB,
    hasKeyLength: false,
}

// ==========

// Serpent192ECB is the 192-bit key Serpent cipher in ECB mode.
var Serpent192ECB = CipherECB{
    cipherFunc:   serpent.NewCipher,
    keySize:      24,
    blockSize:    serpent.BlockSize,
    identifier:   oidSerpent192ECB,
    hasKeyLength: false,
}
// Serpent192CBC is the 192-bit key Serpent cipher in CBC mode.
var Serpent192CBC = CipherCBC{
    cipherFunc:   serpent.NewCipher,
    keySize:      24,
    blockSize:    serpent.BlockSize,
    identifier:   oidSerpent192CBC,
    hasKeyLength: false,
}
// Serpent192OFB is the 192-bit key Serpent cipher in OFB mode.
var Serpent192OFB = CipherOFB{
    cipherFunc:   serpent.NewCipher,
    keySize:      24,
    blockSize:    serpent.BlockSize,
    identifier:   oidSerpent192OFB,
    hasKeyLength: false,
}
// Serpent192CFB is the 192-bit key Serpent cipher in CFB mode.
var Serpent192CFB = CipherCFB{
    cipherFunc:   serpent.NewCipher,
    keySize:      24,
    blockSize:    serpent.BlockSize,
    identifier:   oidSerpent192CFB,
    hasKeyLength: false,
}

// ==========

// Serpent256ECB is the 256-bit key Serpent cipher in ECB mode.
var Serpent256ECB = CipherECB{
    cipherFunc:   serpent.NewCipher,
    keySize:      32,
    blockSize:    serpent.BlockSize,
    identifier:   oidSerpent256ECB,
    hasKeyLength: false,
}
// Serpent256CBC is the 256-bit key Serpent cipher in CBC mode.
var Serpent256CBC = CipherCBC{
    cipherFunc:   serpent.NewCipher,
    keySize:      32,
    blockSize:    serpent.BlockSize,
    identifier:   oidSerpent256CBC,
    hasKeyLength: false,
}
// Serpent256OFB is the 256-bit key Serpent cipher in OFB mode.
var Serpent256OFB = CipherOFB{
    cipherFunc:   serpent.NewCipher,
    keySize:      32,
    blockSize:    serpent.BlockSize,
    identifier:   oidSerpent256OFB,
    hasKeyLength: false,
}
// Serpent256CFB is the 256-bit key Serpent cipher in CFB mode.
var Serpent256CFB = CipherCFB{
    cipherFunc:   serpent.NewCipher,
    keySize:      32,
    blockSize:    serpent.BlockSize,
    identifier:   oidSerpent256CFB,
    hasKeyLength: false,
}

func init() {
    // des
    AddCipher(oidDESCBC, func() Cipher {
        return DESCBC
    })
    AddCipher(oidDESEDE3CBC, func() Cipher {
        return DESEDE3CBC
    })
    AddCipher(oidRC2CBC, func() Cipher {
        return RC2CBC
    })
    AddCipher(oidRC5CBCPad, func() Cipher {
        return RC5CBC
    })

    // aes-128
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

    // aes-192
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

    // aes-256
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
    AddCipher(oidSM4CFB1, func() Cipher {
        return SM4CFB1
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

    // Gost
    AddCipher(oidGostCipher, func() Cipher {
        return GostCipher
    })

    // aria-128
    AddCipher(oidARIA128ECB, func() Cipher {
        return ARIA128ECB
    })
    AddCipher(oidARIA128CBC, func() Cipher {
        return ARIA128CBC
    })
    AddCipher(oidARIA128CFB, func() Cipher {
        return ARIA128CFB
    })
    AddCipher(oidARIA128OFB, func() Cipher {
        return ARIA128OFB
    })
    AddCipher(oidARIA128CTR, func() Cipher {
        return ARIA128CTR
    })
    AddCipher(oidARIA128GCM, func() Cipher {
        return ARIA128GCM
    })
    AddCipher(oidARIA128CCM, func() Cipher {
        return ARIA128CCM
    })

    // aria-192
    AddCipher(oidARIA192ECB, func() Cipher {
        return ARIA192ECB
    })
    AddCipher(oidARIA192CBC, func() Cipher {
        return ARIA192CBC
    })
    AddCipher(oidARIA192CFB, func() Cipher {
        return ARIA192CFB
    })
    AddCipher(oidARIA192OFB, func() Cipher {
        return ARIA192OFB
    })
    AddCipher(oidARIA192CTR, func() Cipher {
        return ARIA192CTR
    })
    AddCipher(oidARIA192GCM, func() Cipher {
        return ARIA192GCM
    })
    AddCipher(oidARIA192CCM, func() Cipher {
        return ARIA192CCM
    })

    // aria-256
    AddCipher(oidARIA256ECB, func() Cipher {
        return ARIA256ECB
    })
    AddCipher(oidARIA256CBC, func() Cipher {
        return ARIA256CBC
    })
    AddCipher(oidARIA256CFB, func() Cipher {
        return ARIA256CFB
    })
    AddCipher(oidARIA256OFB, func() Cipher {
        return ARIA256OFB
    })
    AddCipher(oidARIA256CTR, func() Cipher {
        return ARIA256CTR
    })
    AddCipher(oidARIA256GCM, func() Cipher {
        return ARIA256GCM
    })
    AddCipher(oidARIA256CCM, func() Cipher {
        return ARIA256CCM
    })

    // Misty1
    AddCipher(oidMisty1CBC, func() Cipher {
        return Misty1CBC
    })

    // serpent-128
    AddCipher(oidSerpent128ECB, func() Cipher {
        return Serpent128ECB
    })
    AddCipher(oidSerpent128CBC, func() Cipher {
        return Serpent128CBC
    })
    AddCipher(oidSerpent128OFB, func() Cipher {
        return Serpent128OFB
    })
    AddCipher(oidSerpent128CFB, func() Cipher {
        return Serpent128CFB
    })

    // serpent-192
    AddCipher(oidSerpent192ECB, func() Cipher {
        return Serpent192ECB
    })
    AddCipher(oidSerpent192CBC, func() Cipher {
        return Serpent192CBC
    })
    AddCipher(oidSerpent192OFB, func() Cipher {
        return Serpent192OFB
    })
    AddCipher(oidSerpent192CFB, func() Cipher {
        return Serpent192CFB
    })

    // serpent-256
    AddCipher(oidSerpent256ECB, func() Cipher {
        return Serpent256ECB
    })
    AddCipher(oidSerpent256CBC, func() Cipher {
        return Serpent256CBC
    })
    AddCipher(oidSerpent256OFB, func() Cipher {
        return Serpent256OFB
    })
    AddCipher(oidSerpent256CFB, func() Cipher {
        return Serpent256CFB
    })

    // seed-256
    AddCipher(oidSeedECB, func() Cipher {
        return SeedECB
    })
    AddCipher(oidSeedCBC, func() Cipher {
        return SeedCBC
    })
    AddCipher(oidSeedOFB, func() Cipher {
        return SeedOFB
    })
    AddCipher(oidSeedCFB, func() Cipher {
        return SeedCFB
    })
}
