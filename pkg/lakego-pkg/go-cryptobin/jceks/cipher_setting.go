package jceks

import (
    "crypto/des"
    "crypto/md5"
    "crypto/sha1"
    "crypto/cipher"
    "encoding/asn1"

    "golang.org/x/crypto/twofish"
)

var (
    oidPbeWithMD5And3DES     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 19, 1}
    oidPbeWithSHA1And3DES    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
)

var (
    newTwofishCipher = func(key []byte) (cipher.Block, error) {
        return twofish.NewCipher(key)
    }
)

var CipherMD5And3DES = CipherBlockCBC{
    cipherFunc:     des.NewTripleDESCipher,
    hashFunc:       md5.New,
    derivedKeyFunc: derivedKey,
    saltSize:       des.BlockSize,
    keySize:        24,
    blockSize:      des.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithMD5And3DES,
}
var CipherSHA1And3DES = CipherBlockCBC{
    cipherFunc:     des.NewTripleDESCipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: derivedKey,
    saltSize:       des.BlockSize,
    keySize:        24,
    blockSize:      des.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1And3DES,
}

// bks 使用
var CipherSHA1And3DESForBKS = CipherBlockCBC{
    cipherFunc:     des.NewTripleDESCipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: derivedKeyWithPbkdf,
    saltSize:       des.BlockSize,
    keySize:        24,
    blockSize:      8,
    iterationCount: 2048,
}
var CipherSHA1AndTwofishForUBER = CipherBlockCBC{
    cipherFunc:     newTwofishCipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: derivedKeyWithPbkdf,
    saltSize:       16,
    keySize:        32,
    blockSize:      twofish.BlockSize,
    iterationCount: 2048,
}

func init() {
    AddCipher(oidPbeWithMD5And3DES, func() Cipher {
        return CipherMD5And3DES
    })
    AddCipher(oidPbeWithSHA1And3DES, func() Cipher {
        return CipherSHA1And3DES
    })
}
