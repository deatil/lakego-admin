package jceks

import (
    "crypto/des"
    "crypto/md5"
    "crypto/sha1"
    "encoding/asn1"
)

var (
    oidPbeWithMD5And3DES  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 19, 1}
    oidPbeWithSHA1And3DES = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
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

func init() {
    AddCipher(oidPbeWithMD5And3DES, func() Cipher {
        return CipherMD5And3DES
    })
    AddCipher(oidPbeWithSHA1And3DES, func() Cipher {
        return CipherSHA1And3DES
    })
}
