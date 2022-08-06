package pkcs8pbe

import (
    "crypto/rc4"
    "crypto/des"
    "crypto/md5"
    "crypto/sha1"
    "encoding/asn1"
)

var (
    oidPbeWithMD5AndDES      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}
    oidPbeWithSHA1AndDES     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 10}
    oidPbeWithSHA1And3DES    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
    oidPbeWithSHA1AndRC4_128 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 1}
    oidPbeWithSHA1AndRC4_40  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 2}
)

var PEMCipherMD5AndDES = CipherBlockCBC{
    cipherFunc:     des.NewCipher,
    hashFunc:       md5.New,
    derivedKeyFunc: derivedKey,
    keySize:        8,
    blockSize:      des.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithMD5AndDES,
}

var PEMCipherSHA1AndDES = CipherBlockCBC{
    cipherFunc:     des.NewCipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: derivedKey,
    keySize:        8,
    blockSize:      des.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndDES,
}

var PEMCipherSHA1And3DES = CipherBlockCBC{
    cipherFunc:     des.NewTripleDESCipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: derivedKey2,
    keySize:        24,
    blockSize:      des.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1And3DES,
}

var PEMCipherSHA1AndRC4_128 = CipherRC4{
    cipherFunc:     rc4.NewCipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: derivedKey,
    keySize:        16,
    blockSize:      16,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndRC4_128,
}

var PEMCipherSHA1AndRC4_40 = CipherRC4{
    cipherFunc:     rc4.NewCipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: derivedKey,
    keySize:        5,
    blockSize:      5,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndRC4_40,
}

func init() {
    AddCipher(oidPbeWithMD5AndDES, PEMCipherMD5AndDES)
    AddCipher(oidPbeWithSHA1AndDES, PEMCipherSHA1AndDES)
    AddCipher(oidPbeWithSHA1And3DES, PEMCipherSHA1And3DES)
    AddCipher(oidPbeWithSHA1AndRC4_128, PEMCipherSHA1AndRC4_128)
    AddCipher(oidPbeWithSHA1AndRC4_40, PEMCipherSHA1AndRC4_40)
}
