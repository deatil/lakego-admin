package pkcs12

import (
    "crypto/des"
    "crypto/sha1"
    "crypto/cipher"
    "encoding/asn1"

    cryptobin_rc2 "github.com/deatil/go-cryptobin/cipher/rc2"
)

var (
    oidPbeWithSHA1And3DES    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
    oidPbeWithSHA1AndRC2_128 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}
    oidPbeWithSHA1AndRC2_40  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}
    oidPbeWithSHA1AndRC4_128 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 1}
    oidPbeWithSHA1AndRC4_40  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 2}
)

var (
    newRC2Cipher = func(key []byte) (cipher.Block, error) {
        return cryptobin_rc2.NewCipher(key, len(key)*8)
    }
)

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
var CipherSHA1AndRC2_128 = CipherBlockCBC{
    cipherFunc:     newRC2Cipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: derivedKey,
    saltSize:       20,
    keySize:        16,
    blockSize:      cryptobin_rc2.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndRC2_128,
}
var CipherSHA1AndRC2_40 = CipherBlockCBC{
    cipherFunc:     newRC2Cipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: derivedKey,
    saltSize:       20,
    keySize:        5,
    blockSize:      cryptobin_rc2.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndRC2_40,
}

var CipherSHA1AndRC4_128 = CipherRC4{
    hashFunc:       sha1.New,
    derivedKeyFunc: derivedKey,
    saltSize:       20,
    keySize:        16,
    blockSize:      16,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndRC4_128,
}
var CipherSHA1AndRC4_40 = CipherRC4{
    hashFunc:       sha1.New,
    derivedKeyFunc: derivedKey,
    saltSize:       20,
    keySize:        5,
    blockSize:      5,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndRC4_40,
}

func init() {
    AddCipher(oidPbeWithSHA1And3DES, func() Cipher {
        return CipherSHA1And3DES
    })
    AddCipher(oidPbeWithSHA1AndRC2_128, func() Cipher {
        return CipherSHA1AndRC2_128
    })
    AddCipher(oidPbeWithSHA1AndRC2_40, func() Cipher {
        return CipherSHA1AndRC2_40
    })

    AddCipher(oidPbeWithSHA1AndRC4_128, func() Cipher {
        return CipherSHA1AndRC4_128
    })
    AddCipher(oidPbeWithSHA1AndRC4_40, func() Cipher {
        return CipherSHA1AndRC4_40
    })
}
