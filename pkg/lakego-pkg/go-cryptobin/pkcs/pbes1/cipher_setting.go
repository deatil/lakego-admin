package pbes1

import (
    "crypto/des"
    "crypto/md5"
    "crypto/sha1"
    "crypto/cipher"
    "encoding/asn1"

    "golang.org/x/crypto/cast5"
    "golang.org/x/crypto/twofish"

    cryptobin_md2 "github.com/deatil/go-cryptobin/hash/md2"
    cryptobin_rc2 "github.com/deatil/go-cryptobin/cipher/rc2"
    cryptobin_des "github.com/deatil/go-cryptobin/cipher/des"
)

var (
    // pkcs12
    oidPbeWithSHA1AndRC4_128 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 1}
    oidPbeWithSHA1AndRC4_40  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 2}
    oidPbeWithSHA1And3DES    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
    oidPbeWithSHA1And2DES    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 4}
    oidPbeWithSHA1AndRC2_128 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}
    oidPbeWithSHA1AndRC2_40  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}

    oidPbeWithMD5AndCAST5   = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 12}
    oidPbeWithSHAAndTwofish = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 21}

    // PBES1
    oidPbeWithMD2AndDES      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 1}
    oidPbeWithMD2AndRC2_64   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 4}
    oidPbeWithMD5AndDES      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}
    oidPbeWithMD5AndRC2_64   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 6}
    oidPbeWithSHA1AndDES     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 10}
    oidPbeWithSHA1AndRC2_64  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 11}
)

var (
    newRC2Cipher = func(key []byte) (cipher.Block, error) {
        return cryptobin_rc2.NewCipher(key, len(key)*8)
    }
    newCAST5Cipher = func(key []byte) (cipher.Block, error) {
        return cast5.NewCipher(key)
    }
    newTwofishCipher = func(key []byte) (cipher.Block, error) {
        return twofish.NewCipher(key)
    }
)

// pkcs12
var SHA1AndRC4_128 = CipherRC4{
    hashFunc:       sha1.New,
    derivedKeyFunc: DerivedKeyPkcs12,
    saltSize:       20,
    keySize:        16,
    blockSize:      16,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndRC4_128,
    hasKeyLength:   false,
    needBmpPass:    true,
}
var SHA1AndRC4_40 = CipherRC4{
    hashFunc:       sha1.New,
    derivedKeyFunc: DerivedKeyPkcs12,
    saltSize:       20,
    keySize:        5,
    blockSize:      5,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndRC4_40,
    hasKeyLength:   false,
    needBmpPass:    true,
}
var SHA1And3DES = CipherBlockCBC{
    cipherFunc:     des.NewTripleDESCipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: DerivedKeyPkcs12,
    saltSize:       des.BlockSize,
    keySize:        24,
    blockSize:      des.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1And3DES,
    hasKeyLength:   false,
    needBmpPass:    true,
}
var SHA1And2DES = CipherBlockCBC{
    cipherFunc:     cryptobin_des.NewTwoDESCipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: DerivedKeyPkcs12,
    saltSize:       cryptobin_des.BlockSize,
    keySize:        16,
    blockSize:      cryptobin_des.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1And2DES,
    hasKeyLength:   false,
    needBmpPass:    true,
}
var SHA1AndRC2_128 = CipherBlockCBC{
    cipherFunc:     newRC2Cipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: DerivedKeyPkcs12,
    saltSize:       20,
    keySize:        16,
    blockSize:      cryptobin_rc2.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndRC2_128,
    hasKeyLength:   false,
    needBmpPass:    true,
}
var SHA1AndRC2_40 = CipherBlockCBC{
    cipherFunc:     newRC2Cipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: DerivedKeyPkcs12,
    saltSize:       20,
    keySize:        5,
    blockSize:      cryptobin_rc2.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndRC2_40,
    hasKeyLength:   false,
    needBmpPass:    true,
}

var MD5AndCAST5 = CipherBlockCBC{
    cipherFunc:     newCAST5Cipher,
    hashFunc:       md5.New,
    derivedKeyFunc: DerivedKeyPkcs12,
    saltSize:       cast5.BlockSize,
    keySize:        16,
    blockSize:      cast5.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithMD5AndCAST5,
    hasKeyLength:   false,
    needBmpPass:    true,
}
// use 32 bytes key length
var SHAAndTwofish = CipherBlockCBC{
    cipherFunc:     newTwofishCipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: DerivedKeyPkcs12,
    saltSize:       twofish.BlockSize,
    keySize:        32,
    blockSize:      twofish.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHAAndTwofish,
    hasKeyLength:   false,
    needBmpPass:    true,
}

// PBES1
var MD2AndDES = CipherBlockCBC{
    cipherFunc:     des.NewCipher,
    hashFunc:       cryptobin_md2.New,
    derivedKeyFunc: DerivedKeyPbkdf1,
    saltSize:       des.BlockSize,
    keySize:        8,
    blockSize:      des.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithMD2AndDES,
    hasKeyLength:   false,
    needBmpPass:    false,
}
var MD2AndRC2_64 = CipherBlockCBC{
    cipherFunc:     newRC2Cipher,
    hashFunc:       cryptobin_md2.New,
    derivedKeyFunc: DerivedKeyPbkdf1,
    saltSize:       20,
    keySize:        8,
    blockSize:      cryptobin_rc2.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithMD2AndRC2_64,
    hasKeyLength:   false,
    needBmpPass:    false,
}
var MD5AndDES = CipherBlockCBC{
    cipherFunc:     des.NewCipher,
    hashFunc:       md5.New,
    derivedKeyFunc: DerivedKeyPbkdf1,
    saltSize:       des.BlockSize,
    keySize:        8,
    blockSize:      des.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithMD5AndDES,
    hasKeyLength:   false,
    needBmpPass:    false,
}
var MD5AndRC2_64 = CipherBlockCBC{
    cipherFunc:     newRC2Cipher,
    hashFunc:       md5.New,
    derivedKeyFunc: DerivedKeyPbkdf1,
    saltSize:       20,
    keySize:        8,
    blockSize:      cryptobin_rc2.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithMD5AndRC2_64,
    hasKeyLength:   false,
    needBmpPass:    false,
}
var SHA1AndDES = CipherBlockCBC{
    cipherFunc:     des.NewCipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: DerivedKeyPbkdf1,
    saltSize:       des.BlockSize,
    keySize:        8,
    blockSize:      des.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndDES,
    hasKeyLength:   false,
    needBmpPass:    false,
}
var SHA1AndRC2_64 = CipherBlockCBC{
    cipherFunc:     newRC2Cipher,
    hashFunc:       sha1.New,
    derivedKeyFunc: DerivedKeyPbkdf1,
    saltSize:       20,
    keySize:        8,
    blockSize:      cryptobin_rc2.BlockSize,
    iterationCount: 2048,
    oid:            oidPbeWithSHA1AndRC2_64,
    hasKeyLength:   false,
    needBmpPass:    false,
}

func init() {
    // pkcs12
    AddCipher(oidPbeWithSHA1And3DES, func() Cipher {
        return SHA1And3DES
    })
    AddCipher(oidPbeWithSHA1And2DES, func() Cipher {
        return SHA1And2DES
    })
    AddCipher(oidPbeWithSHA1AndRC2_128, func() Cipher {
        return SHA1AndRC2_128
    })
    AddCipher(oidPbeWithSHA1AndRC2_40, func() Cipher {
        return SHA1AndRC2_40
    })
    AddCipher(oidPbeWithSHA1AndRC4_128, func() Cipher {
        return SHA1AndRC4_128
    })
    AddCipher(oidPbeWithSHA1AndRC4_40, func() Cipher {
        return SHA1AndRC4_40
    })

    AddCipher(oidPbeWithMD5AndCAST5, func() Cipher {
        return MD5AndCAST5
    })
    AddCipher(oidPbeWithSHAAndTwofish, func() Cipher {
        return SHAAndTwofish
    })

    // PBES1
    AddCipher(oidPbeWithMD2AndDES, func() Cipher {
        return MD2AndDES
    })
    AddCipher(oidPbeWithMD2AndRC2_64, func() Cipher {
        return MD2AndRC2_64
    })
    AddCipher(oidPbeWithMD5AndDES, func() Cipher {
        return MD5AndDES
    })
    AddCipher(oidPbeWithMD5AndRC2_64, func() Cipher {
        return MD5AndRC2_64
    })
    AddCipher(oidPbeWithSHA1AndDES, func() Cipher {
        return SHA1AndDES
    })
    AddCipher(oidPbeWithSHA1AndRC2_64, func() Cipher {
        return SHA1AndRC2_64
    })

}
