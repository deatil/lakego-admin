package pkcs8

import (
    "crypto/aes"
    "crypto/des"
    "encoding/asn1"
)

var (
    // 加密方式
    oidEncryptionAlgorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 3}
    oidDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
    oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}

    oidAES       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1}
    oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
    oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
    oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

var DESCBC = CipherBlock{
    cipherFunc: des.NewCipher,
    keySize:    8,
    blockSize:  des.BlockSize,
    identifier: oidDESCBC,
}

var DESEDE3CBC = CipherBlock{
    cipherFunc: des.NewTripleDESCipher,
    keySize:    24,
    blockSize:  des.BlockSize,
    identifier: oidDESEDE3CBC,
}

var AES128CBC = CipherBlock{
    cipherFunc: aes.NewCipher,
    keySize:    16,
    blockSize:  aes.BlockSize,
    identifier: oidAES128CBC,
}

var AES192CBC = CipherBlock{
    cipherFunc: aes.NewCipher,
    keySize:    24,
    blockSize:  aes.BlockSize,
    identifier: oidAES192CBC,
}

var AES256CBC = CipherBlock{
    cipherFunc: aes.NewCipher,
    keySize:    32,
    blockSize:  aes.BlockSize,
    identifier: oidAES256CBC,
}

func init() {
    AddCipher(oidDESCBC, DESCBC)
    AddCipher(oidDESEDE3CBC, DESEDE3CBC)
    AddCipher(oidAES128CBC, AES128CBC)
    AddCipher(oidAES192CBC, AES192CBC)
    AddCipher(oidAES256CBC, AES256CBC)
}
