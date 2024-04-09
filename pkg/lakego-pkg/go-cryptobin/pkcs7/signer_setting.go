package pkcs7

import (
    "crypto"
    _ "crypto/md5"
    _ "crypto/sha1"
    _ "crypto/sha256"
    _ "crypto/sha512"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/hash/sm3"
)

var (
    // dsa 签名
    OidEncryptionAlgorithmDSA       = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
    OidEncryptionAlgorithmDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
    OidEncryptionAlgorithmDSASHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 1}
    OidEncryptionAlgorithmDSASHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}

    // ecdsa 签名
    OidEncryptionAlgorithmECDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
    OidEncryptionAlgorithmECDSASHA224 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}
    OidEncryptionAlgorithmECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
    OidEncryptionAlgorithmECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
    OidEncryptionAlgorithmECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

    OidEncryptionAlgorithmECDSAP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
    OidEncryptionAlgorithmECDSAP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
    OidEncryptionAlgorithmECDSAP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

    // rsa 签名
    OidEncryptionAlgorithmRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
    OidEncryptionAlgorithmRSAMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
    OidEncryptionAlgorithmRSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
    OidEncryptionAlgorithmRSASHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}
    OidEncryptionAlgorithmRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
    OidEncryptionAlgorithmRSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
    OidEncryptionAlgorithmRSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
    OidEncryptionAlgorithmRSASM3    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 504}

    // eddsa 签名
    OidEncryptionAlgorithmEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

    // sm2 签名
    OidEncryptionAlgorithmSM2SM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
    OidDigestEncryptionAlgorithmSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}

    // sm9 签名
    OidDigestAlgorithmSM9SM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502}
    OidDigestEncryptionAlgorithmSM9 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302, 1}
)

var KeySignWithDSASHA1 = KeySignWithDSA{
    hashFunc:   crypto.SHA1,
    hashId:     OidDigestAlgorithmSHA1,
    identifier: OidEncryptionAlgorithmDSASHA1,
}
var KeySignWithDSASHA224 = KeySignWithDSA{
    hashFunc:   crypto.SHA224,
    hashId:     OidDigestAlgorithmSHA224,
    identifier: OidEncryptionAlgorithmDSASHA224,
}
var KeySignWithDSASHA256 = KeySignWithDSA{
    hashFunc:   crypto.SHA256,
    hashId:     OidDigestAlgorithmSHA256,
    identifier: OidEncryptionAlgorithmDSASHA256,
}

var KeySignWithECDSASHA1 = KeySignWithECDSA{
    hashFunc:   crypto.SHA1,
    hashId:     OidDigestAlgorithmSHA1,
    identifier: OidEncryptionAlgorithmECDSASHA1,
}
var KeySignWithECDSASHA224 = KeySignWithECDSA{
    hashFunc:   crypto.SHA224,
    hashId:     OidDigestAlgorithmSHA224,
    identifier: OidEncryptionAlgorithmECDSASHA224,
}
var KeySignWithECDSASHA256 = KeySignWithECDSA{
    hashFunc:   crypto.SHA256,
    hashId:     OidDigestAlgorithmSHA256,
    identifier: OidEncryptionAlgorithmECDSASHA256,
}
var KeySignWithECDSASHA384 = KeySignWithECDSA{
    hashFunc:   crypto.SHA384,
    hashId:     OidDigestAlgorithmSHA384,
    identifier: OidEncryptionAlgorithmECDSASHA384,
}
var KeySignWithECDSASHA512 = KeySignWithECDSA{
    hashFunc:   crypto.SHA512,
    hashId:     OidDigestAlgorithmSHA512,
    identifier: OidEncryptionAlgorithmECDSASHA512,
}

var KeySignWithRSAMD5 = KeySignWithRSA{
    hashFunc:   crypto.MD5,
    hashId:     OidDigestAlgorithmMD5,
    identifier: OidEncryptionAlgorithmRSAMD5,
}
var KeySignWithRSASHA1 = KeySignWithRSA{
    hashFunc:   crypto.SHA1,
    hashId:     OidDigestAlgorithmSHA1,
    identifier: OidEncryptionAlgorithmRSASHA1,
}
var KeySignWithRSASHA224 = KeySignWithRSA{
    hashFunc:   crypto.SHA224,
    hashId:     OidDigestAlgorithmSHA224,
    identifier: OidEncryptionAlgorithmRSASHA224,
}
var KeySignWithRSASHA256 = KeySignWithRSA{
    hashFunc:   crypto.SHA256,
    hashId:     OidDigestAlgorithmSHA256,
    identifier: OidEncryptionAlgorithmRSASHA256,
}
var KeySignWithRSASHA384 = KeySignWithRSA{
    hashFunc:   crypto.SHA384,
    hashId:     OidDigestAlgorithmSHA384,
    identifier: OidEncryptionAlgorithmRSASHA384,
}
var KeySignWithRSASHA512 = KeySignWithRSA{
    hashFunc:   crypto.SHA512,
    hashId:     OidDigestAlgorithmSHA512,
    identifier: OidEncryptionAlgorithmRSASHA512,
}

var KeySignWithEdDSASHA1 = KeySignWithEdDSA{
    hashFunc:   crypto.SHA1,
    hashId:     OidDigestAlgorithmSHA1,
    identifier: OidEncryptionAlgorithmEd25519,
}

var KeySignWithSM2SM3 = KeySignWithSM2{
    hashFunc:   sm3.New,
    hashId:     OidDigestAlgorithmSM3,
    identifier: OidEncryptionAlgorithmSM2SM3,
}
var KeySignWithSM2WithSM3 = KeySignWithSM2{
    hashFunc:   sm3.New,
    hashId:     OidDigestAlgorithmSM3,
    identifier: OidDigestEncryptionAlgorithmSM2,
}

func init() {
    // DSA
    AddKeySign(OidEncryptionAlgorithmDSASHA1, func() KeySign {
        return KeySignWithDSASHA1
    })
    AddKeySign(OidEncryptionAlgorithmDSASHA224, func() KeySign {
        return KeySignWithDSASHA224
    })
    AddKeySign(OidEncryptionAlgorithmDSASHA256, func() KeySign {
        return KeySignWithDSASHA256
    })

    // ECDSA
    AddKeySign(OidEncryptionAlgorithmECDSASHA1, func() KeySign {
        return KeySignWithECDSASHA1
    })
    AddKeySign(OidEncryptionAlgorithmECDSASHA224, func() KeySign {
        return KeySignWithECDSASHA224
    })
    AddKeySign(OidEncryptionAlgorithmECDSASHA256, func() KeySign {
        return KeySignWithECDSASHA256
    })
    AddKeySign(OidEncryptionAlgorithmECDSASHA384, func() KeySign {
        return KeySignWithECDSASHA384
    })
    AddKeySign(OidEncryptionAlgorithmECDSASHA512, func() KeySign {
        return KeySignWithECDSASHA512
    })

    // RSA
    AddKeySign(OidEncryptionAlgorithmRSAMD5, func() KeySign {
        return KeySignWithRSAMD5
    })
    AddKeySign(OidEncryptionAlgorithmRSASHA1, func() KeySign {
        return KeySignWithRSASHA1
    })
    AddKeySign(OidEncryptionAlgorithmRSASHA224, func() KeySign {
        return KeySignWithRSASHA224
    })
    AddKeySign(OidEncryptionAlgorithmRSASHA256, func() KeySign {
        return KeySignWithRSASHA256
    })
    AddKeySign(OidEncryptionAlgorithmRSASHA384, func() KeySign {
        return KeySignWithRSASHA384
    })
    AddKeySign(OidEncryptionAlgorithmRSASHA512, func() KeySign {
        return KeySignWithRSASHA512
    })

    // EdDSA
    AddKeySign(OidEncryptionAlgorithmEd25519, func() KeySign {
        return KeySignWithEdDSASHA1
    })

    // SM2
    AddKeySign(OidEncryptionAlgorithmSM2SM3, func() KeySign {
        return KeySignWithSM2SM3
    })
    AddKeySign(oidDigestEncryptionAlgorithmSM2, func() KeySign {
        return KeySignWithSM2WithSM3
    })
}

