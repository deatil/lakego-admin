package sign

import (
    "crypto"
    _ "crypto/md5"
    _ "crypto/sha1"
    _ "crypto/sha256"
    _ "crypto/sha512"
    "encoding/asn1"

    "github.com/tjfoc/gmsm/sm3"
)

var (
    // dsa 签名
    oidDigestAlgorithmDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
    oidDigestAlgorithmDSASHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 1}
    oidDigestAlgorithmDSASHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}

    // ecdsa 签名
    oidDigestAlgorithmECDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
    oidDigestAlgorithmECDSASHA224 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}
    oidDigestAlgorithmECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
    oidDigestAlgorithmECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
    oidDigestAlgorithmECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

    // rsa 签名
    oidDigestAlgorithmRSAMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
    oidDigestAlgorithmRSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
    oidDigestAlgorithmRSASHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}
    oidDigestAlgorithmRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
    oidDigestAlgorithmRSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
    oidDigestAlgorithmRSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
    oidDigestAlgorithmRSASM3    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 504}

    // eddsa 签名
    oidDigestAlgorithmEd25519   = asn1.ObjectIdentifier{1, 3, 101, 112}

    // sm2 签名
    oidDigestAlgorithmSM2SM3    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
)

var KeySignWithDSASHA1 = KeySignWithDSA{
    hashFunc:   crypto.SHA1,
    hashId:     oidDigestAlgorithmSHA1,
    identifier: oidDigestAlgorithmDSASHA1,
}
var KeySignWithDSASHA224 = KeySignWithDSA{
    hashFunc:   crypto.SHA224,
    hashId:     oidDigestAlgorithmSHA224,
    identifier: oidDigestAlgorithmDSASHA224,
}
var KeySignWithDSASHA256 = KeySignWithDSA{
    hashFunc:   crypto.SHA256,
    hashId:     oidDigestAlgorithmSHA256,
    identifier: oidDigestAlgorithmDSASHA256,
}

var KeySignWithEcdsaSHA1 = KeySignWithEcdsa{
    hashFunc:   crypto.SHA1,
    hashId:     oidDigestAlgorithmSHA1,
    identifier: oidDigestAlgorithmECDSASHA1,
}
var KeySignWithEcdsaSHA224 = KeySignWithEcdsa{
    hashFunc:   crypto.SHA224,
    hashId:     oidDigestAlgorithmSHA224,
    identifier: oidDigestAlgorithmECDSASHA224,
}
var KeySignWithEcdsaSHA256 = KeySignWithEcdsa{
    hashFunc:   crypto.SHA256,
    hashId:     oidDigestAlgorithmSHA256,
    identifier: oidDigestAlgorithmECDSASHA256,
}
var KeySignWithEcdsaSHA384 = KeySignWithEcdsa{
    hashFunc:   crypto.SHA384,
    hashId:     oidDigestAlgorithmSHA384,
    identifier: oidDigestAlgorithmECDSASHA384,
}
var KeySignWithEcdsaSHA512 = KeySignWithEcdsa{
    hashFunc:   crypto.SHA512,
    hashId:     oidDigestAlgorithmSHA512,
    identifier: oidDigestAlgorithmECDSASHA512,
}

var KeySignWithRsaMD5 = KeySignWithRsa{
    hashFunc:   crypto.MD5,
    hashId:     oidDigestAlgorithmMd5,
    identifier: oidDigestAlgorithmRSAMD5,
}
var KeySignWithRsaSHA1 = KeySignWithRsa{
    hashFunc:   crypto.SHA1,
    hashId:     oidDigestAlgorithmSHA1,
    identifier: oidDigestAlgorithmRSASHA1,
}
var KeySignWithRsaSHA224 = KeySignWithRsa{
    hashFunc:   crypto.SHA224,
    hashId:     oidDigestAlgorithmSHA224,
    identifier: oidDigestAlgorithmRSASHA224,
}
var KeySignWithRsaSHA256 = KeySignWithRsa{
    hashFunc:   crypto.SHA256,
    hashId:     oidDigestAlgorithmSHA256,
    identifier: oidDigestAlgorithmRSASHA256,
}
var KeySignWithRsaSHA384 = KeySignWithRsa{
    hashFunc:   crypto.SHA384,
    hashId:     oidDigestAlgorithmSHA384,
    identifier: oidDigestAlgorithmRSASHA384,
}
var KeySignWithRsaSHA512 = KeySignWithRsa{
    hashFunc:   crypto.SHA512,
    hashId:     oidDigestAlgorithmSHA512,
    identifier: oidDigestAlgorithmRSASHA512,
}

var KeySignWithEdDsaSHA1 = KeySignWithRsa{
    hashFunc:   crypto.SHA1,
    hashId:     oidDigestAlgorithmSHA1,
    identifier: oidDigestAlgorithmEd25519,
}

var KeySignWithSM2SM3 = KeySignWithSM2{
    hashFunc:   sm3.New,
    hashId:     oidDigestAlgorithmSM3,
    identifier: oidDigestAlgorithmSM2SM3,
}

func init() {
    AddKeySign(oidDigestAlgorithmDSASHA1, func() KeySign {
        return KeySignWithDSASHA1
    })
    AddKeySign(oidDigestAlgorithmDSASHA224, func() KeySign {
        return KeySignWithDSASHA224
    })
    AddKeySign(oidDigestAlgorithmDSASHA256, func() KeySign {
        return KeySignWithDSASHA256
    })

    AddKeySign(oidDigestAlgorithmECDSASHA1, func() KeySign {
        return KeySignWithEcdsaSHA1
    })
    AddKeySign(oidDigestAlgorithmECDSASHA224, func() KeySign {
        return KeySignWithEcdsaSHA224
    })
    AddKeySign(oidDigestAlgorithmECDSASHA256, func() KeySign {
        return KeySignWithEcdsaSHA256
    })
    AddKeySign(oidDigestAlgorithmECDSASHA384, func() KeySign {
        return KeySignWithEcdsaSHA384
    })
    AddKeySign(oidDigestAlgorithmECDSASHA512, func() KeySign {
        return KeySignWithEcdsaSHA512
    })

    AddKeySign(oidDigestAlgorithmRSAMD5, func() KeySign {
        return KeySignWithRsaMD5
    })
    AddKeySign(oidDigestAlgorithmRSASHA1, func() KeySign {
        return KeySignWithRsaSHA1
    })
    AddKeySign(oidDigestAlgorithmRSASHA224, func() KeySign {
        return KeySignWithRsaSHA224
    })
    AddKeySign(oidDigestAlgorithmRSASHA256, func() KeySign {
        return KeySignWithRsaSHA256
    })
    AddKeySign(oidDigestAlgorithmRSASHA384, func() KeySign {
        return KeySignWithRsaSHA384
    })
    AddKeySign(oidDigestAlgorithmRSASHA512, func() KeySign {
        return KeySignWithRsaSHA512
    })

    AddKeySign(oidDigestAlgorithmEd25519, func() KeySign {
        return KeySignWithEdDsaSHA1
    })

    AddKeySign(oidDigestAlgorithmSM2SM3, func() KeySign {
        return KeySignWithSM2SM3
    })
}

