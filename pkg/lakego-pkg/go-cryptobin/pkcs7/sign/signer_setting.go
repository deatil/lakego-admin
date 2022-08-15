package sign

import (
    "crypto"
    _ "crypto/sha1"
    _ "crypto/sha256"
    _ "crypto/sha512"
    "encoding/asn1"
)

var (
    // 签名
    oidDigestAlgorithmDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
    oidDigestAlgorithmDSASHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}

    oidDigestAlgorithmECDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
    oidDigestAlgorithmECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
    oidDigestAlgorithmECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
    oidDigestAlgorithmECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

    // Signature Algorithms
    oidDigestAlgorithmRSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
    oidDigestAlgorithmRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
    oidDigestAlgorithmRSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
    oidDigestAlgorithmRSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
)

var KeySignWithDSASHA1 = KeySignWithDSA{
    hashFunc:   crypto.SHA1,
    hashId:     oidDigestAlgorithmSHA1,
    identifier: oidDigestAlgorithmDSASHA1,
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

var KeySignWithRsaSHA1 = KeySignWithRsa{
    hashFunc:   crypto.SHA1,
    hashId:     oidDigestAlgorithmSHA1,
    identifier: oidDigestAlgorithmRSASHA1,
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

func init() {
    AddKeySign(oidDigestAlgorithmDSASHA1, func() KeySign {
        return KeySignWithDSASHA1
    })
    AddKeySign(oidDigestAlgorithmDSASHA256, func() KeySign {
        return KeySignWithDSASHA256
    })

    AddKeySign(oidDigestAlgorithmECDSASHA1, func() KeySign {
        return KeySignWithEcdsaSHA1
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

    AddKeySign(oidDigestAlgorithmRSASHA1, func() KeySign {
        return KeySignWithRsaSHA1
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
}

