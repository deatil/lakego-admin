package pkcs7

import (
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/asn1"
)

var(
    // Signature Algorithms
    oidEncryptionAlgorithmRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
    oidEncryptionAlgorithmRSAESOAEP = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
    oidEncryptionAlgorithmRSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
    oidEncryptionAlgorithmRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
    oidEncryptionAlgorithmRSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
    oidEncryptionAlgorithmRSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

    oidEncryptionAlgorithmSM2       = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 3}
)

// KeyEncryptRSA
var KeyEncryptRSA = KeyEncryptWithRSA{
    hashFunc:   nil,
    identifier: oidEncryptionAlgorithmRSA,
}

// KeyEncryptRSAESOAEP
var KeyEncryptRSAESOAEP = KeyEncryptWithRSA{
    hashFunc:   sha1.New,
    identifier: oidEncryptionAlgorithmRSAESOAEP,
}

// KeyEncryptRSASHA1
var KeyEncryptRSASHA1 = KeyEncryptWithRSA{
    hashFunc:   sha1.New,
    identifier: oidEncryptionAlgorithmRSASHA1,
}

// KeyEncryptRSASHA256
var KeyEncryptRSASHA256 = KeyEncryptWithRSA{
    hashFunc:   sha256.New,
    identifier: oidEncryptionAlgorithmRSASHA256,
}

// KeyEncryptRSASHA384
var KeyEncryptRSASHA384 = KeyEncryptWithRSA{
    hashFunc:   sha512.New384,
    identifier: oidEncryptionAlgorithmRSASHA384,
}

// KeyEncryptRSASHA512
var KeyEncryptRSASHA512 = KeyEncryptWithRSA{
    hashFunc:   sha512.New,
    identifier: oidEncryptionAlgorithmRSASHA512,
}

// KeyEncryptSM2
var KeyEncryptSM2 = KeyEncryptWithSM2{
    identifier: oidEncryptionAlgorithmSM2,
}

func init() {
    AddkeyEncrypt(oidEncryptionAlgorithmRSA, func() KeyEncrypt {
        return KeyEncryptRSA
    })
    AddkeyEncrypt(oidEncryptionAlgorithmRSAESOAEP, func() KeyEncrypt {
        return KeyEncryptRSAESOAEP
    })
    AddkeyEncrypt(oidEncryptionAlgorithmRSASHA1, func() KeyEncrypt {
        return KeyEncryptRSASHA1
    })
    AddkeyEncrypt(oidEncryptionAlgorithmRSASHA256, func() KeyEncrypt {
        return KeyEncryptRSASHA256
    })
    AddkeyEncrypt(oidEncryptionAlgorithmRSASHA384, func() KeyEncrypt {
        return KeyEncryptRSASHA384
    })
    AddkeyEncrypt(oidEncryptionAlgorithmRSASHA512, func() KeyEncrypt {
        return KeyEncryptRSASHA512
    })

    AddkeyEncrypt(oidEncryptionAlgorithmSM2, func() KeyEncrypt {
        return KeyEncryptSM2
    })
}
