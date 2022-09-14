package jceks

import(
    "encoding/asn1"
)

const (
    certType = "X.509"
)

const (
    jceksMagic   = 0xcececece
    jceksVersion = 0x02

    jceksPrivateKeyId  = 1
    jceksTrustedCertId = 2
    jceksSecretKeyId   = 3
)

const (
    jksMagic   = 0xFEEDFEED
    jksVersion = 0x02

    jksPrivateKeyId  = 1
    jksTrustedCertId = 2
)

var (
    // JavaSoft proprietary key-protection algorithm (used to protect
    // private keys in the keystore implementation that comes with JDK
    // 1.2).
    oidKeyProtector = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1}
)
