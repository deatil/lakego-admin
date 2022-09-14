package pkcs12

import (
    "encoding/asn1"
    "crypto/x509/pkix"
)

// Encode secret key in a pkcs8
// See ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn, RFC 5208,
// https://github.com/openjdk/jdk/blob/jdk8-b120/jdk/src/share/classes/sun/security/pkcs12/PKCS12KeyStore.java#L613,
// https://github.com/openjdk/jdk/blob/jdk9-b94/jdk/src/java.base/share/classes/sun/security/pkcs12/PKCS12KeyStore.java#L624
// and https://github.com/golang/go/blob/master/src/crypto/x509/pkcs8.go
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
}

// https://tools.ietf.org/html/rfc7292#section-4.2.5
// SecretBag ::= SEQUENCE {
//   secretTypeId   BAG-TYPE.&id ({SecretTypes}),
//   secretValue    [0] EXPLICIT BAG-TYPE.&Type ({SecretTypes}
//                     {@secretTypeId})
// }
type secretBag struct {
    SecretTypeID asn1.ObjectIdentifier
    SecretValue  []byte `asn1:"tag:0,explicit"`
}
