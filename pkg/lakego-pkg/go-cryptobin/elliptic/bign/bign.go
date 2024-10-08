package bign

import (
    "sync"
    "encoding/asn1"
    "crypto/elliptic"
)

var (
    OIDNamedCurveP256v1 = asn1.ObjectIdentifier{1, 2, 112, 0, 2, 0, 34, 101, 45, 3, 1}
    OIDNamedCurveP384v1 = asn1.ObjectIdentifier{1, 2, 112, 0, 2, 0, 34, 101, 45, 3, 2}
    OIDNamedCurveP512v1 = asn1.ObjectIdentifier{1, 2, 112, 0, 2, 0, 34, 101, 45, 3, 3}
)

var initonce sync.Once

func P256v1() elliptic.Curve {
    initonce.Do(initAll)
    return p256v1
}

func P384v1() elliptic.Curve {
    initonce.Do(initAll)
    return p384v1
}

func P512v1() elliptic.Curve {
    initonce.Do(initAll)
    return p512v1
}
