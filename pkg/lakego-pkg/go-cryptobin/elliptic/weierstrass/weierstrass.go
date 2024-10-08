package weierstrass

import (
    "encoding/asn1"
    "crypto/elliptic"
)

// Support for short Weierstrass elliptic curves
// http://www.secg.org/SEC2-Ver-1.0.pdf

var (
    OIDNamedCurveSecp160k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 9}
    OIDNamedCurveSecp160r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 8}
    OIDNamedCurveSecp160r2 = asn1.ObjectIdentifier{1, 3, 132, 0, 30}
    OIDNamedCurveSecp192k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 31}
    OIDNamedCurveSecp192r1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 1}
    OIDNamedCurveSecp224k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 32}
    OIDNamedCurveSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

func P160r1() elliptic.Curve {
    once.Do(initAll)
    return p160r1
}

func P160r2() elliptic.Curve {
    once.Do(initAll)
    return p160r2
}

func P192r1() elliptic.Curve {
    once.Do(initAll)
    return p192r1
}
