package koblitz

import (
    "encoding/asn1"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/elliptic/bitcurves"
)

// Support for Koblitz elliptic curves
// http://www.secg.org/SEC2-Ver-1.0.pdf

var (
    OIDNamedCurveSecp160k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 9}
    OIDNamedCurveSecp192k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 31}
    OIDNamedCurveSecp224k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 32}
    OIDNamedCurveSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

func P160k1() elliptic.Curve {
    return bitcurves.S160()
}

func P192k1() elliptic.Curve {
    return bitcurves.S192()
}

func P224k1() elliptic.Curve {
    return bitcurves.S224()
}

func P256k1() elliptic.Curve {
    return bitcurves.S256()
}
