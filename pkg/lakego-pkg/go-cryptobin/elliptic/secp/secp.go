package secp

import (
    "encoding/asn1"
    "crypto/elliptic"
)

var (
    OIDNamedCurveSecp192r1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 1}
    OIDNamedCurveP192 = OIDNamedCurveSecp192r1

    OIDNamedCurveSecp112r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 6}
    OIDNamedCurveSecp112r2 = asn1.ObjectIdentifier{1, 3, 132, 0, 7}
    OIDNamedCurveSecp128r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 28}
    OIDNamedCurveSecp128r2 = asn1.ObjectIdentifier{1, 3, 132, 0, 29}
    OIDNamedCurveSecp160r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 8}
    OIDNamedCurveSecp160r2 = asn1.ObjectIdentifier{1, 3, 132, 0, 30}
)

func P112r1() elliptic.Curve {
    once.Do(initAll)
    return secp112r1
}

func P112r2() elliptic.Curve {
    once.Do(initAll)
    return secp112r2
}

func P128r1() elliptic.Curve {
    once.Do(initAll)
    return secp128r1
}

func P128r2() elliptic.Curve {
    once.Do(initAll)
    return secp128r2
}

func P160r1() elliptic.Curve {
    once.Do(initAll)
    return secp160r1
}

func P160r2() elliptic.Curve {
    once.Do(initAll)
    return secp160r2
}

func P192() elliptic.Curve {
    once.Do(initAll)
    return secp192r1
}

func P192r1() elliptic.Curve {
    once.Do(initAll)
    return secp192r1
}
