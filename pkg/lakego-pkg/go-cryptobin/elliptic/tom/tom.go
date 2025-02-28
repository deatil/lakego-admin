package tom

import (
    "sync"
    "encoding/asn1"
    "crypto/elliptic"
)

var (
    OIDTom = asn1.ObjectIdentifier{1, 2, 999, 1, 1, 1}

    OIDNamedCurveTom256 = asn1.ObjectIdentifier{1, 2, 999, 1, 1, 1, 1}
    OIDNamedCurveTom384 = asn1.ObjectIdentifier{1, 2, 999, 1, 1, 1, 2}
    OIDNamedCurveTom521 = asn1.ObjectIdentifier{1, 2, 999, 1, 1, 1, 3}
)

// sync.Once variable to ensure initialization occurs only once
var once sync.Once

func P256() elliptic.Curve {
    once.Do(initAll)
    return p256
}

func P384() elliptic.Curve {
    once.Do(initAll)
    return p384
}

func P521() elliptic.Curve {
    once.Do(initAll)
    return p521
}
