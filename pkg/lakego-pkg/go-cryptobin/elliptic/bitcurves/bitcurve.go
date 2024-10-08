// Package bitelliptic implements several Koblitz elliptic curves over prime fields.
package bitcurves

import (
    "encoding/asn1"
)

// curve parameters taken from:
// http://www.secg.org/collateral/sec2_final.pdf

var (
    OIDNamedCurveSecp160k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 9}
    OIDNamedCurveSecp192k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 31}
    OIDNamedCurveSecp224k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 32}
    OIDNamedCurveSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

// S160 returns a BitCurve which implements secp160k1 (see SEC 2 section 2.4.1)
func S160() *BitCurve {
    initonce.Do(initAll)
    return secp160k1
}

// S192 returns a BitCurve which implements secp192k1 (see SEC 2 section 2.5.1)
func S192() *BitCurve {
    initonce.Do(initAll)
    return secp192k1
}

// S224 returns a BitCurve which implements secp224k1 (see SEC 2 section 2.6.1)
func S224() *BitCurve {
    initonce.Do(initAll)
    return secp224k1
}

// S256 returns a BitCurve which implements bitcurves (see SEC 2 section 2.7.1)
func S256() *BitCurve {
    initonce.Do(initAll)
    return secp256k1
}
