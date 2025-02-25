package nums

import (
    "sync"
    "encoding/asn1"
    "crypto/elliptic"
)

// see https://datatracker.ietf.org/doc/draft-black-numscurves/

var (
    OIDNums = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0}

    OIDNumsp256d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 1}
    OIDNumsp256t1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 2}
    OIDNumsp384d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 3}
    OIDNumsp384t1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 4}
    OIDNumsp512d1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 5}
    OIDNumsp512t1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 0, 6}
)

// sync.Once variable to ensure initialization occurs only once
var once sync.Once

// P256d1() returns a Curve which implements p256d1 of Microsoft's Nothing Up My Sleeve (NUMS)
func P256d1() elliptic.Curve {
    once.Do(initAll)
    return p256d1
}

// P256t1() returns a Curve which implements p256t1 of Microsoft's Nothing Up My Sleeve (NUMS)
func P256t1() elliptic.Curve {
    once.Do(initAll)
    return p256t1
}

// P384d1() returns a Curve which implements p384d1 of Microsoft's Nothing Up My Sleeve (NUMS)
func P384d1() elliptic.Curve {
    once.Do(initAll)
    return p384d1
}

// P384t1() returns a Curve which implements p384t1 of Microsoft's Nothing Up My Sleeve (NUMS)
func P384t1() elliptic.Curve {
    once.Do(initAll)
    return p384t1
}

// P512d1() returns a Curve which implements p512d1 of Microsoft's Nothing Up My Sleeve (NUMS)
func P512d1() elliptic.Curve {
    once.Do(initAll)
    return p512d1
}

// P512t1() returns a Curve which implements p512t1 of Microsoft's Nothing Up My Sleeve (NUMS)
func P512t1() elliptic.Curve {
    once.Do(initAll)
    return p512t1
}
