package nist

import (
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/elliptic/base_elliptic"
)

var (
    OIDNamedCurveB233 = asn1.ObjectIdentifier{1, 3, 132, 0, 27} // B-233
    OIDNamedCurveB283 = asn1.ObjectIdentifier{1, 3, 132, 0, 17} // B-283
    OIDNamedCurveB409 = asn1.ObjectIdentifier{1, 3, 132, 0, 37} // B-409
    OIDNamedCurveB571 = asn1.ObjectIdentifier{1, 3, 132, 0, 39} // B-571

    OIDNamedCurveK233 = asn1.ObjectIdentifier{1, 3, 132, 0, 26} // K-233
    OIDNamedCurveK283 = asn1.ObjectIdentifier{1, 3, 132, 0, 16} // K-283
    OIDNamedCurveK409 = asn1.ObjectIdentifier{1, 3, 132, 0, 36} // K-409
    OIDNamedCurveK571 = asn1.ObjectIdentifier{1, 3, 132, 0, 38} // K-571
)

// K163 returns a Curve which implements NIST K-163
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func K163() base_elliptic.Curve {
    initonce.Do(initAll)
    return k163
}

// B163 returns a Curve which implements NIST B-163
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func B163() base_elliptic.Curve {
    initonce.Do(initAll)
    return b163
}

// K233 returns a Curve which implements NIST K-233
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func K233() base_elliptic.Curve {
    initonce.Do(initAll)
    return k233
}

// B233 returns a Curve which implements NIST B-233
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func B233() base_elliptic.Curve {
    initonce.Do(initAll)
    return b233
}

// K283 returns a Curve which implements NIST K-283
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func K283() base_elliptic.Curve {
    initonce.Do(initAll)
    return k283
}

// B283 returns a Curve which implements NIST B-283
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func B283() base_elliptic.Curve {
    initonce.Do(initAll)
    return b283
}

// K409 returns a Curve which implements NIST K-409
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func K409() base_elliptic.Curve {
    initonce.Do(initAll)
    return k409
}

// B409 returns a Curve which implements NIST B-409
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func B409() base_elliptic.Curve {
    initonce.Do(initAll)
    return b409
}

// K571 returns a Curve which implements NIST K-571
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func K571() base_elliptic.Curve {
    initonce.Do(initAll)
    return k571
}

// B571 returns a Curve which implements NIST B-571
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func B571() base_elliptic.Curve {
    initonce.Do(initAll)
    return b571
}
