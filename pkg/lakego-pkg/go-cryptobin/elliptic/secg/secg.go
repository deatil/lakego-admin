package secg

import (
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/elliptic/base_elliptic"
)

var (
    OIDNamedCurveSect113r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 4}
    OIDNamedCurveSect113r2 = asn1.ObjectIdentifier{1, 3, 132, 0, 5}
    OIDNamedCurveSect131r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 22}
    OIDNamedCurveSect131r2 = asn1.ObjectIdentifier{1, 3, 132, 0, 23}
    OIDNamedCurveSect163k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 1}
    OIDNamedCurveSect163r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 2}
    OIDNamedCurveSect163r2 = asn1.ObjectIdentifier{1, 3, 132, 0, 15}
    OIDNamedCurveSect193r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 24}
    OIDNamedCurveSect193r2 = asn1.ObjectIdentifier{1, 3, 132, 0, 25}

    OIDNamedCurveSect233k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 26}
    OIDNamedCurveSect233r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 27}
    OIDNamedCurveSect239k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 3}
    OIDNamedCurveSect283k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 16}
    OIDNamedCurveSect283r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 17}
    OIDNamedCurveSect409k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 36}
    OIDNamedCurveSect409r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 37}
    OIDNamedCurveSect571k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 38}
    OIDNamedCurveSect571r1 = asn1.ObjectIdentifier{1, 3, 132, 0, 39}
)

// Sect113r1 returns a Curve which implements SECG sect113r1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect113r1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect113r1
}

// Sect113r2 returns a Curve which implements SECG sect113r2
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect113r2() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect113r2
}

// Sect131r1 returns a Curve which implements SECG sect131r1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect131r1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect131r1
}

// Sect131r2 returns a Curve which implements SECG sect131r2
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect131r2() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect131r2
}

// Sect163k1 returns a Curve which implements SECG sect163k1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect163k1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect163k1
}

// Sect163r1 returns a Curve which implements SECG sect163r1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect163r1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect163r1
}

// Sect163r2 returns a Curve which implements SECG sect163r2
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect163r2() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect163r2
}

// Sect193r1 returns a Curve which implements SECG sect193r1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect193r1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect193r1
}

// Sect193r2 returns a Curve which implements SECG sect193r2
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect193r2() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect193r2
}

// Sect233k1 returns a Curve which implements SECG sect233k1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect233k1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect233k1
}

// Sect233r1 returns a Curve which implements SECG sect233r1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect233r1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect233r1
}

// Sect239k1 returns a Curve which implements SECG sect239k1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect239k1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect239k1
}

// Sect283k1 returns a Curve which implements SECG sect283k1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect283k1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect283k1
}

// Sect283r1 returns a Curve which implements SECG sect283r1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect283r1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect283r1
}

// Sect409k1 returns a Curve which implements SECG sect409k1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect409k1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect409k1
}

// Sect409r1 returns a Curve which implements SECG sect409r1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect409r1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect409r1
}

// Sect571k1 returns a Curve which implements SECG sect571k1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect571k1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect571k1
}

// Sect571r1 returns a Curve which implements SECG sect571r1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Sect571r1() base_elliptic.Curve {
    initonce.Do(initAll)
    return sect571r1
}
