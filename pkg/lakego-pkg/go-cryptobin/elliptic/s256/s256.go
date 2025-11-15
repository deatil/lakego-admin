// Package secp256k1 implements the standard secp256k1 elliptic curve over prime fields.
package s256

import (
    "sync"
    "encoding/asn1"
)

var (
    OIDS256 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

var once sync.Once

// The following conventions are used, with constants as defined for secp256k1.
// We note that adapting this specification to other elliptic curves is not straightforward
// and can result in an insecure scheme
func S256() *S256Curve {
    once.Do(initAll)
    return s256
}
