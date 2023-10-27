package koblitz

// Support for Koblitz elliptic curves
// http://www.secg.org/SEC2-Ver-1.0.pdf

import (
    "crypto/elliptic"
    
    "github.com/deatil/go-cryptobin/elliptic/bitcurves"
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
