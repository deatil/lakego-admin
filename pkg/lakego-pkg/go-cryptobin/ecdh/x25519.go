package ecdh

import (
    "crypto/ecdh"
)

func X25519() Curve {
    return defaultX25519
}

var defaultX25519 = NewNistCurve(ecdh.X25519())
