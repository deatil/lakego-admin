//go:build go1.20

package x25519

import (
    "bytes"
    "testing"
)

func FuzzNewKeyFromSeed(f *testing.F) {
    f.Add(decodeHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    f.Add(decodeHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
    f.Fuzz(func(t *testing.T, seed []byte) {
        if len(seed) != SeedSize {
            return
        }
        priv := NewKeyFromSeed(seed)
        legacy := newKeyFromSeedLegacy(seed)
        if !priv.Equal(legacy) {
            t.Errorf("result not match: %x and %x", priv, legacy)
        }
    })
}

func FuzzTestX25519(f *testing.F) {
    f.Add(
        decodeHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        decodeHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    )
    f.Add(
        decodeHex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
        decodeHex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
    )
    f.Add(
        decodeHex("0900000000000000000000000000000000000000000000000000000000000000"),
        decodeHex("0900000000000000000000000000000000000000000000000000000000000000"),
    )
    f.Fuzz(func(t *testing.T, a []byte, b []byte) {
        ret, err1 := X25519(a, b)
        legacy, err2 := x25519Legacy(a, b)
        if (err1 != nil) != (err2 != nil) {
            t.Fatal(err1, err2)
        }
        if err1 != nil || err2 != nil {
            return
        }
        if !bytes.Equal(ret, legacy) {
            t.Error("not match")
        }
    })
}
