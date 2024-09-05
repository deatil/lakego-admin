package x25519

import (
    "bytes"
    "testing"
    "encoding/hex"
)

func decodeHex(s string) []byte {
    ret, err := hex.DecodeString(s)
    if err != nil {
        panic(err)
    }
    return ret
}

func TestGenerateKey(t *testing.T) {
    t.Run("x25519.GenerateKey(nil)", func(t *testing.T) {
        _, _, err := GenerateKey(nil)
        if err != nil {
            t.Fatal(err)
        }
    })
    t.Run("x25519.NewKeyFromSeed(wrongSeedLength)", func(t *testing.T) {
        dummy := make([]byte, SeedSize-1)
        err := func() (err any) {
            defer func() {
                err = recover()
            }()
            NewKeyFromSeed(dummy)
            return nil
        }()
        if err == nil {
            t.Error("want some error, but not")
        }
    })
}

func TestPublicKey(t *testing.T) {
    t.Run("RFC 7748 Section 6.1. Curve25519", func(t *testing.T) {
        t.Run("Alice", func(t *testing.T) {
            seed := decodeHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            want := PublicKey(decodeHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
            priv := NewKeyFromSeed(seed)
            pub := priv.Public()
            if !want.Equal(pub) {
                t.Errorf("want %x, got %x", want, pub)
            }
        })
        t.Run("Bob", func(t *testing.T) {
            seed := decodeHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            want := PublicKey(decodeHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
            priv := NewKeyFromSeed(seed)
            pub := priv.Public()
            if !want.Equal(pub) {
                t.Errorf("want %x, got %x", want, pub)
            }
        })
    })
}

func TestX25519(t *testing.T) {
    t.Run("RFC 7748 Section 5.2. Test Vectors", func(t *testing.T) {
        t.Run("Example1", func(t *testing.T) {
            scalar := decodeHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
            uCoordinate := decodeHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
            want := decodeHex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
            got, err := X25519(scalar, uCoordinate)
            if err != nil {
                t.Fatal(err)
            }
            if !bytes.Equal(want, got) {
                t.Errorf("want %x, got %x", want, got)
            }
        })

        t.Run("Example2", func(t *testing.T) {
            scalar := decodeHex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
            uCoordinate := decodeHex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
            want := decodeHex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
            got, err := X25519(scalar, uCoordinate)
            if err != nil {
                t.Fatal(err)
            }
            if !bytes.Equal(want, got) {
                t.Errorf("want %x, got %x", want, got)
            }
        })

        t.Run("After one iteration", func(t *testing.T) {
            k := decodeHex("0900000000000000000000000000000000000000000000000000000000000000")
            u := decodeHex("0900000000000000000000000000000000000000000000000000000000000000")
            got, err := X25519(k, u)
            if err != nil {
                t.Fatal(err)
            }
            want := decodeHex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
            if !bytes.Equal(want, got) {
                t.Errorf("want %x, got %x", want, got)
            }
        })

        t.Run("After 1,000 iteration", func(t *testing.T) {
            k := decodeHex("0900000000000000000000000000000000000000000000000000000000000000")
            u := decodeHex("0900000000000000000000000000000000000000000000000000000000000000")
            for i := 0; i < 1_000; i++ {
                v, err := X25519(k, u)
                if err != nil {
                    t.Fatal(err)
                }
                k, u = v, k
            }
            want := decodeHex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
            if !bytes.Equal(want, k) {
                t.Errorf("want %x, got %x", want, k)
            }
        })
    })
}
