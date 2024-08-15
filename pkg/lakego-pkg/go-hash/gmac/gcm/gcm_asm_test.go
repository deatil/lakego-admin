//go:build (amd64 || arm64) && !purego && (!gccgo || go1.18)
// +build amd64 arm64
// +build !purego
// +build !gccgo go1.18

package gcm

import (
    "bytes"
    "crypto/aes"
    "crypto/rand"
    "testing"
)

func Test_GCMAuthAsm(t *testing.T) {
    if !supportsGFMUL {
        t.Skip("PCLMULQDQ or PMULL not available")
        return
    }

    var tagMaskA, tagMaskB [GCMBlockSize]byte
    outA, outG := make([]byte, 16), make([]byte, 16)

    key := make([]byte, 16)
    ciphertext := make([]byte, 16*16+15)
    additionalData := make([]byte, 16*16+1)

    rand.Read(key)
    rand.Read(ciphertext)
    rand.Read(additionalData)

    block, _ := aes.NewCipher(key)
    kb := WrapCipher(block)

    var gcmA GCM
    var gcmG GCM

    gcmInitGo(&gcmA, kb)
    gcmInitAsm(&gcmG, kb)

    gcmAuthGo(&gcmA, outA, ciphertext, additionalData, &tagMaskA)
    gcmAuthAsm(&gcmG, outG, ciphertext, additionalData, &tagMaskB)

    if !bytes.Equal(outA, outG) {
        t.Fail()
        return
    }
}

func Benchmark_GCMAuthAsm(b *testing.B) {
    if !supportsGFMUL {
        b.Skip("PCLMULQDQ or PMULL not available")
        return
    }

    bench := func(
        blocks int,
        gcmAuth func(g *GCM, out, ciphertext, additionalData []byte, tagMask *[GCMTagSize]byte),
    ) func(b *testing.B) {
        return func(b *testing.B) {
            var g GCM

            block, _ := aes.NewCipher(make([]byte, 16))
            kb := WrapCipher(block)

            gcmInitGo(&g, kb)

            var tagMask [GCMBlockSize]byte
            out := make([]byte, 16)

            ciphertext := make([]byte, GCMBlockSize*blocks)
            rand.Read(ciphertext)

            b.ResetTimer()
            for i := 0; i < b.N; i++ {
                gcmAuth(&g, out, ciphertext, nil, &tagMask)
                copy(ciphertext, out)
            }
        }
    }

    b.Run("generic-8", bench(8, gcmAuthGo))
    b.Run("generic-1K", bench(1*1024, gcmAuthGo))
    b.Run("generic-8K", bench(8*1024, gcmAuthGo))

    b.Run("assembly-8", bench(8, gcmAuthAsm))
    b.Run("assembly-1K", bench(1*1024, gcmAuthAsm))
    b.Run("assembly-8K", bench(8*1024, gcmAuthAsm))
}
