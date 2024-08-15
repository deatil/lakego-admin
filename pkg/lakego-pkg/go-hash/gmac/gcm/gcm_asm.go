//go:build (amd64 || arm64) && !purego && (!gccgo || go1.18)
// +build amd64 arm64
// +build !purego
// +build !gccgo go1.18

package gcm

import (
    "unsafe"

    "golang.org/x/sys/cpu"
)

var supportsGFMUL = cpu.X86.HasPCLMULQDQ || cpu.ARM64.HasPMULL

func init() {
    if supportsGFMUL {
        gcmInit = gcmInitAsm
        gcmDeriveCounter = gcmDeriveCounterAsm
        gcmUpdate = gcmUpdateAsm
        gcmAuth = gcmAuthAsm
        gcmFinish = gcmFinishAsm
    } else {
        gcmInit = gcmInitGo
        gcmDeriveCounter = gcmDeriveCounterGo
        gcmUpdate = gcmUpdateGo
        gcmAuth = gcmAuthGo
        gcmFinish = gcmFinishGo
    }
}

//go:noescape
func _gcmFinish(productTable *[16]GCMFieldElement, tagMask, T unsafe.Pointer, pLen, dLen uint64)

//go:noescape
func _gcmInit(productTable *[16]GCMFieldElement, ks *[GCMBlockSize]byte)

//go:noescape
func _gcmData(productTable *[16]GCMFieldElement, data []byte, T unsafe.Pointer)

func gcmInitAsm(g *GCM, cipher Block) {
    var key [GCMBlockSize]byte
    cipher.Encrypt(key[:], key[:])

    _gcmInit(&g.productTable, &key)
}

func gcmUpdateAsm(g *GCM, y *GCMFieldElement, blocks []byte) {
    _gcmData(&g.productTable, blocks, unsafe.Pointer(y))
}

func gcmDeriveCounterAsm(g *GCM, counter *[GCMBlockSize]byte, nonce []byte) {
    if len(nonce) == GCMStandardNonceSize {
        // Init counter to nonce||1
        copy(counter[:], nonce)
        counter[GCMBlockSize-1] = 1
    } else {
        var tagMask [GCMTagSize]byte

        // Otherwise counter = GHASH(nonce)
        _gcmData(&g.productTable, nonce, unsafe.Pointer(counter))
        _gcmFinish(&g.productTable, vp8(tagMask[:]), unsafe.Pointer(counter), uint64(len(nonce)), uint64(0))
    }
}

func gcmAuthAsm(g *GCM, out, ciphertext, additionalData []byte, tagMask *[GCMTagSize]byte) {
    _gcmData(&g.productTable, additionalData, vp8(out))
    _gcmData(&g.productTable, ciphertext, vp8(out))

    _gcmFinish(&g.productTable, unsafe.Pointer(tagMask), vp8(out), uint64(len(ciphertext)), uint64(len(additionalData)))
}

func gcmFinishAsm(g *GCM, out []byte, y *GCMFieldElement, ciphertextLen, additionalDataLen int, tagMask *[GCMTagSize]byte) {
    copy(out, (*[GCMBlockSize]byte)(unsafe.Pointer(y))[:])
    _gcmFinish(&g.productTable, unsafe.Pointer(tagMask), vp8(out), uint64(ciphertextLen), uint64(additionalDataLen))
}

// void pointer(byte b)
// if b is nil, panic
func vp8(b []byte) unsafe.Pointer {
    return unsafe.Pointer(&b[0])
}
