package zuc

import (
    "crypto/subtle"
)

type ZucState struct {
    LFSR [16]uint32
    R1 uint32
    R2 uint32
}

func NewZucState(key []byte, iv []byte) *ZucState {
    if l := len(key); l != 16 {
        panic(KeySizeError(l))
    }

    if l := len(iv); l != 16 {
        panic(IVSizeError(l))
    }

    s := new(ZucState)
    s.init(key, iv)

    return s
}

func (this *ZucState) init(userKey []byte, iv []byte) {
    var R1, R2 uint32
    var X0, X1, X2 uint32
    var W uint32
    var i int32

    for i = 0; i < 16; i++ {
        this.LFSR[i] = MAKEU31(userKey[i], KD[i], iv[i])
    }

    R1 = 0
    R2 = 0

    for i = 0; i < 32; i++ {
        BitReconstruction3(&X0, &X1, &X2, this.LFSR[:])
        W = F(&R1, &R2, X0, X1, X2)
        LFSRWithInitialisationMode(W >> 1, this.LFSR[:])
    }

    BitReconstruction2(&X1, &X2, this.LFSR[:])
    F_(&R1, &R2, X1, X2)
    LFSRWithWorkMode(this.LFSR[:])

    this.R1 = R1
    this.R2 = R2
}

func (this *ZucState) GenerateKeyword() uint32 {
    var R1 uint32 = this.R1
    var R2 uint32 = this.R2
    var X0, X1, X2, X3 uint32
    var Z uint32

    BitReconstruction4(&X0, &X1, &X2, &X3, this.LFSR[:])
    Z = X3 ^ F(&R1, &R2, X0, X1, X2)
    LFSRWithWorkMode(this.LFSR[:])

    this.R1 = R1
    this.R2 = R2

    return Z
}

func (this *ZucState) GenerateKeystream(nwords int, keystream []uint32) {
    var R1 uint32 = this.R1
    var R2 uint32 = this.R2
    var X0, X1, X2, X3 uint32
    var i int

    for i = 0; i < nwords; i++ {
        BitReconstruction4(&X0, &X1, &X2, &X3, this.LFSR[:])
        keystream[i] = X3 ^ F(&R1, &R2, X0, X1, X2)
        LFSRWithWorkMode(this.LFSR[:])
    }

    this.R1 = R1
    this.R2 = R2
}

func (this *ZucState) Encrypt(out []byte, in []byte) {
    var R1 uint32 = this.R1
    var R2 uint32 = this.R2
    var X0, X1, X2, X3 uint32
    var Z uint32

    var inlen int = len(in)

    var block [4]byte
    var nwords int = inlen / 4
    var i int

    for i = 0; i < nwords; i++ {
        BitReconstruction4(&X0, &X1, &X2, &X3, this.LFSR[:])
        Z = X3 ^ F(&R1, &R2, X0, X1, X2)
        LFSRWithWorkMode(this.LFSR[:])

        PUTU32(block[:], Z)

        subtle.XORBytes(out[:len(block)], in[:len(block)], block[:])

        in = in[len(block):]
        out = out[len(block):]
    }

    if (inlen % 4) > 0 {
        BitReconstruction4(&X0, &X1, &X2, &X3, this.LFSR[:])
        Z = X3 ^ F(&R1, &R2, X0, X1, X2)
        LFSRWithWorkMode(this.LFSR[:])

        PUTU32(block[:], Z)

        subtle.XORBytes(out[:inlen % 4], in[:inlen % 4], block[:inlen % 4])
    }

    this.R1 = R1
    this.R2 = R2
}
