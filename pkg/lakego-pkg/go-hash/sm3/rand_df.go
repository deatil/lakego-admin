package sm3

import (
    "hash"
)

// The size of an SM3-DF checksum in bytes.
const SizeDF = 55

// The blocksize of SM3-DF in bytes.
const BlockSizeDF = 64

type DF struct {
    sm3 [2]hash.Hash
}

func NewDF() *DF {
    df := new(DF)
    df.Reset()

    return df
}

func (this *DF) Reset() {
    var counter = [4]byte{0, 0, 0, 1}
    var seedlen = [4]byte{0, 0, 440/256, 440%256}

    this.sm3[0] = New()
    this.sm3[0].Write(counter[:])
    this.sm3[0].Write(seedlen[:])

    counter[3] = 2

    this.sm3[1] = New()
    this.sm3[1].Write(counter[:])
    this.sm3[1].Write(seedlen[:])
}

func (this *DF) Size() int {
    return SizeDF
}

func (this *DF) BlockSize() int {
    return BlockSizeDF
}

func (this *DF) Write(data []byte) {
    if len(data) > 0 {
        this.sm3[0].Write(data)
        this.sm3[1].Write(data)
    }
}

func (this *DF) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d := *this
    sum := d.checkSum()
    return append(in, sum[:]...)
}

func (this *DF) checkSum() (out [SizeDF]byte) {
    o := this.sm3[0].Sum(nil)
    buf := this.sm3[1].Sum(nil)

    copy(out[:], o)
    copy(out[:SizeDF - 32], buf)

    return
}
