package sm3

import (
    "hash"
)

type DF struct {
    sm3 [2]hash.Hash
}

func NewDF() *DF {
    df := new(DF)
    df.init()

    return df
}

func (this *DF) init() {
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

func (this *DF) Write(data []byte) {
    if len(data) > 0 {
        this.sm3[0].Write(data)
        this.sm3[1].Write(data)
    }
}

func (this *DF) Sum() (out [55]byte) {
    o := this.sm3[0].Sum(nil)
    buf := this.sm3[1].Sum(nil)

    copy(out[:], o)
    copy(out[:55 - 32], buf)

    return
}
