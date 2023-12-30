package sm3

import (
    "time"
    "hash"
    "math/rand"
)

const MAX_RESEED_COUNTER = (1<<20)
const MAX_RESEED_SECONDS = 600

var num = [4]uint8{ 0, 1, 2, 3 }

type Rand struct {
    V [55]uint8
    C [55]uint8
    reseedCounter uint32
    lastReseedTime time.Time
}

func NewRand(nonce []byte, label []byte) *Rand {
    rand := new(Rand)
    rand.init(nonce, label)

    return rand
}

func (this *Rand) init(nonce []byte, label []byte) {
    var df *DF
    var entropy [512]byte

    // get_entropy, 512-byte might be too long for some system RNGs
    if (!randomBytes(entropy[:], 256) || !randomBytes(entropy[256:], 256)) {
        panic("rand bytes error")
    }

    // V = sm3_df(entropy || nonce || label)
    df = NewDF()
    df.Write(entropy[:])
    df.Write(nonce[:])
    df.Write(label[:])
    this.V = df.Sum()

    // C = sm3_df(0x00 || V)
    df = NewDF()
    df.Write(num[0:1])
    df.Write(this.V[:])
    this.C = df.Sum()

    // reseedCounter = 1, last_ressed_time = now()
    this.reseedCounter = 1
    this.lastReseedTime = time.Now()
}

func (this *Rand) Generate(out []byte, addin []byte) {
    var sm3 hash.Hash
    var H []byte
    var counter [4]byte

    if (this.reseedCounter > MAX_RESEED_COUNTER ||
        time.Now().Second() - this.lastReseedTime.Second() > MAX_RESEED_SECONDS) {

        this.reseed(addin)

        if len(addin) > 0 {
            addin = []byte{}
        }
    }

    if len(addin) > 0 {
        var W []byte

        // W = sm3(0x02 || V || addin)
        sm3 = New()
        sm3.Write(num[2:3])
        sm3.Write(this.V[:])
        sm3.Write(addin[:])
        W = sm3.Sum(nil)

        // V = (V + W) mod 2^440
        beAdd(this.V[:], W);
    }

    outlen := len(out)

    // output sm3(V)
    sm3 = New()
    sm3.Write(this.V[:])
    buf := sm3.Sum(nil)
    if (outlen < 32) {
        copy(out, buf[:outlen])
    } else {
        copy(out, buf[:])
    }

    // H = sm3(0x03 || V)
    sm3 = New()
    sm3.Write(num[3:4])
    sm3.Write(this.V[:])
    H = sm3.Sum(nil)

    // V = (V + H + C + reseedCounter) mod 2^440
    beAdd(this.V[:], H)
    beAdd(this.V[:], this.C[:])
    counter[0] = byte(this.reseedCounter >> 24) & 0xff
    counter[1] = byte(this.reseedCounter >> 16) & 0xff
    counter[2] = byte(this.reseedCounter >>  8) & 0xff
    counter[3] = byte(this.reseedCounter      ) & 0xff
    beAdd(this.V[:], counter[:])

    this.reseedCounter++
}

func (this *Rand) reseed(addin []byte) {
    var df *DF
    var entropy [512]byte

    // get_entropy, 512-byte might be too long for some system RNGs
    if (!randomBytes(entropy[:], 256) || !randomBytes(entropy[256:], 256)) {
        panic("rand bytes error")
    }

    // V = sm3_df(0x01 || entropy || V || appin)
    df = NewDF()
    df.Write(num[1:2])
    df.Write(entropy[:])
    df.Write(this.V[:])
    df.Write(addin[:])
    this.V = df.Sum()

    // C = sm3_df(0x00 || V)
    df = NewDF()
    df.Write(num[0:1])
    df.Write(this.V[:])
    this.C = df.Sum()

    // reseedCounter = 1, last_ressed_time = now()
    this.reseedCounter = 1
    this.lastReseedTime = time.Now()
}

func beAdd(r []byte, a []byte) {
    var i, j, carry int32 = 0, 0, 0

    for i, j = 54, int32(len(a) - 1); j >= 0; i, j = i-1, j-1 {
        carry += int32(r[i] + a[j])
        r[i] = byte(carry) & 0xff
        carry >>= 8
    }

    for ; i >= 0; i-- {
        carry += int32(r[i])
        r[i] = byte(carry) & 0xff
        carry >>= 8
    }
}

// rand bytes
func randomBytes(bytes []byte, length uint) bool  {
    charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

    b := make([]byte, length)
    for i := range b {
        b[i] = charset[rand.Int63()%int64(len(charset))]
    }

    copy(bytes[:length], b)

    return true
}
