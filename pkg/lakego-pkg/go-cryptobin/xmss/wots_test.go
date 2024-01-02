package xmss

import (
    "bytes"
    "crypto/rand"
    "testing"
)

// Randomly initialize address, for testing purposes only
func (a *address) initRandom() {
    randBytes := make([]byte, 32)
    rand.Read(randBytes)
    for i := 0; i < 32; i += 4 {
        a[i/4] = bytesToUint32(randBytes[i : i+4])
    }
}

func TestWOTS(t *testing.T) {
    t.Parallel()
    // For WOTS+ tests, the parameter set doesn't matter since n, w and wlen are identical
    params := SHA2_10_256

    seed := make([]byte, params.n)
    rand.Read(seed)
    pubSeed := make([]byte, params.n)
    rand.Read(pubSeed)
    m := make([]byte, params.n)
    rand.Read(m)

    var a address
    a.initRandom()

    prv := *generatePrivate(params, seed)
    pub1 := *prv.generatePublic(params, pubSeed, &a)
    sign := *prv.sign(params, m, pubSeed, &a)
    pub2 := *sign.getPublic(params, m, pubSeed, &a)

    if !bytes.Equal(pub1, pub2) {
        t.Error("WOTS+ test failed. Public keys do not match")
    }

}
