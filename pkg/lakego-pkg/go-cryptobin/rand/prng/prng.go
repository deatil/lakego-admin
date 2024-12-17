package prng

import (
    "hash"
    "errors"
    "crypto/md5"
    "crypto/sha1"
)

var MD5PRNG = New(md5.New)
var SHA1PRNG = New(sha1.New)

type Prng struct {
    hash func() hash.Hash
    seed []byte
}

func New(hash func() hash.Hash) *Prng {
    return &Prng{
        hash: hash,
        seed: make([]byte, 0),
    }
}

func NewWithSeed(hash func() hash.Hash, seed []byte) *Prng {
    return &Prng{
        hash: hash,
        seed: seed,
    }
}

func (this *Prng) SetSeed(seed []byte) *Prng {
    this.seed = seed

    return this
}

func (this *Prng) Read(b []byte) (n int, err error) {
    hashs := this.makeSha(this.makeSha(this.seed))

    n = len(b)
    if n > len(hashs) {
        return 0, errors.New("invalid length!")
    }

    copy(b, hashs)

    return n, nil
}

func (this *Prng) makeSha(data []byte) []byte {
    h := this.hash()
    h.Write(data)
    return h.Sum(nil)
}
