package drbg

import (
    "hash"
    "bytes"
    "errors"
    "crypto/hmac"
)

type hmacDRBG struct {
    h func() hash.Hash
    hashSize int

    v             []byte
    key           []byte
    reseedCounter uint64
}

func NewHMAC(h func() hash.Hash, entropy, nonce, personalstr []byte) (*hmacDRBG, error) {
    if len(entropy) <= 0 ||  len(entropy) >= MAX_BYTES {
        return nil, errors.New("invalid entropy length")
    }

    if len(nonce) == 0 || len(nonce) >= MAX_BYTES>>1 {
        return nil, errors.New("invalid nonce length")
    }

    if len(personalstr) >= MAX_BYTES {
        return nil, errors.New("personalization is too long")
    }

    d := &hmacDRBG{
        h: h,
        hashSize: h().Size(),
    }
    d.init(entropy, nonce, personalstr)

    return d, nil
}

func (d *hmacDRBG) init(entropy, nonce, personalstr []byte) {
    var seedMaterial bytes.Buffer
    seedMaterial.Write(entropy)
    seedMaterial.Write(nonce)
    seedMaterial.Write(personalstr)

    d.key = make([]byte, d.hashSize)

    d.v = make([]byte, d.hashSize)
    for i := range d.v {
        d.v[i] = 0x01
    }

    d.update(seedMaterial.Bytes())

    d.reseedCounter = 1
}

func (d *hmacDRBG) Reseed(entropy, additional []byte) error {
    if len(entropy) <= 0 ||  len(entropy) >= MAX_BYTES {
        return errors.New("invalid entropy length")
    }

    if len(additional) >= MAX_BYTES {
        return errors.New("additional input too long")
    }

    var seedMaterial bytes.Buffer
    seedMaterial.Write(entropy)
    seedMaterial.Write(additional)

    d.update(seedMaterial.Bytes())

    d.reseedCounter = 1

    return nil
}

func (d *hmacDRBG) Generate(out, additional []byte) error {
    if d.reseedCounter > 1<<48 {
        return ErrReseedRequired
    }

    if len(additional) > 0 {
        d.update(additional)
    }

    var temp bytes.Buffer

    h := hmac.New(d.h, d.key)

    for temp.Len() < len(out) {
        h.Reset()
        h.Write(d.v)
        d.v = h.Sum(nil)

        temp.Write(d.v)
    }

    copy(out, temp.Bytes())

    d.update(additional)

    d.reseedCounter += 1

    return nil
}

func (d *hmacDRBG) update(providedData []byte) {
    h := hmac.New(d.h, d.key)
    h.Write(d.v)
    h.Write([]byte{0x00})
    h.Write(providedData)
    d.key = h.Sum(nil)

    h = hmac.New(d.h, d.key)
    h.Write(d.v)
    d.v = h.Sum(nil)

    if len(providedData) == 0 {
        return
    }

    h = hmac.New(d.h, d.key)
    h.Write(d.v)
    h.Write([]byte{0x01})
    h.Write(providedData)
    d.key = h.Sum(nil)

    h = hmac.New(d.h, d.key)
    h.Write(d.v)
    d.v = h.Sum(nil)
}
