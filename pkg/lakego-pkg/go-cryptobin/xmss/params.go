package xmss

import (
    "math"
    "hash"
    "errors"
    "crypto/sha256"
)

// Params is a struct for parameters
type Params struct {
    hash        func() hash.Hash
    n           int
    paddingLen  int
    w           int
    log2w       uint
    len1        uint32
    len2        uint32
    wlen        uint32
    wotsSignLen uint32
    fullHeight  int
    d           int
    treeHeight  uint32
    indexBytes  uint32
    prvBytes    uint32
    pubBytes    uint32
    signBytes   uint32
}

func NewParams(hashFunc func() hash.Hash, n, w, h, d, paddingLen int) *Params {
    log2w := uint(math.Log2(float64(w)))
    len1 := uint32(math.Ceil(float64(8 * n / int(log2w))))
    len2 := uint32(math.Floor(math.Log2(float64(len1*uint32(w-1)))/math.Log2(float64(w)))) + 1 // len2 = 3

    wlen := len1 + len2
    wotsSignLen := wlen * uint32(n)

    treeHeight := uint32(h / d)

    var indexBytes uint32
    if d == 1 {
        indexBytes = uint32(4)
    } else {
        indexBytes = uint32((h + 7) / 8)
    }

    prvBytes := indexBytes + uint32(4*n)
    pubBytes := uint32(2 * n)
    signBytes := uint32(indexBytes + uint32(n) + uint32(d)*wotsSignLen + uint32(h*n))

    return &Params{
        hash:        hashFunc,
        n:           n,
        w:           w,
        log2w:       log2w,
        len1:        len1,
        len2:        len2,
        wlen:        wlen,
        wotsSignLen: wotsSignLen,
        fullHeight:  h,
        d:           d,
        paddingLen:  paddingLen,
        treeHeight:  treeHeight,
        indexBytes:  indexBytes,
        prvBytes:    prvBytes,
        pubBytes:    pubBytes,
        signBytes:   signBytes,
    }
}

// SignBytes the length of the signature based on a given parameter set
func (params *Params) SignBytes() int {
    return int(params.signBytes)
}

func (params *Params) Hash() hash.Hash {
    return params.hash()
}

var oids = map[uint32]string{
    0x00000001: "XMSS-SHA2_10_256",
    0x00000002: "XMSS-SHA2_16_256",
    0x00000003: "XMSS-SHA2_20_256",
    0x00000004: "XMSS-SHA2_10_512",
    0x00000005: "XMSS-SHA2_16_512",
    0x00000006: "XMSS-SHA2_20_512",
}

func GetOidByName(name string) (uint32, error) {
    for oid, n := range oids {
        if n == name {
            return oid, nil
        }
    }

    return 0, errors.New("no support name")
}

func GetNameByOid(oid uint32) (string, error) {
    for o, name := range oids {
        if o == oid {
            return name, nil
        }
    }

    return "", errors.New("no support oid")
}

func NewParamsWithOid(oid uint32) (*Params, error) {
    switch (oid) {
        case 0x00000001:
            // SHA2_10_256 is parameter set using SHA-256 with n = 32, w = 16 and a Merkle Tree of height 10
            return NewParams(sha256.New, 32, 16, 10, 1, 32), nil
        case 0x00000002:
            // SHA2_16_256 is parameter set using SHA-256 with n = 32, w = 16 and a Merkle Tree of height 16
            return NewParams(sha256.New, 32, 16, 16, 1, 32), nil
        case 0x00000003:
            // SHA2_20_256 is parameter set using SHA-256 with n = 32, w = 16 and a Merkle Tree of height 20
            return NewParams(sha256.New, 32, 16, 20, 1, 32), nil
        case 0x00000004:
            return NewParams(sha256.New, 64, 16, 10, 1, 64), nil
        case 0x00000005:
            return NewParams(sha256.New, 64, 16, 16, 1, 64), nil
        case 0x00000006:
            return NewParams(sha256.New, 64, 16, 20, 1, 64), nil
    }

    return nil, errors.New("no support oid")
}

func NewParamsWithName(name string) (*Params, error) {
    oid, err := GetOidByName(name)
    if err != nil {
        return nil, err
    }

    return NewParamsWithOid(oid)
}
