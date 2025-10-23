package xmss

import (
    "hash"
    "errors"
    "crypto/sha256"

    "golang.org/x/crypto/sha3"

    "github.com/deatil/go-cryptobin/pubkey/xmss"
)

var newShake128 = func() hash.Hash {
    return sha3.NewShake128()
}
var newShake256 = func() hash.Hash {
    return sha3.NewShake256()
}

var oids = map[uint32]string{
    0x00000001: "XMSS-SHA2_10_256",
    0x00000002: "XMSS-SHA2_16_256",
    0x00000003: "XMSS-SHA2_20_256",
    0x00000004: "XMSS-SHA2_10_512",
    0x00000005: "XMSS-SHA2_16_512",
    0x00000006: "XMSS-SHA2_20_512",
    0x00000007: "XMSS-SHAKE_10_256",
    0x00000008: "XMSS-SHAKE_16_256",
    0x00000009: "XMSS-SHAKE_20_256",
    0x0000000a: "XMSS-SHAKE_10_512",
    0x0000000b: "XMSS-SHAKE_16_512",
    0x0000000c: "XMSS-SHAKE_20_512",
    0x0000000d: "XMSS-SHA2_10_192",
    0x0000000e: "XMSS-SHA2_16_192",
    0x0000000f: "XMSS-SHA2_20_192",
    0x00000010: "XMSS-SHAKE256_10_256",
    0x00000011: "XMSS-SHAKE256_16_256",
    0x00000012: "XMSS-SHAKE256_20_256",
    0x00000013: "XMSS-SHAKE256_10_192",
    0x00000014: "XMSS-SHAKE256_16_192",
    0x00000015: "XMSS-SHAKE256_20_192",
}

func GetOidByName(name string) (uint32, error) {
    for oid, n := range oids {
        if n == name {
            return oid, nil
        }
    }

    return 0, errors.New("go-cryptobin/xmss: no support name")
}

func GetNameByOid(oid uint32) (string, error) {
    for o, name := range oids {
        if o == oid {
            return name, nil
        }
    }

    return "", errors.New("go-cryptobin/xmss: no support oid")
}

func NewParamsWithOid(oid uint32) (*xmss.Params, error) {
    var hasher func() hash.Hash
    var n, w, h, d, paddingLen int

    switch (oid) {
        case 0x00000001,
             0x00000002,
             0x00000003,
             0x00000004,
             0x00000005,
             0x00000006,

             0x0000000d,
             0x0000000e,
             0x0000000f:
            hasher = sha256.New

        case 0x00000007,
             0x00000008,
             0x00000009:
            hasher = newShake128

        case 0x0000000a,
             0x0000000b,
             0x0000000c,

             0x00000010,
             0x00000011,
             0x00000012,
             0x00000013,
             0x00000014,
             0x00000015:
            hasher = newShake256

        default:
            return nil, errors.New("go-cryptobin/xmss: oid unsported")
    }

    switch (oid) {
        case 0x0000000d,
             0x0000000e,
             0x0000000f,

             0x00000013,
             0x00000014,
             0x00000015:
            n = 24
            paddingLen = 4

        case 0x00000001,
             0x00000002,
             0x00000003,

             0x00000007,
             0x00000008,
             0x00000009,

             0x00000010,
             0x00000011,
             0x00000012:
            n = 32
            paddingLen = 32

        case 0x00000004,
             0x00000005,
             0x00000006,

             0x0000000a,
             0x0000000b,
             0x0000000c:
            n = 64
            paddingLen = 64

        default:
            return nil, errors.New("go-cryptobin/xmss: oid unsported")
    }

    switch (oid) {
        case 0x00000001,
             0x00000004,
             0x00000007,
             0x0000000a,
             0x0000000d,
             0x00000010,
             0x00000013:
            h = 10
            break

        case 0x00000002,
             0x00000005,
             0x00000008,
             0x0000000b,
             0x0000000e,
             0x00000011,
             0x00000014:
            h = 16
            break

        case 0x00000003,
             0x00000006,
             0x00000009,
             0x0000000c,
             0x0000000f,
             0x00000012,
             0x00000015:
            h = 20

            break
        default:
            return nil, errors.New("go-cryptobin/xmss: oid unsported")
    }

    d = 1
    w = 16

    return xmss.NewParams(hasher, n, w, h, d, paddingLen), nil
}

func NewParamsWithName(name string) (*xmss.Params, error) {
    oid, err := GetOidByName(name)
    if err != nil {
        return nil, err
    }

    return NewParamsWithOid(oid)
}
