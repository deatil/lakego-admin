package xmssmt

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
    0x00000001: "XMSSMT-SHA2_20/2_256",
    0x00000002: "XMSSMT-SHA2_20/4_256",
    0x00000003: "XMSSMT-SHA2_40/2_256",
    0x00000004: "XMSSMT-SHA2_40/4_256",
    0x00000005: "XMSSMT-SHA2_40/8_256",
    0x00000006: "XMSSMT-SHA2_60/3_256",
    0x00000007: "XMSSMT-SHA2_60/6_256",
    0x00000008: "XMSSMT-SHA2_60/12_256",
    0x00000009: "XMSSMT-SHA2_20/2_512",
    0x0000000a: "XMSSMT-SHA2_20/4_512",
    0x0000000b: "XMSSMT-SHA2_40/2_512",
    0x0000000c: "XMSSMT-SHA2_40/4_512",
    0x0000000d: "XMSSMT-SHA2_40/8_512",
    0x0000000e: "XMSSMT-SHA2_60/3_512",
    0x0000000f: "XMSSMT-SHA2_60/6_512",
    0x00000010: "XMSSMT-SHA2_60/12_512",
    0x00000011: "XMSSMT-SHAKE_20/2_256",
    0x00000012: "XMSSMT-SHAKE_20/4_256",
    0x00000013: "XMSSMT-SHAKE_40/2_256",
    0x00000014: "XMSSMT-SHAKE_40/4_256",
    0x00000015: "XMSSMT-SHAKE_40/8_256",
    0x00000016: "XMSSMT-SHAKE_60/3_256",
    0x00000017: "XMSSMT-SHAKE_60/6_256",
    0x00000018: "XMSSMT-SHAKE_60/12_256",
    0x00000019: "XMSSMT-SHAKE_20/2_512",
    0x0000001a: "XMSSMT-SHAKE_20/4_512",
    0x0000001b: "XMSSMT-SHAKE_40/2_512",
    0x0000001c: "XMSSMT-SHAKE_40/4_512",
    0x0000001d: "XMSSMT-SHAKE_40/8_512",
    0x0000001e: "XMSSMT-SHAKE_60/3_512",
    0x0000001f: "XMSSMT-SHAKE_60/6_512",
    0x00000020: "XMSSMT-SHAKE_60/12_512",
    0x00000021: "XMSSMT-SHA2_20/2_192",
    0x00000022: "XMSSMT-SHA2_20/4_192",
    0x00000023: "XMSSMT-SHA2_40/2_192",
    0x00000024: "XMSSMT-SHA2_40/4_192",
    0x00000025: "XMSSMT-SHA2_40/8_192",
    0x00000026: "XMSSMT-SHA2_60/3_192",
    0x00000027: "XMSSMT-SHA2_60/6_192",
    0x00000028: "XMSSMT-SHA2_60/12_192",
    0x00000029: "XMSSMT-SHAKE256_20/2_256",
    0x0000002a: "XMSSMT-SHAKE256_20/4_256",
    0x0000002b: "XMSSMT-SHAKE256_40/2_256",
    0x0000002c: "XMSSMT-SHAKE256_40/4_256",
    0x0000002d: "XMSSMT-SHAKE256_40/8_256",
    0x0000002e: "XMSSMT-SHAKE256_60/3_256",
    0x0000002f: "XMSSMT-SHAKE256_60/6_256",
    0x00000030: "XMSSMT-SHAKE256_60/12_256",
    0x00000031: "XMSSMT-SHAKE256_20/2_192",
    0x00000032: "XMSSMT-SHAKE256_20/4_192",
    0x00000033: "XMSSMT-SHAKE256_40/2_192",
    0x00000034: "XMSSMT-SHAKE256_40/4_192",
    0x00000035: "XMSSMT-SHAKE256_40/8_192",
    0x00000036: "XMSSMT-SHAKE256_60/3_192",
    0x00000037: "XMSSMT-SHAKE256_60/6_192",
    0x00000038: "XMSSMT-SHAKE256_60/12_192",
}

func GetOidByName(name string) (uint32, error) {
    for oid, n := range oids {
        if n == name {
            return oid, nil
        }
    }

    return 0, errors.New("go-cryptobin/xmssmt: no support name")
}

func GetNameByOid(oid uint32) (string, error) {
    for o, name := range oids {
        if o == oid {
            return name, nil
        }
    }

    return "", errors.New("go-cryptobin/xmssmt: no support oid")
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
             0x00000007,
             0x00000008,
             0x00000009,
             0x0000000a,
             0x0000000b,
             0x0000000c,
             0x0000000d,
             0x0000000e,
             0x0000000f,
             0x00000010,

             0x00000021,
             0x00000022,
             0x00000023,
             0x00000024,
             0x00000025,
             0x00000026,
             0x00000027,
             0x00000028:
            hasher = sha256.New

        case 0x00000011,
             0x00000012,
             0x00000013,
             0x00000014,
             0x00000015,
             0x00000016,
             0x00000017,
             0x00000018:
            hasher = newShake128

        case 0x00000019,
             0x0000001a,
             0x0000001b,
             0x0000001c,
             0x0000001e,
             0x0000001d,
             0x0000001f,
             0x00000020,

             0x00000029,
             0x0000002a,
             0x0000002b,
             0x0000002c,
             0x0000002d,
             0x0000002e,
             0x0000002f,
             0x00000030,
             0x00000031,
             0x00000032,
             0x00000033,
             0x00000034,
             0x00000035,
             0x00000036,
             0x00000037,
             0x00000038:
            hasher = newShake256

        default:
            return nil, errors.New("go-cryptobin/xmssmt: oid unsported")
    }

    switch (oid) {
        case 0x00000021,
             0x00000022,
             0x00000023,
             0x00000024,
             0x00000025,
             0x00000026,
             0x00000027,
             0x00000028,

             0x00000031,
             0x00000032,
             0x00000033,
             0x00000034,
             0x00000035,
             0x00000036,
             0x00000037,
             0x00000038:
            n = 24
            paddingLen = 4

        case 0x00000001,
             0x00000002,
             0x00000003,
             0x00000004,
             0x00000005,
             0x00000006,
             0x00000007,
             0x00000008,

             0x00000011,
             0x00000012,
             0x00000013,
             0x00000014,
             0x00000015,
             0x00000016,
             0x00000017,
             0x00000018,

             0x00000029,
             0x0000002a,
             0x0000002b,
             0x0000002c,
             0x0000002d,
             0x0000002e,
             0x0000002f,
             0x00000030:
            n = 32
            paddingLen = 32

        case 0x00000009,
             0x0000000a,
             0x0000000b,
             0x0000000c,
             0x0000000d,
             0x0000000e,
             0x0000000f,
             0x00000010,

             0x00000019,
             0x0000001a,
             0x0000001b,
             0x0000001c,
             0x0000001d,
             0x0000001e,
             0x0000001f,
             0x00000020:
            n = 64
            paddingLen = 64

        default:
            return nil, errors.New("go-cryptobin/xmssmt: oid unsported")
    }

    switch (oid) {
        case 0x00000001,
             0x00000002,

             0x00000009,
             0x0000000a,

             0x00000011,
             0x00000012,

             0x00000019,
             0x0000001a,

             0x00000021,
             0x00000022,

             0x00000029,
             0x0000002a,

             0x00000031,
             0x00000032:
            h = 20

        case 0x00000003,
             0x00000004,
             0x00000005,

             0x0000000b,
             0x0000000c,
             0x0000000d,

             0x00000013,
             0x00000014,
             0x00000015,

             0x0000001b,
             0x0000001c,
             0x0000001d,

             0x00000023,
             0x00000024,
             0x00000025,

             0x0000002b,
             0x0000002c,
             0x0000002d,

             0x00000033,
             0x00000034,
             0x00000035:
            h = 40

        case 0x00000006,
             0x00000007,
             0x00000008,

             0x0000000e,
             0x0000000f,
             0x00000010,

             0x00000016,
             0x00000017,
             0x00000018,

             0x0000001e,
             0x0000001f,
             0x00000020,

             0x00000026,
             0x00000027,
             0x00000028,

             0x0000002e,
             0x0000002f,
             0x00000030,

             0x00000036,
             0x00000037,
             0x00000038:
            h = 60

        default:
            return nil, errors.New("go-cryptobin/xmssmt: oid unsported")
    }

    switch (oid) {
        case 0x00000001,
             0x00000003,
             0x00000009,
             0x0000000b,
             0x00000011,
             0x00000013,
             0x00000019,
             0x0000001b,
             0x00000021,
             0x00000023,
             0x00000029,
             0x0000002b,
             0x00000031,
             0x00000033:
            d = 2

        case 0x00000002,
             0x00000004,
             0x0000000a,
             0x0000000c,
             0x00000012,
             0x00000014,
             0x0000001a,
             0x0000001c,
             0x00000022,
             0x00000024,
             0x0000002a,
             0x0000002c,
             0x00000032,
             0x00000034:
            d = 4

        case 0x00000005,
             0x0000000d,
             0x00000015,
             0x0000001d,
             0x00000025,
             0x0000002d,
             0x00000035:
            d = 8

        case 0x00000006,
             0x0000000e,
             0x00000016,
             0x0000001e,
             0x00000026,
             0x0000002e,
             0x00000036:
            d = 3

        case 0x00000007,
             0x0000000f,
             0x00000017,
             0x0000001f,
             0x00000027,
             0x0000002f,
             0x00000037:
            d = 6

        case 0x00000008,
             0x00000010,
             0x00000018,
             0x00000020,
             0x00000028,
             0x00000030,
             0x00000038:
            d = 12

        default:
            return nil, errors.New("go-cryptobin/xmssmt: oid unsported")
    }

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
