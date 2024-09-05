package sm3xmss

import (
    "hash"
    "errors"

    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/pubkey/xmss"
)

var oids = map[uint32]string{
    0x00000001: "XMSS-SM3_10_256",
    0x00000002: "XMSS-SM3_16_256",
    0x00000003: "XMSS-SM3_20_256",
}

func GetOidByName(name string) (uint32, error) {
    for oid, n := range oids {
        if n == name {
            return oid, nil
        }
    }

    return 0, errors.New("sm3xmss: no support name")
}

func GetNameByOid(oid uint32) (string, error) {
    for o, name := range oids {
        if o == oid {
            return name, nil
        }
    }

    return "", errors.New("sm3xmss: no support oid")
}

func NewParamsWithOid(oid uint32) (*xmss.Params, error) {
    var hasher func() hash.Hash
    var n, w, h, d, paddingLen int

    switch (oid) {
        case 0x00000001,
             0x00000002,
             0x00000003:
            hasher = sm3.New

        default:
            return nil, errors.New("sm3xmss: oid unsported")
    }

    switch (oid) {
        case 0x00000001,
             0x00000002,
             0x00000003:
            n = 32
            paddingLen = 32

        default:
            return nil, errors.New("sm3xmss: oid unsported")
    }

    switch (oid) {
        case 0x00000001:
            h = 10
            break

        case 0x00000002:
            h = 16
            break

        case 0x00000003:
            h = 20

            break
        default:
            return nil, errors.New("sm3xmss: oid unsported")
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
