package sm9

import (
    "errors"
    "reflect"
    "math/big"
    "encoding/asn1"
    "crypto/x509/pkix"

    "golang.org/x/crypto/cryptobyte"
    cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
    oidSM9     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302}
    oidSM9Sign = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302, 1}
    oidSM9Enc  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302, 3}
)

// pkcs8
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
    Attributes []asn1.RawValue `asn1:"optional,tag:0"`
}

// pkcs8 attribute info
type pkcs8Attribute struct {
    Id     asn1.ObjectIdentifier
    Values []asn1.RawValue `asn1:"set"`
}

type sm9PrivateKey struct {
    PrivateKey asn1.RawValue
    PublicKey  asn1.RawValue
}

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

func ParsePublicKey(der []byte) (key any, err error) {
    var pubkey pkixPublicKey
    if _, err := asn1.Unmarshal(der, &pubkey); err != nil {
        return nil, err
    }

    if !reflect.DeepEqual(pubkey.Algo.Algorithm, oidSM9) {
        return nil, errors.New("x509: not sm2 elliptic curve")
    }

    params := pubkey.Algo.Parameters.FullBytes

    pubOID := new(asn1.ObjectIdentifier)
    _, err = asn1.Unmarshal(params, pubOID)
    if err != nil {
        return
    }

    var bytes []byte

    switch {
        case oidSM9Sign.Equal(*pubOID):
            input := cryptobyte.String(pubkey.BitString.Bytes)
            if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
                return nil, errors.New("sm9: invalid sign user public key asn1 data")
            }

            key, err = NewSignMasterPublicKey(bytes)
            return
        case oidSM9Enc.Equal(*pubOID):
            input := cryptobyte.String(pubkey.BitString.Bytes)
            if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
                return nil, errors.New("sm9: invalid encrypt user public key asn1 data")
            }

            key, err = NewEncryptMasterPublicKey(bytes)
            return
    }

    return nil, errors.New("not support yet")
}

func MarshalPublicKey(key any) ([]byte, error) {
    var r pkixPublicKey
    var algo pkix.AlgorithmIdentifier

    var pubBytes []byte
    var oidBytes []byte
    var err error

    switch k := key.(type) {
        case *SignMasterPublicKey:
            pubBytes = k.Mpk.MarshalUncompressed()
            oidBytes, err = asn1.Marshal(oidSM9Sign)
        case *EncryptMasterPublicKey:
            pubBytes = k.Mpk.MarshalUncompressed()
            oidBytes, err = asn1.Marshal(oidSM9Enc)
        default:
            return nil, errors.New("sm9: no support key algo")
    }

    if err != nil {
        return nil, errors.New("sm9: failed to marshal algo param: " + err.Error())
    }

    algo.Algorithm = oidSM9
    algo.Parameters.Class = 0
    algo.Parameters.Tag = 6
    algo.Parameters.IsCompound = false
    algo.Parameters.FullBytes = oidBytes

    var b cryptobyte.Builder
    b.AddASN1BitString(pubBytes)
    pub, err := b.Bytes()
    if err != nil {
        return nil, err
    }

    r.Algo = algo
    r.BitString = asn1.BitString{
        Bytes: pub,
    }

    return asn1.Marshal(r)
}

// =============

func ParsePrivateKey(der []byte) (any, error) {
    var privKey pkcs8
    if _, err := asn1.Unmarshal(der, &privKey); err != nil {
        return nil, err
    }

    if privKey.Algo.Algorithm.Equal(oidSM9) ||
        privKey.Algo.Algorithm.Equal(oidSM9Sign) ||
        privKey.Algo.Algorithm.Equal(oidSM9Enc) {
        return parsePrivateKey(privKey)
    }

    return nil, errors.New("sm9: unknown private key algorithm")
}

func MarshalPrivateKey(key any) ([]byte, error) {
    switch k := key.(type) {
        case *SignPrivateKey:
            return marshalSignPrivateKey(k)
        case *EncryptPrivateKey:
            return marshalEncPrivateKey(k)
        case *SignMasterPrivateKey:
            return marshalSignMasterPrivateKey(k)
        case *EncryptMasterPrivateKey:
            return marshalEncMasterPrivateKey(k)
    }

    return nil, errors.New("key error")
}

// =============

func parsePrivateKey(privKey pkcs8) (key any, err error) {
    var bytes []byte
    var inner cryptobyte.String
    var pubBytes []byte

    switch {
        case privKey.Algo.Algorithm.Equal(oidSM9Sign):
            input := cryptobyte.String(privKey.PrivateKey)

            if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
                !input.Empty() ||
                !inner.ReadASN1BitStringAsBytes(&bytes) {
                return nil, errors.New("sm9: invalid sign user private key asn1 data")
            }
            if !inner.Empty() && (!inner.ReadASN1BitStringAsBytes(&pubBytes) || !inner.Empty()) {
                return nil, errors.New("sm9: invalid sign user private key asn1 data")
            }

            priBytes := append(bytes, pubBytes...)

            key, err = NewSignPrivateKey(priBytes)
            return
        case privKey.Algo.Algorithm.Equal(oidSM9Enc):
            input := cryptobyte.String(privKey.PrivateKey)

            if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
                !input.Empty() ||
                !inner.ReadASN1BitStringAsBytes(&bytes) {
                return nil, errors.New("sm9: invalid encrypt user private key asn1 data")
            }
            if !inner.Empty() && (!inner.ReadASN1BitStringAsBytes(&pubBytes) || !inner.Empty()) {
                return nil, errors.New("sm9: invalid encrypt user private key asn1 data")
            }

            priBytes := append(bytes, pubBytes...)

            key, err = NewEncryptPrivateKey(priBytes)
            return
        case privKey.Algo.Algorithm.Equal(oidSM9):
            bytes := privKey.Algo.Parameters.FullBytes

            priOID := new(asn1.ObjectIdentifier)
            _, err = asn1.Unmarshal(bytes, priOID)
            if err != nil {
                return
            }

            d := &big.Int{}

            switch {
                case oidSM9Sign.Equal(*priOID):
                    input := cryptobyte.String(privKey.PrivateKey)

                    if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
                        !input.Empty() ||
                        !inner.ReadASN1Integer(d) {
                        return nil, errors.New("sm9: invalid sign master private key asn1 data")
                    }
                    if !inner.Empty() && (!inner.ReadASN1BitStringAsBytes(&pubBytes) || !inner.Empty()) {
                        return nil, errors.New("sm9: invalid sign master private key asn1 data")
                    }

                    key, err = NewSignMasterPrivateKey(d.Bytes())
                    return
                case oidSM9Enc.Equal(*priOID):
                    input := cryptobyte.String(privKey.PrivateKey)

                    if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
                        !input.Empty() ||
                        !inner.ReadASN1Integer(d) {
                        return nil, errors.New("sm9: invalid encrypt master private key asn1 data")
                    }
                    if !inner.Empty() && (!inner.ReadASN1BitStringAsBytes(&pubBytes) || !inner.Empty()) {
                        return nil, errors.New("sm9: invalid encrypt master private key asn1 data")
                    }

                    key, err = NewEncryptMasterPrivateKey(d.Bytes())
                    return
            }
    }

    return nil, errors.New("not support yet")
}

// =============

func marshalSignPrivateKey(k *SignPrivateKey) ([]byte, error) {
    var privKey pkcs8
    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidSM9Sign,
        Parameters: asn1.NullRawValue,
    }

    var b cryptobyte.Builder
    b.AddASN1BitString(k.Sk.MarshalUncompressed())
    privans1, err := b.Bytes()
    if err != nil {
        return nil, err
    }

    var pub cryptobyte.Builder
    pub.AddASN1BitString(k.Mpk.MarshalUncompressed())
    pubasn1, err := pub.Bytes()
    if err != nil {
        return nil, err
    }

    key := sm9PrivateKey{}
    key.PrivateKey.FullBytes = privans1
    key.PublicKey.FullBytes = pubasn1

    if privKey.PrivateKey, err = asn1.Marshal(key); err != nil {
        return nil, errors.New("sm9: failed to marshal sm9 sign private key while building PKCS#8: " + err.Error())
    }

    return asn1.Marshal(privKey)
}

func marshalEncPrivateKey(k *EncryptPrivateKey) ([]byte, error) {
    var privKey pkcs8
    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidSM9Enc,
        Parameters: asn1.NullRawValue,
    }

    var b cryptobyte.Builder
    b.AddASN1BitString(k.Sk.MarshalUncompressed())
    privans1, err := b.Bytes()
    if err != nil {
        return nil, err
    }

    var pub cryptobyte.Builder
    pub.AddASN1BitString(k.Mpk.MarshalUncompressed())
    pubasn1, err := pub.Bytes()
    if err != nil {
        return nil, err
    }

    key := sm9PrivateKey{}
    key.PrivateKey.FullBytes = privans1
    key.PublicKey.FullBytes = pubasn1

    if privKey.PrivateKey, err = asn1.Marshal(key); err != nil {
        return nil, errors.New("sm9: failed to marshal sm9 encrypt private key while building PKCS#8: " + err.Error())
    }

    return asn1.Marshal(privKey)
}

func marshalSignMasterPrivateKey(k *SignMasterPrivateKey) ([]byte, error) {
    var privKey pkcs8
    oidBytes, err := asn1.Marshal(oidSM9Sign)
    if err != nil {
        return nil, errors.New("sm9: failed to marshal SM9 OID: " + err.Error())
    }

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm: oidSM9,
        Parameters: asn1.RawValue{
            FullBytes: oidBytes,
        },
    }

    var pri cryptobyte.Builder
    pri.AddASN1BigInt(k.D)
    privans1, err := pri.Bytes()
    if err != nil {
        return nil, err
    }

    var pub cryptobyte.Builder
    pub.AddASN1BitString(k.Mpk.MarshalUncompressed())
    pubasn1, err := pub.Bytes()
    if err != nil {
        return nil, err
    }

    key := sm9PrivateKey{}
    key.PrivateKey.FullBytes = privans1
    key.PublicKey.FullBytes = pubasn1

    if privKey.PrivateKey, err = asn1.Marshal(key); err != nil {
        return nil, errors.New("sm9: failed to marshal sm9 sign master private key while building PKCS#8: " + err.Error())
    }

    return asn1.Marshal(privKey)
}

func marshalEncMasterPrivateKey(k *EncryptMasterPrivateKey) ([]byte, error) {
    var privKey pkcs8
    oidBytes, err := asn1.Marshal(oidSM9Enc)
    if err != nil {
        return nil, errors.New("sm9: failed to marshal SM9 OID: " + err.Error())
    }

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm: oidSM9,
        Parameters: asn1.RawValue{
            FullBytes: oidBytes,
        },
    }

    var pri cryptobyte.Builder
    pri.AddASN1BigInt(k.D)
    privans1, err := pri.Bytes()
    if err != nil {
        return nil, err
    }

    var pub cryptobyte.Builder
    pub.AddASN1BitString(k.Mpk.MarshalUncompressed())
    pubasn1, err := pub.Bytes()
    if err != nil {
        return nil, err
    }

    key := sm9PrivateKey{}
    key.PrivateKey.FullBytes = privans1
    key.PublicKey.FullBytes = pubasn1

    if privKey.PrivateKey, err = asn1.Marshal(key); err != nil {
        return nil, errors.New("sm9: failed to marshal sm9 encrypt master private key while building PKCS#8: " + err.Error())
    }

    return asn1.Marshal(privKey)
}
