package gost

import (
    "errors"
    "math/big"
    "encoding/asn1"
    "crypto/x509/pkix"

    "golang.org/x/crypto/cryptobyte"
)

var (
    // PublicKey oid
    oidGOSTPublicKey         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 19}
    oidGost2012PublicKey256  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
    oidGost2012PublicKey512  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}

    // Digest oid
    oidGost94Digest = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 9}

    // param digest oid
    oidCryptoProDigestA  = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 30, 1}
    oidGost2012Digest256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
    oidGost2012Digest512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}

    oidGostR3410_2001_TestParamSet         = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 0}
    oidGostR3410_2001_CryptoPro_A_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1}
    oidGostR3410_2001_CryptoPro_B_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 2}
    oidGostR3410_2001_CryptoPro_C_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 3}

    /* OID for EC DH */
    oidGostR3410_2001_CryptoPro_XchA_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0}
    oidGostR3410_2001_CryptoPro_XchB_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 1}

    oidTc26_gost_3410_12_256_paramSetA = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
    oidTc26_gost_3410_12_256_paramSetB = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}
    oidTc26_gost_3410_12_256_paramSetC = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 3}
    oidTc26_gost_3410_12_256_paramSetD = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 4}

    oidTc26_gost_3410_12_512_paramSetTest = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 0}
    oidTc26_gost_3410_12_512_paramSetA    = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}
    oidTc26_gost_3410_12_512_paramSetB    = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}
    oidTc26_gost_3410_12_512_paramSetC    = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}
    oidTc26_gost_3410_12_512_paramSetD    = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 4}

    oidCryptoPro2012Sign256A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
    oidCryptoPro2012Sign256B = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}
    oidCryptoPro2012Sign256C = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 3}
    oidCryptoPro2012Sign256D = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 4}

    oidCryptoPro2012Sign512Test = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 0}
    oidCryptoPro2012Sign512A    = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}
    oidCryptoPro2012Sign512B    = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}
    oidCryptoPro2012Sign512C    = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}
    oidCryptoPro2012Sign512D    = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 4}
)

func init() {
    AddNamedCurve(CurveIdGostR34102001TestParamSet(),       oidGostR3410_2001_TestParamSet)
    AddNamedCurve(CurveIdGostR34102001CryptoProAParamSet(), oidGostR3410_2001_CryptoPro_A_ParamSet)
    AddNamedCurve(CurveIdGostR34102001CryptoProBParamSet(), oidGostR3410_2001_CryptoPro_B_ParamSet)
    AddNamedCurve(CurveIdGostR34102001CryptoProCParamSet(), oidGostR3410_2001_CryptoPro_C_ParamSet)

    AddNamedCurve(CurveIdGostR34102001CryptoProXchAParamSet(), oidGostR3410_2001_CryptoPro_XchA_ParamSet)
    AddNamedCurve(CurveIdGostR34102001CryptoProXchBParamSet(), oidGostR3410_2001_CryptoPro_XchB_ParamSet)

    AddNamedCurve(CurveIdtc26gost34102012256paramSetA(), oidCryptoPro2012Sign256A)
    AddNamedCurve(CurveIdtc26gost34102012256paramSetB(), oidCryptoPro2012Sign256B)
    AddNamedCurve(CurveIdtc26gost34102012256paramSetC(), oidCryptoPro2012Sign256C)
    AddNamedCurve(CurveIdtc26gost34102012256paramSetD(), oidCryptoPro2012Sign256D)

    AddNamedCurve(CurveIdtc26gost34102012512paramSetTest(), oidCryptoPro2012Sign512Test)
    AddNamedCurve(CurveIdtc26gost34102012512paramSetA(),    oidCryptoPro2012Sign512A)
    AddNamedCurve(CurveIdtc26gost34102012512paramSetB(),    oidCryptoPro2012Sign512B)
    AddNamedCurve(CurveIdtc26gost34102012512paramSetC(),    oidCryptoPro2012Sign512C)
}

// gost version
const gostPrivKeyVersion = 1

// Gost param type mode
type ParamMode uint

const (
    Gost2001Param ParamMode = iota
    Gost2012Param
)

// Param Opts
type ParamOpts struct {
    Mode         ParamMode
    DigestOid    asn1.ObjectIdentifier
    PublicKeyOid asn1.ObjectIdentifier
}

// set default options
var DefaultParamOpts = ParamOpts{
    Mode: Gost2012Param,
}

// pkcs8 info
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

// Key Algo
type keyAlgoParam struct {
    Curve  asn1.ObjectIdentifier
    Digest asn1.ObjectIdentifier `asn1:"optional"`
}

// PublicKey data
type pkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

// publicKeyInfo parse
type publicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

// Marshal PublicKey
func MarshalPublicKey(pub *PublicKey) ([]byte, error) {
    return MarshalPublicKeyWithOpts(pub, DefaultParamOpts)
}

// Marshal PublicKey with options
func MarshalPublicKeyWithOpts(pub *PublicKey, opts ParamOpts) ([]byte, error) {
    var publicKey, publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier
    var err error

    oid, ok := OidFromNamedCurve(pub.Curve)
    if !ok {
        return nil, errors.New("cryptobin/gost: unsupported gost curve")
    }

    keyAlgo := keyAlgoParam{
        Curve: oid,
    }

    if opts.DigestOid != nil {
        keyAlgo.Digest = opts.DigestOid
    } else {
        digestOid, ok := HashOidFromNamedCurve(pub.Curve)
        if ok {
            keyAlgo.Digest = digestOid
        }
    }

    var paramBytes []byte
    paramBytes, err = asn1.Marshal(keyAlgo)
    if err != nil {
        return nil, err
    }

    if opts.PublicKeyOid != nil {
        publicKeyAlgorithm.Algorithm = opts.PublicKeyOid
    } else {
        publicKeyAlgorithm.Algorithm = PublicKeyOidFromNamedCurve(pub.Curve)
    }
    publicKeyAlgorithm.Parameters.FullBytes = paramBytes

    if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
        return nil, errors.New("cryptobin/gost: invalid gost curve public key")
    }

    publicKey = Marshal(pub.Curve, pub.X, pub.Y)

    if opts.Mode == Gost2012Param {
        publicKeyBytes, err = asn1.Marshal(publicKey)
        if err != nil {
            return nil, err
        }
    } else {
        publicKeyBytes = publicKey
    }

    pkix := pkixPublicKey{
        Algo: publicKeyAlgorithm,
        BitString: asn1.BitString{
            Bytes:     publicKeyBytes,
            BitLength: 8 * len(publicKeyBytes),
        },
    }

    return asn1.Marshal(pkix)
}

// Parse PublicKey
func ParsePublicKey(publicKey []byte) (pub *PublicKey, err error) {
    var pki publicKeyInfo
    rest, err := asn1.Unmarshal(publicKey, &pki)
    if err != nil {
        return
    } else if len(rest) != 0 {
        err = errors.New("cryptobin/gost: trailing data after ASN.1 of public-key")
        return
    }

    if len(rest) > 0 {
        err = asn1.SyntaxError{Msg: "trailing data"}
        return
    }

    algo := pki.Algorithm.Algorithm
    params := pki.Algorithm.Parameters
    der := cryptobyte.String(pki.PublicKey.RightAlign())

    if !algo.Equal(oidGOSTPublicKey) &&
        !algo.Equal(oidGost2012PublicKey256) &&
        !algo.Equal(oidGost2012PublicKey512) {
        err = errors.New("cryptobin/gost: unknown public key algorithm")
        return
    }

    var param keyAlgoParam
    if _, err := asn1.Unmarshal(params.FullBytes, &param); err != nil {
        err = errors.New("cryptobin/gost: unknown public key algorithm curve")
        return nil, err
    }

    namedCurve := NamedCurveFromOid(param.Curve)
    if namedCurve == nil {
        err = errors.New("cryptobin/gost: unsupported gost curve")
        return
    }

    x, y := Unmarshal(namedCurve, der)
    if x == nil || y == nil {
        var derBytes []byte
        rest, err = asn1.Unmarshal(der, &derBytes)
        if err != nil {
            return
        } else if len(rest) != 0 {
            err = errors.New("cryptobin/gost: trailing data after ASN.1 of public-key der")
            return
        }

        x, y = Unmarshal(namedCurve, derBytes)
        if x == nil || y == nil {
            err = errors.New("cryptobin/gost: failed to unmarshal gost curve point")
            return
        }
    }

    pub = &PublicKey{
        Curve: namedCurve,
        X:     x,
        Y:     y,
    }

    return
}

// Marshal PrivateKey
func MarshalPrivateKey(priv *PrivateKey) ([]byte, error) {
    return MarshalPrivateKeyWithOpts(priv, DefaultParamOpts)
}

// Marshal PrivateKey with options
func MarshalPrivateKeyWithOpts(priv *PrivateKey, opts ParamOpts) ([]byte, error) {
    oid, ok := OidFromNamedCurve(priv.Curve)
    if !ok {
        return nil, errors.New("cryptobin/gost: unsupported gost curve")
    }

    keyAlgo := keyAlgoParam{
        Curve: oid,
    }

    if opts.DigestOid != nil {
        keyAlgo.Digest = opts.DigestOid
    } else {
        digestOid, ok := HashOidFromNamedCurve(priv.Curve)
        if ok {
            keyAlgo.Digest = digestOid
        }
    }

    // Marshal oid
    oidBytes, err := asn1.Marshal(keyAlgo)
    if err != nil {
        return nil, errors.New("cryptobin/gost: failed to marshal algo param: " + err.Error())
    }

    var publicKeyOid asn1.ObjectIdentifier
    if opts.PublicKeyOid != nil {
        publicKeyOid = opts.PublicKeyOid
    } else {
        publicKeyOid = PublicKeyOidFromNamedCurve(priv.Curve)
    }

    var privKey pkcs8
    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  publicKeyOid,
        Parameters: asn1.RawValue{
            FullBytes: oidBytes,
        },
    }

    privKey.PrivateKey, err = marshalGostPrivateKey(priv, opts)
    if err != nil {
        return nil, errors.New("cryptobin/gost: failed to marshal private key while building PKCS#8: " + err.Error())
    }

    return asn1.Marshal(privKey)
}

// Parse PrivateKey
func ParsePrivateKey(privateKey []byte) (*PrivateKey, error) {
    var privKey pkcs8
    var err error

    _, err = asn1.Unmarshal(privateKey, &privKey)
    if err != nil {
        return nil, err
    }

    algo := privKey.Algo.Algorithm
    if !algo.Equal(oidGOSTPublicKey) &&
        !algo.Equal(oidGost2012PublicKey256) &&
        !algo.Equal(oidGost2012PublicKey512) {
        err = errors.New("cryptobin/gost: unknown private key algorithm")
        return nil, err
    }

    bytes := privKey.Algo.Parameters.FullBytes

    var param keyAlgoParam
    if _, err := asn1.Unmarshal(bytes, &param); err != nil {
        err = errors.New("cryptobin/gost: unknown private key algorithm curve")
        return nil, err
    }

    key, err := parseGostPrivateKey(param.Curve, privKey.PrivateKey)
    if err != nil {
        return nil, errors.New("cryptobin/gost: failed to parse private key embedded in PKCS#8: " + err.Error())
    }

    return key, nil
}

func marshalGostPrivateKey(key *PrivateKey, opts ParamOpts) ([]byte, error) {
    if !key.Curve.IsOnCurve(key.X, key.Y) {
        return nil, errors.New("invalid gost public key")
    }

    if opts.Mode == Gost2012Param {
        var b cryptobyte.Builder
        b.AddASN1BigInt(key.D)
        return b.Bytes()
    }

    pointSize := key.Curve.PointSize()
    d := key.D.FillBytes(make([]byte, pointSize))

    return Reverse(d), nil
}

func parseGostPrivateKey(namedCurveOID asn1.ObjectIdentifier, der []byte) (key *PrivateKey, err error) {
    var privKey big.Int
    var private []byte

    input := cryptobyte.String(der)
    if !input.ReadASN1Integer(&privKey) {
        private = make([]byte, len(der))
        copy(private, Reverse(der))
    } else {
        private = privKey.Bytes()
    }

    curve := NamedCurveFromOid(namedCurveOID)
    if curve == nil {
        return nil, errors.New("unknown gost curve")
    }

    return newPrivateKey(curve, private)
}

// get PublicKey oid
func PublicKeyOidFromNamedCurve(curve *Curve) asn1.ObjectIdentifier {
    switch {
        case curve.Equal(CurveIdGostR34102001TestParamSet()),
            curve.Equal(CurveIdGostR34102001CryptoProAParamSet()),
            curve.Equal(CurveIdGostR34102001CryptoProBParamSet()),
            curve.Equal(CurveIdGostR34102001CryptoProCParamSet()),
            curve.Equal(CurveIdGostR34102001CryptoProXchAParamSet()),
            curve.Equal(CurveIdGostR34102001CryptoProXchBParamSet()),
            curve.Equal(CurveIdtc26gost34102012256paramSetA()),
            curve.Equal(CurveIdtc26gost34102012256paramSetB()),
            curve.Equal(CurveIdtc26gost34102012256paramSetC()),
            curve.Equal(CurveIdtc26gost34102012256paramSetD()):
            return oidGost2012PublicKey256
        case curve.Equal(CurveIdtc26gost34102012512paramSetTest()),
            curve.Equal(CurveIdtc26gost34102012512paramSetA()),
            curve.Equal(CurveIdtc26gost34102012512paramSetB()),
            curve.Equal(CurveIdtc26gost34102012512paramSetC()):
            return oidGost2012PublicKey512
        default:
            return oidGOSTPublicKey
    }
}

// get Hash oid
func HashOidFromNamedCurve(curve *Curve) (asn1.ObjectIdentifier, bool) {
    switch {
        case curve.Equal(CurveIdGostR34102001TestParamSet()),
            curve.Equal(CurveIdGostR34102001CryptoProAParamSet()),
            curve.Equal(CurveIdGostR34102001CryptoProBParamSet()),
            curve.Equal(CurveIdGostR34102001CryptoProCParamSet()),
            curve.Equal(CurveIdGostR34102001CryptoProXchAParamSet()),
            curve.Equal(CurveIdGostR34102001CryptoProXchBParamSet()):
            return oidGost2012Digest256, true
        case curve.Equal(CurveIdtc26gost34102012512paramSetTest()),
            curve.Equal(CurveIdtc26gost34102012512paramSetA()),
            curve.Equal(CurveIdtc26gost34102012512paramSetB()):
            return oidGost2012Digest512, true
        case curve.Equal(CurveGostR34102001ParamSetcc()):
            return oidCryptoProDigestA, true
        default:
            return asn1.ObjectIdentifier{}, false
    }
}
