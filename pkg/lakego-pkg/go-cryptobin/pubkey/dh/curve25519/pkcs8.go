package curve25519

import (
    "fmt"
    "errors"
    "encoding/asn1"
    "crypto/x509/pkix"

    "golang.org/x/crypto/curve25519"
)

var (
    // DH PublicKey oid
    oidPublicKeyDH = asn1.ObjectIdentifier{1, 3, 132, 1, 12}
)

// Marshal privateKey struct
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
    Attributes []asn1.RawValue `asn1:"optional,tag:0"`
}

// Marshal publicKey struct
type pkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

// Parse publicKey struct
type publicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

// Marshal PublicKey to der
func MarshalPublicKey(key *PublicKey) ([]byte, error) {
    var publicKeyBytes []byte
    var publicKeyAlgorithm pkix.AlgorithmIdentifier

    publicKeyAlgorithm.Algorithm = oidPublicKeyDH
    publicKeyAlgorithm.Parameters = asn1.NullRawValue

    publicKeyBytes = key.Y

    pkix := pkixPublicKey{
        Algo: publicKeyAlgorithm,
        BitString: asn1.BitString{
            Bytes:     publicKeyBytes,
            BitLength: 8 * len(publicKeyBytes),
        },
    }

    return asn1.Marshal(pkix)
}

// Parse PublicKey der
func ParsePublicKey(derBytes []byte) (*PublicKey, error) {
    var pki publicKeyInfo
    rest, err := asn1.Unmarshal(derBytes, &pki)
    if err != nil {
        return nil, err
    }

    if len(rest) > 0 {
        err = asn1.SyntaxError{Msg: "trailing data"}
        return nil, err
    }

    algoEq := pki.Algorithm.Algorithm.Equal(oidPublicKeyDH)
    if !algoEq {
        err = errors.New("curve25519: unknown public key algorithm")
        return nil, err
    }

    y := []byte(pki.PublicKey.RightAlign())

    pub := &PublicKey{}
    pub.Y = y

    return pub, nil
}

// Marshal PrivateKey to der
func MarshalPrivateKey(key *PrivateKey) ([]byte, error) {
    var privKey pkcs8

    privKey.Algo = pkix.AlgorithmIdentifier{
        Algorithm:  oidPublicKeyDH,
        Parameters: asn1.NullRawValue,
    }

    privKey.PrivateKey = key.X

    return asn1.Marshal(privKey)
}

// Parse PrivateKey der
func ParsePrivateKey(derBytes []byte) (*PrivateKey, error) {
    var privKey pkcs8
    var err error

    _, err = asn1.Unmarshal(derBytes, &privKey)
    if err != nil {
        return nil, err
    }

    switch {
        case privKey.Algo.Algorithm.Equal(oidPublicKeyDH):
            x := privKey.PrivateKey

            priv := &PrivateKey{}
            priv.X = x

            var pri, pub [32]byte
            copy(pri[:], x)

            curve25519.ScalarBaseMult(&pub, &pri)

            // 算出 Y 值
            priv.Y = pub[:]

            return priv, nil

        default:
            err = fmt.Errorf("curve25519: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
            return nil, err
    }
}
