package key

import (
    "fmt"
    "errors"
    "encoding/asn1"
    "crypto/ecdsa"
    "crypto/x509"
    "crypto/x509/pkix"
    crypto_ecdh "crypto/ecdh"

    "golang.org/x/crypto/cryptobyte"

    "github.com/deatil/go-cryptobin/ecdh"
)

var (
    oidPublicKeyX448 = asn1.ObjectIdentifier{1, 3, 101, 111}
)

// 私钥 - 包装
type pkcs8 struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
}

// 公钥 - 包装
type pkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

// 公钥信息 - 解析
type publicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

// 包装公钥
func MarshalPublicKey(pub *ecdh.PublicKey) ([]byte, error) {
    if pub.Curve() == ecdh.X448() {
        var publicKeyBytes []byte
        var publicKeyAlgorithm pkix.AlgorithmIdentifier

        publicKeyBytes = pub.Bytes()
        publicKeyAlgorithm.Algorithm = oidPublicKeyX448

        pkix := pkixPublicKey{
            Algo: publicKeyAlgorithm,
            BitString: asn1.BitString{
                Bytes:     publicKeyBytes,
                BitLength: 8 * len(publicKeyBytes),
            },
        }

        ret, _ := asn1.Marshal(pkix)
        return ret, nil
    } else {
        var newCurve crypto_ecdh.Curve

        switch pub.Curve() {
            case ecdh.P256():
                newCurve = crypto_ecdh.P256()
            case ecdh.P384():
                newCurve = crypto_ecdh.P384()
            case ecdh.P521():
                newCurve = crypto_ecdh.P521()
            case ecdh.X25519():
                newCurve = crypto_ecdh.X25519()
            default:
                return nil, fmt.Errorf("x509: unsupported public key type: %T", pub)
        }

        pubkey, err := newCurve.NewPublicKey(pub.Bytes())
        if err != nil {
            return nil, fmt.Errorf("x509: failed to marshal public key: %v", err)
        }

        public, err := x509.MarshalPKIXPublicKey(pubkey)
        if err != nil {
            return nil, fmt.Errorf("x509: failed to marshal public key: %v", err)
        }

        return public, nil
    }
}

// 解析公钥
func ParsePublicKey(derBytes []byte) (*ecdh.PublicKey, error) {
    var pki publicKeyInfo
    if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
        return nil, err
    } else if len(rest) != 0 {
        return nil, errors.New("x509: trailing data after ASN.1 of public-key")
    }

    keyData := &pki

    oid := keyData.Algorithm.Algorithm
    params := keyData.Algorithm.Parameters
    der := cryptobyte.String(keyData.PublicKey.RightAlign())

    switch {
        case oid.Equal(oidPublicKeyX448):
            if len(params.FullBytes) != 0 {
                return nil, errors.New("x509: X25519 key encoded with illegal parameters")
            }

            return ecdh.X448().NewPublicKey(der)
        default:
            key, err := x509.ParsePKIXPublicKey(derBytes)
            if err != nil {
                return nil, err
            }

            switch k := key.(type) {
                case *ecdsa.PublicKey:
                    eckey, err := k.ECDH()
                    if err != nil {
                        return nil, err
                    }

                    switch eckey.Curve() {
                        case crypto_ecdh.P256():
                            return ecdh.P256().NewPublicKey(eckey.Bytes())
                        case crypto_ecdh.P384():
                            return ecdh.P384().NewPublicKey(eckey.Bytes())
                        case crypto_ecdh.P521():
                            return ecdh.P521().NewPublicKey(eckey.Bytes())
                    }

                case *crypto_ecdh.PublicKey:
                    if k.Curve() == crypto_ecdh.X25519() {
                        return ecdh.X25519().NewPublicKey(k.Bytes())
                    }
            }

            return nil, errors.New("x509: unknown public key algorithm")
    }

}

// ====================

// 包装私钥
func MarshalPrivateKey(key *ecdh.PrivateKey) ([]byte, error) {
    var privKey pkcs8

    if key.Curve() == ecdh.X448() {
        privKey.Algo = pkix.AlgorithmIdentifier{
            Algorithm: oidPublicKeyX448,
        }
        var err error
        if privKey.PrivateKey, err = asn1.Marshal(key.Bytes()); err != nil {
            return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
        }
    } else {
        var newCurve crypto_ecdh.Curve

        switch key.Curve() {
            case ecdh.P256():
                newCurve = crypto_ecdh.P256()
            case ecdh.P384():
                newCurve = crypto_ecdh.P384()
            case ecdh.P521():
                newCurve = crypto_ecdh.P521()
            case ecdh.X25519():
                newCurve = crypto_ecdh.X25519()
            default:
                return nil, fmt.Errorf("x509: unknown key type while marshaling PKCS#8: %T", key)
        }

        prikey, err := newCurve.NewPrivateKey(key.Bytes())
        if err != nil {
            return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
        }

        private, err := x509.MarshalPKCS8PrivateKey(prikey)
        if err != nil {
            return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
        }

        return private, nil
    }

    return asn1.Marshal(privKey)
}

// 解析私钥
func ParsePrivateKey(der []byte) (*ecdh.PrivateKey, error) {
    var privKey pkcs8
    if _, err := asn1.Unmarshal(der, &privKey); err != nil {
        return nil, err
    }

    switch {
        case privKey.Algo.Algorithm.Equal(oidPublicKeyX448):
            if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
                return nil, errors.New("x509: invalid X448 private key parameters")
            }

            var curvePrivateKey []byte
            if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
                return nil, fmt.Errorf("x509: invalid X448 private key: %v", err)
            }

            return ecdh.X448().NewPrivateKey(curvePrivateKey)
        default:
            key, err := x509.ParsePKCS8PrivateKey(der)
            if err != nil {
                return nil, err
            }

            switch k := key.(type) {
                case *ecdsa.PrivateKey:
                    eckey, err := k.ECDH()
                    if err != nil {
                        return nil, err
                    }

                    switch eckey.Curve() {
                        case crypto_ecdh.P256():
                            return ecdh.P256().NewPrivateKey(eckey.Bytes())
                        case crypto_ecdh.P384():
                            return ecdh.P384().NewPrivateKey(eckey.Bytes())
                        case crypto_ecdh.P521():
                            return ecdh.P521().NewPrivateKey(eckey.Bytes())
                    }

                case *crypto_ecdh.PrivateKey:
                    if k.Curve() == crypto_ecdh.X25519() {
                        return ecdh.X25519().NewPrivateKey(k.Bytes())
                    }
            }

            return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
    }
}
