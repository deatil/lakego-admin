package x509

import (
    "io"
    "fmt"
    "errors"
    "math/big"
    "crypto/x509/pkix"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/gm/sm2"
    "github.com/deatil/go-cryptobin/gm/sm2/sm2curve"
    "github.com/deatil/go-cryptobin/pkcs/pbes2"
)

// 别名
type (
    EnvelopedCipher = pbes2.Cipher
)

// 加密方式
var (
    Enveloped_SM4Cipher = pbes2.SM4Cipher
    Enveloped_SM4ECB    = pbes2.SM4ECB
    Enveloped_SM4CBC    = pbes2.SM4CBC
    Enveloped_SM4OFB    = pbes2.SM4OFB
    Enveloped_SM4CFB    = pbes2.SM4CFB
    Enveloped_SM4CFB1   = pbes2.SM4CFB1
    Enveloped_SM4CFB8   = pbes2.SM4CFB8
    Enveloped_SM4GCM    = pbes2.SM4GCM
    Enveloped_SM4CCM    = pbes2.SM4CCM
)

var (
    AddEnvelopedCipher = pbes2.AddCipher
    GetEnvelopedCipher = pbes2.GetCipher
)

// Enveloped 配置
type EnvelopedOpts struct {
    // encrypt cipher
    Cipher EnvelopedCipher

    // PrivateKey get bytes type
    IsFill bool
}

// 默认配置
var DefaultEnvelopedOpts = EnvelopedOpts{
    Cipher: Enveloped_SM4ECB,
    IsFill: false,
}

// GB/T 35276-2017, see Section 7.4
//
//  SM2EnvelopedKey ::= SEQUENCE {
//    symAlgID               AlgorithmIdentifier,
//    symEncryptedKey        SM2Cipher,
//    sm2PublicKey           SM2PublicKey,
//    sm2EncryptedPrivateKey BIT STRING,
//  }
type SM2EnvelopedKey struct {
    Algo                pkix.AlgorithmIdentifier
    EncryptedKey        SM2EncryptedKey
    PublicKey           asn1.BitString
    EncryptedPrivateKey asn1.BitString
}

type SM2EncryptedKey struct {
    XCoordinate *big.Int
    YCoordinate *big.Int
    HASH        []byte
    CipherText  []byte
}

// This implementation follows GB/T 35276-2017, wiil use SM4 cipher to encrypt sm2 private key.
//
// MarshalSM2EnvelopedPrivateKey, returns sm2 key pair protected data with ASN.1 format:
//
// This function can be used in CSRResponse.encryptedPrivateKey, reference GM/T 0092-2020
// Specification of certificate request syntax based on SM2 cryptographic algorithm.
func MarshalSM2EnvelopedPrivateKey(
    rand        io.Reader,
    pub         *sm2.PublicKey,
    toEnveloped *sm2.PrivateKey,
    opts        ...EnvelopedOpts,
) ([]byte, error) {
    opt := &DefaultEnvelopedOpts
    if len(opts) > 0 {
        opt = &opts[0]
    }

    cipher := opt.Cipher
    if cipher == nil {
        err := errors.New("x509: unknown opts cipher")
        return nil, err
    }

    var prikeyBytes []byte

    // encrypt sm2 private key
    if opt.IsFill {
        size := (toEnveloped.Curve.Params().N.BitLen() + 7) / 8
        if toEnveloped.D.BitLen() > size*8 {
            return nil, errors.New("x509: invalid private key")
        }

        prikeyBytes = toEnveloped.D.FillBytes(make([]byte, size))
    } else {
        prikeyBytes = toEnveloped.D.Bytes()
    }

    key := make([]byte, cipher.KeySize())
    if _, err := io.ReadFull(rand, key); err != nil {
        return nil, err
    }

    encryptedPrivateKey, encryptedPrivateKeyParams, err := cipher.Encrypt(rand, key, prikeyBytes)
    if err != nil {
        return nil, err
    }

    // encrypt the symmetric key
    encryptedKeyBytes, err := sm2.EncryptASN1(rand, pub, key, nil)
    if err != nil {
        return nil, err
    }

    var symEncryptedKey SM2EncryptedKey
    _, err = asn1.Unmarshal(encryptedKeyBytes, &symEncryptedKey)
    if err != nil {
        return nil, errors.New("x509: sm2 encrypt key fail")
    }

    symAlgo := pkix.AlgorithmIdentifier{
        Algorithm:  cipher.OID(),
        Parameters: asn1.RawValue{
            FullBytes: encryptedPrivateKeyParams,
        },
    }

    // publicKey data bytes
    publicKeyBytes := sm2curve.Marshal(toEnveloped.Curve, toEnveloped.X, toEnveloped.Y)

    envelopedKey := SM2EnvelopedKey{
        Algo:         symAlgo,
        EncryptedKey: symEncryptedKey,
        PublicKey: asn1.BitString{
            Bytes:     publicKeyBytes,
            BitLength: 8 * len(publicKeyBytes),
        },
        EncryptedPrivateKey: asn1.BitString{
            Bytes:     encryptedPrivateKey,
            BitLength: 8 * len(encryptedPrivateKey),
        },
    }

    return asn1.Marshal(envelopedKey)

}

// ParseSM2EnvelopedPrivateKey, parses and decrypts the enveloped SM2 private key.
func ParseSM2EnvelopedPrivateKey(priv *sm2.PrivateKey, enveloped []byte) (*sm2.PrivateKey, error) {
    // unmarshal the asn.1 data
    var envelopedKey SM2EnvelopedKey
    _, err := asn1.Unmarshal(enveloped, &envelopedKey)
    if err != nil {
        return nil, errors.New("x509: invalid asn1 format enveloped key")
    }

    symAlgo := envelopedKey.Algo
    symEncryptedKeyASN1 := envelopedKey.EncryptedKey
    pub := envelopedKey.PublicKey
    encryptedPrivateKey := envelopedKey.EncryptedPrivateKey

    // parse public key
    pubKey, err := sm2.NewPublicKey(pub.RightAlign())
    if err != nil {
        return nil, err
    }

    symEncryptedKey, err := asn1.Marshal(symEncryptedKeyASN1)
    if err != nil {
        return nil, err
    }

    // decrypt symmetric cipher key
    key, err := sm2.DecryptASN1(priv, symEncryptedKey, nil)
    if err != nil {
        return nil, err
    }

    priBytes := encryptedPrivateKey.RightAlign()

    cipher, cipherParams, err := parseEnvelopedEncryptionScheme(symAlgo)
    if err != nil {
        return nil, err
    }

    prikey, err := cipher.Decrypt(key, cipherParams, priBytes)
    if err != nil {
        return nil, err
    }

    sm2Key, err := sm2.NewPrivateKey(prikey)
    if err != nil {
        return nil, err
    }

    if !sm2Key.PublicKey.Equal(pubKey) {
        return nil, errors.New("x509: miss match key pair in enveloped data")
    }

    return sm2Key, nil
}

func parseEnvelopedEncryptionScheme(encryptionScheme pkix.AlgorithmIdentifier) (EnvelopedCipher, []byte, error) {
    newCipher, err := GetEnvelopedCipher(encryptionScheme)
    if err != nil {
        oid := encryptionScheme.Algorithm.String()

        return nil, nil, fmt.Errorf("unsupported cipher (OID: %s)", oid)
    }

    params := encryptionScheme.Parameters.FullBytes

    return newCipher, params, nil
}
