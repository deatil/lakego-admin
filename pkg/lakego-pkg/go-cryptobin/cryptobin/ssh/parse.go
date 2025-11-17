package ssh

import (
    "errors"
    "crypto"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "encoding/asn1"

    crypto_ssh "golang.org/x/crypto/ssh"

    "github.com/deatil/go-cryptobin/ssh"
    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/gm/sm2"
    pubkey_dsa "github.com/deatil/go-cryptobin/pubkey/dsa"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("go-cryptobin/ssh: invalid key: Key must be a PEM encoded OpenSSH key")
    ErrNotOpenSSHPublicKey = errors.New("go-cryptobin/ssh: key is not a valid SSH public key")

    ErrPrivateKeyError = errors.New("go-cryptobin/ssh: key is not a valid private key")
    ErrPublicKeyError  = errors.New("go-cryptobin/ssh: key is not a valid public key")
)

var (
    oidPublicKeySM2     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
    oidPublicKeyRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
    oidPublicKeyDSA     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
    oidPublicKeyECDSA   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
    oidPublicKeyEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// Parse OpenSSH PrivateKey From PEM
func (this SSH) ParseOpenSSHPrivateKeyFromPEM(key []byte) (crypto.PrivateKey, string, string, error) {
    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, "", "", ErrKeyMustBePEMEncoded
    }

    privateKey, comment, err := ssh.ParseOpenSSHPrivateKey(block.Bytes)
    if err != nil {
        return nil, "", "", err
    }

    info, err := ssh.ParseOpenSSHPrivateKeyToInfo(block.Bytes)
    if err != nil {
        return nil, "", "", err
    }

    return privateKey, comment, info.CipherName, nil
}

// Parse OpenSSH PrivateKey From PEM With Password
func (this SSH) ParseOpenSSHPrivateKeyFromPEMWithPassword(key []byte, password []byte) (crypto.PrivateKey, string, string, error) {
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, "", "", ErrKeyMustBePEMEncoded
    }

    privateKey, comment, err := ssh.ParseOpenSSHPrivateKeyWithPassword(block.Bytes, password)
    if err != nil {
        return nil, "", "", err
    }

    info, err := ssh.ParseOpenSSHPrivateKeyToInfo(block.Bytes)
    if err != nil {
        return nil, "", "", err
    }

    return privateKey, comment, info.CipherName, nil
}

type openSSHPrivateKey struct {
    CipherName   string
    KdfName      string
    KdfOpts      string
    NumKeys      uint32
    PubKey       []byte
    PrivKeyBlock []byte
}

// Parse OpenSSH PrivateKey To Info From PEM
func (this SSH) ParseOpenSSHPrivateKeyToInfoFromPEM(key []byte) (openSSHPrivateKey, error) {
    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return openSSHPrivateKey{}, ErrKeyMustBePEMEncoded
    }

    info, err := ssh.ParseOpenSSHPrivateKeyToInfo(block.Bytes)
    if err != nil {
        return openSSHPrivateKey{}, err
    }

    return openSSHPrivateKey(info), nil
}

// Parse OpenSSH PublicKey From PEM
func (this SSH) ParseOpenSSHPublicKeyFromPEM(key []byte) (crypto.PublicKey, string, error) {
    var err error

    // Parse the key
    var parsedKey crypto_ssh.PublicKey
    var comment string
    if parsedKey, comment, _, _, err = ssh.ParseAuthorizedKey(key); err != nil {
        return nil, "", err
    }

    var pkey crypto_ssh.CryptoPublicKey
    var ok bool

    if pkey, ok = parsedKey.(crypto_ssh.CryptoPublicKey); !ok {
        return nil, "", ErrNotOpenSSHPublicKey
    }

    return pkey.CryptoPublicKey(), comment, nil
}

// ====================

type pkcs8Info struct {
    Version    int
    Algo       pkix.AlgorithmIdentifier
    PrivateKey []byte
    Attributes []asn1.RawValue `asn1:"optional,tag:0"`
}

type pkixPublicKey struct {
    Algo      pkix.AlgorithmIdentifier
    BitString asn1.BitString
}

// Parse PKCS8 PrivateKey From PEM
func (this SSH) ParsePKCS8PrivateKeyFromPEM(key []byte) (crypto.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var privKey pkcs8Info
    if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
        return nil, err
    }

    var parsedKey any

    switch {
        case privKey.Algo.Algorithm.Equal(oidPublicKeySM2):
            parsedKey, err = sm2.ParsePrivateKey(block.Bytes)
        case privKey.Algo.Algorithm.Equal(oidPublicKeyRSA):
            parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
        case privKey.Algo.Algorithm.Equal(oidPublicKeyDSA):
            parsedKey, err = pubkey_dsa.ParsePKCS8PrivateKey(block.Bytes)
        case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
            bytes := privKey.Algo.Parameters.FullBytes

            namedCurveOID := new(asn1.ObjectIdentifier)
            if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
                namedCurveOID = nil
            }

            if oidPublicKeySM2.Equal(*namedCurveOID) {
                parsedKey, err = sm2.ParsePrivateKey(block.Bytes)
            } else {
                parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
            }
        case privKey.Algo.Algorithm.Equal(oidPublicKeyEd25519):
            parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
        default:
            return nil, ErrPrivateKeyError
    }

    if err != nil {
        return nil, err
    }

    return parsedKey, nil
}

// Parse PKCS8 PrivateKey From PEM With Password
func (this SSH) ParsePKCS8PrivateKeyFromPEMWithPassword(key []byte, password []byte) (crypto.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var blockDecrypted []byte
    if blockDecrypted, err = pkcs8.DecryptPEMBlock(block, password); err != nil {
        return nil, err
    }

    var privKey pkcs8Info
    if _, err := asn1.Unmarshal(blockDecrypted, &privKey); err != nil {
        return nil, err
    }

    var parsedKey any

    switch {
        case privKey.Algo.Algorithm.Equal(oidPublicKeySM2):
            parsedKey, err = sm2.ParsePrivateKey(blockDecrypted)
        case privKey.Algo.Algorithm.Equal(oidPublicKeyRSA):
            parsedKey, err = x509.ParsePKCS8PrivateKey(blockDecrypted)
        case privKey.Algo.Algorithm.Equal(oidPublicKeyDSA):
            parsedKey, err = pubkey_dsa.ParsePKCS8PrivateKey(blockDecrypted)
        case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
            bytes := privKey.Algo.Parameters.FullBytes

            namedCurveOID := new(asn1.ObjectIdentifier)
            if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
                namedCurveOID = nil
            }

            if oidPublicKeySM2.Equal(*namedCurveOID) {
                parsedKey, err = sm2.ParsePrivateKey(blockDecrypted)
            } else {
                parsedKey, err = x509.ParsePKCS8PrivateKey(blockDecrypted)
            }
        case privKey.Algo.Algorithm.Equal(oidPublicKeyEd25519):
            parsedKey, err = x509.ParsePKCS8PrivateKey(blockDecrypted)
        default:
            return nil, ErrPrivateKeyError
    }

    if err != nil {
        return nil, err
    }

    return parsedKey, nil
}

// Parse PKCS8 PublicKey From PEM
func (this SSH) ParsePKCS8PublicKeyFromPEM(key []byte) (crypto.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var pubkey pkixPublicKey
    if _, err := asn1.Unmarshal(block.Bytes, &pubkey); err != nil {
        return nil, err
    }

    var parsedKey any

    switch {
        case pubkey.Algo.Algorithm.Equal(oidPublicKeySM2):
            parsedKey, err = sm2.ParsePublicKey(block.Bytes)
        case pubkey.Algo.Algorithm.Equal(oidPublicKeyRSA):
            parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes)
        case pubkey.Algo.Algorithm.Equal(oidPublicKeyDSA):
            parsedKey, err = pubkey_dsa.ParsePKCS8PublicKey(block.Bytes)
        case pubkey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
            bytes := pubkey.Algo.Parameters.FullBytes

            namedCurveOID := new(asn1.ObjectIdentifier)
            if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
                namedCurveOID = nil
            }

            if oidPublicKeySM2.Equal(*namedCurveOID) {
                parsedKey, err = sm2.ParsePublicKey(block.Bytes)
            } else {
                parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes)
            }
        case pubkey.Algo.Algorithm.Equal(oidPublicKeyEd25519):
            parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes)
        default:
            return nil, ErrPublicKeyError
    }

    if err != nil {
        return nil, err
    }

    return parsedKey, nil
}
