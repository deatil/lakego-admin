package jceks

import (
    "io"
    "fmt"
    "time"
    "hash"
    "errors"
    "crypto"
    "crypto/subtle"
    "crypto/x509"
)

// Jks 解析
type JksDecode struct {
    // 别名
    aliases      []string

    // 证书
    trustedCerts map[string]*x509.Certificate

    // 私钥
    privateKeys  map[string][]byte

    // 证书链
    certChains   map[string][]*x509.Certificate

    // 时间
    dates        map[string]time.Time
}

func (this *JksDecode) parsePrivateKey(r io.Reader) error {
    alias, err := readUTF(r)
    if err != nil {
        return err
    }

    this.aliases = append(this.aliases, alias)

    this.dates[alias], err = readDate(r)
    if err != nil {
        return err
    }

    this.privateKeys[alias], err = readBytes(r)
    if err != nil {
        return err
    }

    n, err := readInt32(r)
    if err != nil {
        return err
    }

    var chain []*x509.Certificate

    for j := 0; j < int(n); j++ {
        readCertType, err := readUTF(r)
        if err != nil {
            return err
        }

        if readCertType != certType {
            return fmt.Errorf("unable to handle certificate type: %s", certType)
        }

        certBytes, err := readBytes(r)
        if err != nil {
            return err
        }

        cert, err := x509.ParseCertificate(certBytes)
        if err != nil {
            return err
        }

        chain = append(chain, cert)
    }

    this.certChains[alias] = chain
    return nil
}

func (this *JksDecode) parseTrustedCert(r io.Reader) error {
    alias, err := readUTF(r)
    if err != nil {
        return err
    }

    this.aliases = append(this.aliases, alias)

    this.dates[alias], err = readDate(r)
    if err != nil {
        return err
    }

    readCertType, err := readUTF(r)
    if err != nil {
        return err
    }

    if readCertType != certType {
        return fmt.Errorf("unable to handle certificate type: %s", certType)
    }

    certBytes, err := readBytes(r)
    if err != nil {
        return err
    }

    this.trustedCerts[alias], err = x509.ParseCertificate(certBytes)
    if err != nil {
        return err
    }

    return nil
}

// 解析
func (this *JksDecode) Parse(r io.Reader, password string) error {
    var md hash.Hash
    md = getJksPreKeyedHash([]byte(password))
    r = io.TeeReader(r, md)

    magic, err := readUint32(r)
    if err != nil {
        return err
    }

    if magic != jksMagic {
        return fmt.Errorf("unexpected magic: %08x != %08x", magic, uint32(jksMagic))
    }

    version, err := readUint32(r)
    if err != nil {
        return err
    }

    if version != jksVersion {
        return fmt.Errorf("unexpected version: %d != %d", version, jksVersion)
    }

    count, err := readInt32(r)
    if err != nil {
        return err
    }

    for i := 0; i < int(count); i++ {
        tag, err := readInt32(r)
        if err != nil {
            return err
        }

        switch tag {
            case jksPrivateKeyId:
                // Private-key entry
                err := this.parsePrivateKey(r)
                if err != nil {
                    return err
                }
            case jksTrustedCertId:
                // Trusted-cert entry
                err := this.parseTrustedCert(r)
                if err != nil {
                    return err
                }
            default:
                return fmt.Errorf("unimplemented tag: %d", tag)
        }
    }

    computed := md.Sum([]byte{})
    actual := make([]byte, len(computed))
    if _, err := io.ReadFull(r, actual); err != nil {
        return err
    }

    if subtle.ConstantTimeCompare(computed, actual) != 1 {
        return fmt.Errorf("keystore was tampered with or password was incorrect")
    }

    return nil
}

// GetKey
func (this *JksDecode) GetKey(alias string, password string) (crypto.PrivateKey, error) {
    encodedKey := this.privateKeys[alias]
    if encodedKey == nil {
        return nil, errors.New("no data")
    }

    decryptedKey, err := jksDecryptKey(encodedKey, []byte(password))
    if err != nil {
        return nil, err
    }

    privateKey, err := ParsePKCS8PrivateKey(decryptedKey)
    if err != nil {
        return nil, err
    }

    return privateKey, nil
}

// GetEncodedKey
func (this *JksDecode) GetEncodedKey(alias string) ([]byte, error) {
    encodedKey := this.privateKeys[alias]
    if encodedKey == nil {
        return nil, errors.New("no data")
    }

    return encodedKey, nil
}

// GetCertificateChain
func (this *JksDecode) GetCertChain(alias string) ([]*x509.Certificate, error) {
    chain := this.certChains[alias]
    if chain != nil {
        return chain, nil
    }

    return nil, errors.New("no data")
}

// GetCertificate
func (this *JksDecode) GetCert(alias string) (*x509.Certificate, error) {
    cert := this.trustedCerts[alias]
    if cert != nil {
        return cert, nil
    }

    return nil, errors.New("no data")
}

// GetCreationDate
func (this *JksDecode) GetCreateDate(alias string) (time.Time, error) {
    date, ok := this.dates[alias]
    if ok {
        return date, nil
    }

    return time.Unix(0, 0), errors.New("no data")
}

// ListPrivateKeys
func (this *JksDecode) ListPrivateKeys() []string {
    var r []string
    for k, _ := range this.privateKeys {
        r = append(r, k)
    }

    return r
}

// ListCerts
func (this *JksDecode) ListCerts() []string {
    var r []string

    for k, _ := range this.trustedCerts {
        r = append(r, k)
    }

    return r
}

func (this *JksDecode) String() string {
    return "JKS Decode"
}
