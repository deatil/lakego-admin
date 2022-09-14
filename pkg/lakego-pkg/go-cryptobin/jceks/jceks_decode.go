package jceks

import (
    "io"
    "fmt"
    "hash"
    "bytes"
    "crypto"
    "crypto/subtle"
    "crypto/x509"
)

// Jceks 解析
type JceksDecode struct {
    entries map[string]interface{}
}

func (this *JceksDecode) parsePrivateKey(r io.Reader) error {
    alias, err := readUTF(r)
    if err != nil {
        return err
    }

    entry := &privateKeyEntry{
        certs: []*x509.Certificate{},
    }

    entry.date, err = readDate(r)
    if err != nil {
        return err
    }

    entry.encodedKey, err = readBytes(r)
    if err != nil {
        return err
    }

    nCerts, err := readInt32(r)
    if err != nil {
        return err
    }

    for j := 0; j < int(nCerts); j++ {
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

        entry.certs = append(entry.certs, cert)
    }

    this.entries[alias] = entry
    return nil
}

func (this *JceksDecode) parseTrustedCert(r io.Reader) error {
    alias, err := readUTF(r)
    if err != nil {
        return err
    }

    entry := &trustedCertEntry{}

    entry.date, err = readDate(r)
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

    entry.cert, err = x509.ParseCertificate(certBytes)
    if err != nil {
        return err
    }

    this.entries[alias] = entry
    return nil
}

func (this *JceksDecode) parseSecretKey(r io.Reader) error {
    alias, err := readUTF(r)
    if err != nil {
        return err
    }

    entry := &secretKeyEntry{}

    entry.date, err = readDate(r)
    if err != nil {
        return err
    }

    entry.encodedKey, err = readBytes(r)
    if err != nil {
        return err
    }

    this.entries[alias] = entry
    return nil
}

// 解析
func (this *JceksDecode) Parse(r io.Reader, password string) error {
    var md hash.Hash
    if password != "" {
        md = getPreKeyedHash([]byte(password))
        r = io.TeeReader(r, md)
    }

    version, err := parseHeader(r)
    if err != nil {
        return err
    }

    if version != jceksVersion {
        return fmt.Errorf("unexpected version: %d != %d", version, jceksVersion)
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
            case jceksPrivateKeyId:
                // Private-key entry
                err := this.parsePrivateKey(r)
                if err != nil {
                    return err
                }
            case jceksTrustedCertId:
                // Trusted-cert entry
                err := this.parseTrustedCert(r)
                if err != nil {
                    return err
                }
            case jceksSecretKeyId:
                // Secret-key entry
                err := this.parseSecretKey(r)
                if err != nil {
                    return err
                }
            default:
                return fmt.Errorf("unimplemented tag: %d", tag)
        }
    }

    if md != nil {
        computed := md.Sum([]byte{})
        actual := make([]byte, len(computed))
        _, err := io.ReadFull(r, actual)
        if err != nil {
            return err
        }

        if subtle.ConstantTimeCompare(computed, actual) != 1 {
            return fmt.Errorf("keystore was tampered with or password was incorrect")
        }
    }

    return nil
}

// GetPrivateKeyAndCerts
func (this *JceksDecode) GetPrivateKeyAndCerts(alias string, password string) (
    key crypto.PrivateKey,
    certs []*x509.Certificate,
    err error,
) {
    entry := this.entries[alias]
    if entry == nil {
        return
    }

    switch t := entry.(type) {
        case *privateKeyEntry:
            if len(t.certs) < 1 {
                return nil, nil, fmt.Errorf("key has no certificates")
            }

            key, err = t.Recover([]byte(password))
            if err == nil {
                certs = t.certs
                return
            }
    }

    return
}

// GetCert
func (this *JceksDecode) GetCert(alias string) (*x509.Certificate, error) {
    entry := this.entries[alias]
    if entry == nil {
        return nil, nil
    }

    switch t := entry.(type) {
        case *trustedCertEntry:
            return t.cert, nil
    }

    return nil, nil
}

// GetSecretKey
func (this *JceksDecode) GetSecretKey(alias string, password string) (key []byte, err error) {
    entry := this.entries[alias]
    if entry == nil {
        return
    }

    switch t := entry.(type) {
        case *secretKeyEntry:
            key, err = t.Recover([]byte(password))
            return
    }

    return
}

// ListPrivateKeys
func (this *JceksDecode) ListPrivateKeys() []string {
    var r []string
    for k, v := range this.entries {
        if _, ok := v.(*privateKeyEntry); ok {
            r = append(r, k)
        }
    }
    return r
}

// ListCerts
func (this *JceksDecode) ListCerts() []string {
    var r []string

    for k, v := range this.entries {
        if _, ok := v.(*trustedCertEntry); ok {
            r = append(r, k)
        }
    }

    return r
}

// ListSecretKeys lists the names of the SecretKey stored in the key store.
func (this *JceksDecode) ListSecretKeys() []string {
    var r []string

    for k, v := range this.entries {
        if _, ok := v.(*secretKeyEntry); ok {
            r = append(r, k)
        }
    }

    return r
}

func (this *JceksDecode) String() string {
    var buf bytes.Buffer

    for k, v := range this.entries {
        fmt.Fprintf(&buf, "%s\n", k)
        fmt.Fprintf(&buf, "  %s\n", v)
    }

    return buf.String()
}
